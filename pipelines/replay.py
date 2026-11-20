"""Replay every Sigma rule against its committed fixtures in a disposable Elasticsearch.

Usage (CI, or a local throwaway container on localhost:9200):
  uv run pipelines/replay.py [--es-url http://localhost:9200] [--strict-filters]

What it does:
  1. Installs an index template per snapshot in tests/mappings/, so documents are mapped
     exactly as the production integrations map them (host.name is keyword, etc.).
  2. Bulk-loads every fixture referenced by tests/cases/*.yml into the data stream each
     document names in its data_stream.* fields, remembering which _ids came from which file.
  3. Converts each rule with the same backend and pipeline used for deployment
     (Lucene backend, ecs_windows pipeline) and runs it as Kibana would (query_string).
  4. Asserts per fixture: 'all' events match, 'none' match, or exactly n match.
  5. Reports, for each filter_* block in a rule, how many benign events it actually
     suppresses. A filter nothing exercises is a filter nobody will notice breaking.

Exit code is non-zero on any failed assertion, a rule without a test case, a missing or
empty fixture, or (with --strict-filters) a filter with no supporting benign event.

Safety: this script deletes and recreates logs-* data streams. It refuses to talk to
anything but localhost unless --allow-remote is given. Never point it at the SIEM.
"""
import argparse, glob, json, os, sys
from urllib.parse import urlparse

import requests
import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch import ecs_windows
from sigma.rule import SigmaRule

RULES_DIR, CASES_DIR, FIXTURES_DIR, MAPPINGS_DIR = "rules", "tests/cases", "tests/fixtures", "tests/mappings"


class ES:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.s = requests.Session()

    def req(self, method: str, path: str, ok=(200, 201), **kw) -> dict:
        r = self.s.request(method, f"{self.url}{path}", timeout=60, **kw)
        if r.status_code not in ok:
            sys.exit(f"{method} {path} -> HTTP {r.status_code}: {r.text[:500]}")
        return r.json() if r.text else {}


def backend() -> LuceneBackend:
    # A fresh backend per conversion: the pipeline mutates the rules it processes.
    return LuceneBackend(processing_pipeline=ecs_windows())


def install_mappings(es: ES) -> list[str]:
    files = sorted(glob.glob(os.path.join(MAPPINGS_DIR, "*.json")))
    if not files:
        sys.exit(f"No mapping snapshots in {MAPPINGS_DIR}/. Run pipelines/export_mapping.py first.")
    streams = []
    for path in files:
        with open(path, encoding="utf-8") as f:
            snap = json.load(f)
        ds = snap["data_stream"]
        es.req("PUT", f"/_index_template/ci-{ds}", json={
            "index_patterns": [ds],
            "data_stream": {},
            "priority": 500,
            "template": {
                "settings": {"index.mapping.total_fields.limit": 10000},
                "mappings": snap["mappings"],
            },
        })
        streams.append(ds)
    return streams


def data_stream_of(doc: dict, path: str) -> str:
    ds = doc.get("data_stream") or {}
    try:
        return f"{ds['type']}-{ds['dataset']}-{ds['namespace']}"
    except KeyError:
        sys.exit(f"{path}: event has no data_stream.type/dataset/namespace; cannot route it")


def load_fixtures(es: ES, files: list[str]) -> dict[str, list[str]]:
    """Bulk-create every event; return {fixture path: [_id, ...]} in file order."""
    ids: dict[str, list[str]] = {}
    for path in files:
        if not os.path.exists(path):
            sys.exit(f"Fixture not found: {path}")
        with open(path, encoding="utf-8") as f:
            docs = json.load(f)
        if not isinstance(docs, list) or not docs:
            sys.exit(f"Fixture is empty or not a JSON array: {path}")
        lines = []
        for doc in docs:
            lines.append(json.dumps({"create": {"_index": data_stream_of(doc, path)}}))
            lines.append(json.dumps(doc))
        resp = es.req("POST", "/_bulk", data="\n".join(lines) + "\n",
                      headers={"Content-Type": "application/x-ndjson"})
        if resp.get("errors"):
            bad = next(i["create"] for i in resp["items"] if i["create"].get("error"))
            sys.exit(f"{path}: Elasticsearch rejected an event: {json.dumps(bad['error'])[:500]}")
        ids[path] = [item["create"]["_id"] for item in resp["items"]]
    es.req("POST", "/logs-*/_refresh")
    return ids


def convert(rule_path: str) -> str:
    queries = backend().convert(SigmaCollection.load_ruleset([rule_path]))
    if len(queries) != 1:
        sys.exit(f"{rule_path}: expected one query, got {len(queries)}")
    return queries[0]


def filter_queries(rule_path: str) -> dict[str, str]:
    """For each filter_* block, the query for 'selection and filter_x': the events the
    filter exists to suppress."""
    with open(rule_path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    det = doc.get("detection", {})
    if "selection" not in det:
        return {}
    out = {}
    for name in [k for k in det if k.startswith("filter")]:
        variant = dict(doc, detection=dict(det, condition=f"selection and {name}"))
        out[name] = backend().convert_rule(SigmaRule.from_dict(variant))[0]
    return out


def count(es: ES, query: str, ids: list[str]) -> int:
    """How many of these _ids the query matches. query_string with analyze_wildcard mirrors
    how Kibana executes a Lucene-language detection rule."""
    if not ids:
        return 0
    resp = es.req("POST", "/logs-*/_search", json={
        "size": 0, "track_total_hits": True,
        "query": {"bool": {
            "must": [{"query_string": {"query": query, "analyze_wildcard": True}}],
            "filter": [{"ids": {"values": ids}}],
        }},
    })
    return resp["hits"]["total"]["value"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--es-url", default=os.environ.get("ES_URL", "http://localhost:9200"))
    p.add_argument("--allow-remote", action="store_true", help="permit a non-localhost target")
    p.add_argument("--strict-filters", action="store_true",
                   help="fail when a filter_* block has no benign event exercising it")
    args = p.parse_args()

    host = urlparse(args.es_url).hostname
    if host not in ("localhost", "127.0.0.1", "::1") and not args.allow_remote:
        sys.exit(f"Refusing to replay against {args.es_url}: this deletes logs-* data streams. "
                 "Use a disposable Elasticsearch, or pass --allow-remote if you are certain.")
    es = ES(args.es_url)

    # Discover rules and cases; every rule needs exactly one case.
    rules = sorted(p.replace("\\", "/")   # forward slashes so Windows paths match the case files
                   for p in glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True))
    cases = {}
    for path in sorted(glob.glob(os.path.join(CASES_DIR, "*.yml"))):
        with open(path, encoding="utf-8") as f:
            case = yaml.safe_load(f)
        cases.setdefault(case["rule"].replace("\\", "/"), []).append((path, case))
    failures = 0
    for rule in rules:
        if rule not in cases:
            print(f"FAIL  {rule}: no test case in {CASES_DIR}/")
            failures += 1
        elif len(cases[rule]) > 1:
            print(f"FAIL  {rule}: more than one test case: {[c[0] for c in cases[rule]]}")
            failures += 1
    for rule in cases:
        if rule not in rules:
            print(f"FAIL  {cases[rule][0][0]}: rule {rule} does not exist")
            failures += 1
    if failures:
        return 1

    es.req("DELETE", "/_data_stream/logs-*", ok=(200, 404))
    streams = install_mappings(es)
    print(f"Mappings installed for: {', '.join(streams)}")

    fixture_files = sorted({fx["file"] for cs in cases.values() for _, c in cs for fx in c["fixtures"]})
    ids = load_fixtures(es, fixture_files)
    print(f"Loaded {sum(len(v) for v in ids.values())} events from {len(ids)} fixtures\n")

    for rule in rules:
        case_path, case = cases[rule][0]
        query = convert(rule)
        print(rule)
        print(f"  query: {query}")
        benign_ids: list[str] = []
        for fx in case["fixtures"]:
            n, total, expect = count(es, query, ids[fx["file"]]), len(ids[fx["file"]]), fx["expect"]
            if expect == "all":
                ok, want = n == total, f"all {total}"
            elif expect == "none":
                ok, want = n == 0, "none"
                benign_ids += ids[fx["file"]]
            else:
                ok, want = n == int(expect), f"exactly {expect}"
            print(f"  {'PASS' if ok else 'FAIL'}  {fx['file']}: {n}/{total} matched, expected {want}")
            failures += 0 if ok else 1
        for name, fq in filter_queries(rule).items():
            n = count(es, fq, benign_ids)
            if n == 0:
                print(f"  {'FAIL' if args.strict_filters else 'WARN'}  {name}: no benign event exercises this filter")
                failures += 1 if args.strict_filters else 0
            else:
                print(f"  ok    {name}: suppresses {n} benign event(s)")
        print()

    print(f"{'FAILED' if failures else 'PASSED'}: {len(rules)} rule(s), {failures} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
