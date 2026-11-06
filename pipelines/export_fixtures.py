"""Export events from Elasticsearch as JSON fixtures for CI replay tests.

Usage:
  uv run pipelines/export_fixtures.py --query '<lucene>' --minutes 60 --out tests/fixtures/name.json
Credentials come from ES_URL and ES_API_KEY environment variables; never from the repo.
"""
import argparse, json, os, sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # lab self-signed cert


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--query", required=True, help="Lucene query string")
    p.add_argument("--minutes", type=int, default=60, help="Look back this many minutes")
    p.add_argument("--out", required=True, help="Output JSON file")
    p.add_argument("--max", type=int, default=50, help="Max events to export")
    args = p.parse_args()

    url, key = os.environ.get("ES_URL"), os.environ.get("ES_API_KEY")
    if not url or not key:
        sys.exit("Set ES_URL and ES_API_KEY environment variables")

    body = {
        "size": args.max,
        "sort": [{"@timestamp": "desc"}],
        "query": {"bool": {"filter": [
            {"query_string": {"query": args.query, "analyze_wildcard": True}},
            {"range": {"@timestamp": {"gte": f"now-{args.minutes}m"}}},
        ]}},
    }
    r = requests.post(f"{url}/logs-*/_search", json=body,
                      headers={"Authorization": f"ApiKey {key}"}, verify=False, timeout=30)
    r.raise_for_status()
    hits = [h["_source"] for h in r.json()["hits"]["hits"]]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(hits, f, indent=2)
    print(f"Wrote {len(hits)} events to {args.out}")
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())