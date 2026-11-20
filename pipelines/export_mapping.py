"""Snapshot a data stream's field mapping so CI replays rules against production field types.

Usage:
  uv run pipelines/export_mapping.py --data-stream logs-system.security-default
Writes tests/mappings/<data-stream>.json. Credentials come from ES_URL and ES_API_KEY
(the key needs read and view_index_metadata on logs-*); never from the repo.

Why: a bare Elasticsearch maps unknown fields dynamically (strings become text with a
.keyword sub-field), which is not how the Elastic Agent integrations map them. A rule can
pass CI against a dynamic mapping and fail in Kibana, or the reverse. Replaying against
the real mapping removes that gap.
"""
import argparse, json, os, sys
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # lab self-signed cert


def count_fields(mapping: dict) -> int:
    """Count leaf fields under nested 'properties' blocks."""
    total = 0
    for field in mapping.get("properties", {}).values():
        total += 1 if "type" in field or "properties" not in field else 0
        total += count_fields(field)
    return total


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--data-stream", required=True, help="e.g. logs-system.security-default")
    p.add_argument("--out-dir", default="tests/mappings")
    args = p.parse_args()

    url, key = os.environ.get("ES_URL"), os.environ.get("ES_API_KEY")
    if not url or not key:
        sys.exit("Set ES_URL and ES_API_KEY environment variables")

    r = requests.get(f"{url}/{args.data_stream}/_mapping",
                     headers={"Authorization": f"ApiKey {key}"}, verify=False, timeout=30)
    r.raise_for_status()
    backing = sorted(r.json())           # backing indices, oldest first
    newest = backing[-1]
    mappings = r.json()[newest]["mappings"]
    mappings.pop("_data_stream_timestamp", None)   # data streams add this themselves

    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, f"{args.data_stream}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"data_stream": args.data_stream, "exported_from": newest, "mappings": mappings},
                  f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"Wrote {path}: {count_fields(mappings)} fields, from backing index {newest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
