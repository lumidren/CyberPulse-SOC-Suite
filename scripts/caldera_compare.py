#!/usr/bin/env python3
"""
Compare a MITRE Caldera operation with the incidents CyberPulse raised (roadmap F22).

    python scripts/caldera_compare.py --report operation_report.json --incidents incidents.json
    python scripts/caldera_compare.py --operation <id> --incidents incidents.json   # needs CALDERA_URL/CALDERA_API_KEY

incidents.json is the "incidents" list from GET /api/incidents (or the whole response).
Prints a what-ran / what-fired / what-missed table; nothing is written to the repo.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.caldera import DEFAULT_WINDOW_SEC, compare, fetch_report, parse_operation_report, summarise  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="What ran in a Caldera operation vs what CyberPulse detected")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--report", help="operation report JSON exported from Caldera")
    source.add_argument("--operation", help="operation id to fetch (CALDERA_URL / CALDERA_API_KEY)")
    parser.add_argument("--incidents", required=True, help="JSON from GET /api/incidents")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW_SEC, help="seconds after a step to accept an alert")
    args = parser.parse_args()
    if args.report:
        with open(args.report, encoding="utf-8") as fh:
            report = json.load(fh)
    else:
        report = fetch_report(args.operation)
    with open(args.incidents, encoding="utf-8") as fh:
        incidents = json.load(fh)
    if isinstance(incidents, dict):
        incidents = incidents.get("incidents", [])
    results = compare(parse_operation_report(report), incidents, args.window)
    for r in results:
        verdict = f"DETECTED by {r['rule_id']} after {r['latency_sec']}s" if r["detected"] else "MISSED"
        print(f"{r['ran_at'] or '?':<28} {r['technique']:<11} {r['status']:<9} {verdict:<40} {r['ability']}")
    print(json.dumps(summarise(results), indent=2))


if __name__ == "__main__":
    main()
