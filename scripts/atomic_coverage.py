#!/usr/bin/env python3
"""
Map Atomic Red Team tests to CyberPulse rules and emulations (roadmap F21).

    git clone https://github.com/redcanaryco/atomic-red-team   # your own copy, MIT licence
    python scripts/atomic_coverage.py --atomics-dir atomic-red-team/atomics [--platform windows] [--json]

Reads the atomic YAML definitions and reports, per technique, how many atomic tests
exist, which CyberPulse rules are tagged with that technique, and whether the lab has
a telemetry-only emulation (simulator/atomic_tests/*.yaml). It is a planning tool:

  * It never executes an atomic test and never copies executor commands into its
    output; only test names, GUIDs, platforms and executor *type* are read.
  * Running atomics is a separate, manual step in your own authorised lab VM
    (docs/ATOMIC_RED_TEAM.md). Their telemetry then reaches CyberPulse through the
    normal ingest path, like any other log source.

The output is derived from third-party content, so it is printed, not committed.
"""

import argparse
import json
import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.sigma_correlation import CorrelationEngine  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402

MANIFEST_DIR = os.path.join(ROOT, "simulator", "atomic_tests")


def load_atomics(atomics_dir, platform=None):
    """{technique: [{"name", "guid", "platforms", "executor"}]} without any command text."""
    found = {}
    for entry in sorted(os.listdir(atomics_dir)):
        path = os.path.join(atomics_dir, entry, f"{entry}.yaml")
        if not (entry.startswith("T") and os.path.isfile(path)):
            continue
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        tests = []
        for test in doc.get("atomic_tests") or []:
            platforms = [str(p).lower() for p in test.get("supported_platforms") or []]
            if platform and platform not in platforms:
                continue
            tests.append({"name": test.get("name"), "guid": test.get("auto_generated_guid"),
                          "platforms": platforms, "executor": (test.get("executor") or {}).get("name")})
        if tests:
            found[str(doc.get("attack_technique", entry)).upper()] = tests
    return found


def load_manifests():
    manifests = {}
    for name in sorted(os.listdir(MANIFEST_DIR)):
        if name.endswith((".yaml", ".yml")):
            with open(os.path.join(MANIFEST_DIR, name), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            manifests[doc["attack_technique"]] = doc
    return manifests


def rules_by_technique():
    table = {}
    for rule in SigmaEngine().rules + CorrelationEngine().rules:
        for tid in rule.technique_ids:
            table.setdefault(tid, []).append(rule.soar.get("soc_rule_id", rule.id))
    return table


def build(atomics):
    rules = rules_by_technique()
    manifests = load_manifests()
    rows = []
    for tid, tests in sorted(atomics.items()):
        covering = sorted(set(rules.get(tid, []) + [r for t, ids in rules.items() if t.split(".")[0] == tid for r in ids]))
        rows.append({"technique": tid, "atomic_tests": len(tests), "rules": covering,
                     "emulated_by": (manifests.get(tid) or {}).get("emulated_by"),
                     "tests": tests})
    return rows


def render(rows):
    covered = sum(1 for r in rows if r["rules"])
    lines = [f"{len(rows)} techniques with atomic tests; {covered} have at least one CyberPulse rule; "
             f"{sum(1 for r in rows if r['emulated_by'])} have a telemetry-only lab emulation.", "",
             f"{'Technique':<12} {'Atomics':>7}  {'Rules':<30} Emulation"]
    for r in rows:
        lines.append(f"{r['technique']:<12} {r['atomic_tests']:>7}  {', '.join(r['rules']) or '-':<30} "
                     f"{r['emulated_by'] or '-'}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Map Atomic Red Team tests to CyberPulse rules (no execution)")
    parser.add_argument("--atomics-dir", required=True, help="path to atomic-red-team/atomics")
    parser.add_argument("--platform", help="only tests supporting this platform (e.g. windows)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not os.path.isdir(args.atomics_dir):
        sys.exit(f"not a directory: {args.atomics_dir}")
    rows = build(load_atomics(args.atomics_dir, args.platform))
    print(json.dumps(rows, indent=2) if args.json else render(rows))


if __name__ == "__main__":
    main()
