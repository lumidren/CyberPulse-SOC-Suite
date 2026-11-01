#!/usr/bin/env python3
"""
Detection regression corpus (roadmap F27).

Every sample event in rules/tests/ and every scripted attack generator is run through
the full detection stage (single-event rules, correlations, exceptions), and the set
of rules that match is recorded in tests/regression/expected_matches.json. The test
suite fails when any of those results changes, so a rule edit that stops an old
detection, or a new rule that starts matching old events, shows up in review.

    python scripts/regression_corpus.py            # show differences from the golden file
    python scripts/regression_corpus.py --accept   # rewrite the golden file (commit the diff)

Accepting is for intended changes only. tests/test_regression_corpus.py also fails,
whatever the golden file says, if a positive sample stops matching its own rule.
"""

import argparse
import json
import os
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # the generators only run in a declared lab

from scripts.validate_detections import EXPECTED_RULE, VALIDATION_DATE  # noqa: E402
from simulator.attack_simulator import SCRIPTED_GENERATORS  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402

GOLDEN = os.path.join(ROOT, "tests", "regression", "expected_matches.json")
SAMPLES_DIR = os.path.join(ROOT, "rules", "tests")


def corpus():
    """[(key, event, kind, owner_rule_file_or_expected_id)]"""
    items = []
    for name in sorted(os.listdir(SAMPLES_DIR)):
        if not name.endswith(".yml"):
            continue
        with open(os.path.join(SAMPLES_DIR, name), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        for kind in ("positive", "negative"):
            for sample in doc.get(kind) or []:
                items.append((f"{doc['rule']}::{kind}::{sample['name']}", sample["event"], kind, doc["rule"]))
    for name, generator in SCRIPTED_GENERATORS:
        items.append((f"generator::{name}", generator(), "generator", EXPECTED_RULE[name]))
    return items


_ORCHESTRATOR = None


def evaluate(event):
    global _ORCHESTRATOR
    if _ORCHESTRATOR is None:
        _ORCHESTRATOR = _fresh()
    # Correlation state must not leak between unrelated samples
    _ORCHESTRATOR.correlation.reset()
    match = _ORCHESTRATOR.evaluate_detection(event)
    if not match:
        return {"top": None, "all": []}
    return {"top": match["rule_id"], "all": sorted([match["rule_id"]] + list(match.get("also_matched", [])))}


def _fresh():
    orchestrator = SOAROrchestrator(policy_mode="DRY_RUN")
    orchestrator.exceptions.clock = lambda: VALIDATION_DATE
    return orchestrator


def current():
    return {key: evaluate(event) for key, event, _, _ in corpus()}


def diff(golden, now):
    changes = []
    for key in sorted(set(golden) | set(now)):
        if golden.get(key) != now.get(key):
            changes.append((key, golden.get(key), now.get(key)))
    return changes


def load_golden():
    with open(GOLDEN, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    parser = argparse.ArgumentParser(description="Detection regression corpus")
    parser.add_argument("--accept", action="store_true", help="rewrite the golden file with current results")
    args = parser.parse_args()
    now = current()
    if args.accept:
        os.makedirs(os.path.dirname(GOLDEN), exist_ok=True)
        with open(GOLDEN, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(now, fh, indent=1, sort_keys=True)
            fh.write("\n")
        print(f"wrote {os.path.relpath(GOLDEN, ROOT)} ({len(now)} events)")
        return
    changes = diff(load_golden(), now)
    for key, old, new in changes:
        print(f"{key}\n    was: {old}\n    now: {new}")
    print(f"{len(changes)} change(s) across {len(now)} corpus events")
    sys.exit(1 if changes else 0)


if __name__ == "__main__":
    main()
