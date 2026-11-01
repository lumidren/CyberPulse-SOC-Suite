#!/usr/bin/env python3
"""
Detection validation for the CyberPulse SOC Lab.

Replays synthetic traffic through the detection engine and reports counts.
These are counts on traffic the project itself generated, so they measure
"does the rule match the events we scripted", not real-world efficacy.

  * Scripted detections: every attack generator is run RUNS times and we count
    how often the *expected* rule fired ("X/Y scripted runs detected").
  * False positives: the deterministic benign baseline
    (simulator/benign_baseline.py) is replayed and every rule match is an FP.

Usage:
    python scripts/validate_detections.py            # print markdown report
    python scripts/validate_detections.py --write    # regenerate docs/VALIDATION_RESULTS.md
"""

import argparse
import os
import sys
from collections import Counter
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import SCRIPTED_GENERATORS  # noqa: E402
from simulator.benign_baseline import generate_baseline  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402

SCRIPTED_RUNS = 6
BASELINE_COUNT = 600
BASELINE_SEED = 1337
RESULTS_PATH = os.path.join(ROOT, "docs", "VALIDATION_RESULTS.md")
# Exceptions expire; evaluate them as of a fixed date so the committed report is reproducible
VALIDATION_DATE = date(2026, 11, 1)

# Rule each scripted generator is written to trigger.
EXPECTED_RULE = {
    "t1003": "SOC-RULE-001",
    "t1110": "SOC-RULE-002",
    "t1053": "SOC-RULE-003",
    "t1059": "SOC-RULE-004",
    "t1562": "SOC-RULE-005",
    "t1486": "SOC-RULE-006",
    "t1558": "SOC-RULE-007",
    "t1003_dcsync": "SOC-RULE-008",
    "cloud_aws": "SOC-RULE-009",
    "cloud_entra": "SOC-RULE-010",
}


def run_scripted(runs=SCRIPTED_RUNS):
    """Run each attack generator `runs` times; count matches of the expected rule."""
    orchestrator = SOAROrchestrator(policy_mode="DRY_RUN")
    results = {}
    for name, generator in SCRIPTED_GENERATORS:
        expected = EXPECTED_RULE[name]
        detected = 0
        for _ in range(runs):
            match = orchestrator.evaluate_detection(generator())
            if match and match["rule_id"] == expected:
                detected += 1
        results[expected] = {"generator": name, "detected": detected, "runs": runs}
    return results


def scripted_status(rule_id, scripted):
    """Human-readable validation status for a catalogue rule."""
    r = scripted.get(rule_id)
    if not r:
        return "No scripted test yet"
    return f"{r['detected']}/{r['runs']} scripted runs detected (self-authored events)"


def run_baseline(count=BASELINE_COUNT, seed=BASELINE_SEED):
    """Replay benign events; every detection is a false positive."""
    orchestrator = SOAROrchestrator(policy_mode="DRY_RUN")
    orchestrator.exceptions.clock = lambda: VALIDATION_DATE
    fps_by_rule = Counter()
    fps_by_category = Counter()
    events = generate_baseline(count, seed)
    for event in events:
        match = orchestrator.evaluate_detection(event)
        if match:
            fps_by_rule[match["rule_id"]] += 1
            fps_by_category[event["baseline_category"]] += 1
    return {
        "events": len(events),
        "seed": seed,
        "false_positives": sum(fps_by_rule.values()),
        "by_rule": dict(sorted(fps_by_rule.items())),
        "by_category": dict(sorted(fps_by_category.items())),
        "suppressed": dict(sorted(orchestrator.exceptions.suppressed.items())),
    }


def run_confusion(runs=SCRIPTED_RUNS, count=BASELINE_COUNT, seed=BASELINE_SEED):
    """Confusion counts over a labelled set: scripted attacks (label = expected rule) + benign baseline.

    Overall: did an attack event alert at all, did a benign one. Per rule: TP when the rule is the
    top match for an event labelled with it, FN when such an event got another or no rule, FP when
    the rule is the top match for any other event, TN for everything else."""
    labelled = []
    attacks = SOAROrchestrator(policy_mode="DRY_RUN")
    for _ in range(runs):
        for name, generator in SCRIPTED_GENERATORS:
            match = attacks.evaluate_detection(generator())
            labelled.append((EXPECTED_RULE[name], (match or {}).get("rule_id")))
    benign = SOAROrchestrator(policy_mode="DRY_RUN")
    benign.exceptions.clock = lambda: VALIDATION_DATE
    for event in generate_baseline(count, seed):
        labelled.append((None, (benign.evaluate_detection(event) or {}).get("rule_id")))
    overall = {
        "tp": sum(1 for label, fired in labelled if label and fired),
        "fn": sum(1 for label, fired in labelled if label and not fired),
        "fp": sum(1 for label, fired in labelled if not label and fired),
        "tn": sum(1 for label, fired in labelled if not label and not fired),
    }
    rules = sorted({label for label, _ in labelled if label} | {fired for _, fired in labelled if fired})
    per_rule = {}
    for rule in rules:
        tp = sum(1 for label, fired in labelled if label == rule and fired == rule)
        fn = sum(1 for label, fired in labelled if label == rule and fired != rule)
        fp = sum(1 for label, fired in labelled if label != rule and fired == rule)
        per_rule[rule] = {"tp": tp, "fn": fn, "fp": fp, "tn": len(labelled) - tp - fn - fp}
    return {"events": len(labelled), "overall": overall, "per_rule": per_rule}


def _ratio(num, den):
    return f"{num / den:.3f}" if den else "n/a"


def render_confusion(conf, suppressed=0):
    o = conf["overall"]
    lines = [
        "## Confusion matrix",
        "",
        f"Over {conf['events']} labelled events: every scripted attack run (label: the expected rule) plus every",
        "benign baseline event (label: none), after exceptions. Counts are real outputs of this script; the",
        "events are synthetic and self-authored, so precision and recall here describe agreement between",
        "the rules and their own test data, not performance on real traffic.",
        "",
        "| | Alerted | Did not alert |",
        "| :--- | ---: | ---: |",
        f"| **Attack event** | TP {o['tp']} | FN {o['fn']} |",
        f"| **Benign event** | FP {o['fp']} | TN {o['tn']} |",
        "",
        f"Precision {_ratio(o['tp'], o['tp'] + o['fp'])}, recall {_ratio(o['tp'], o['tp'] + o['fn'])}"
        + (f" (without the exceptions, FP would be {o['fp'] + suppressed} and precision "
           f"{_ratio(o['tp'], o['tp'] + o['fp'] + suppressed)})." if suppressed else "."),
        f"Only the {len([r for r, c in conf['per_rule'].items() if c['tp'] + c['fn']])} rules with a scripted attack "
        "generator appear below; the others are checked by their samples in `rules/tests/` only.",
        "",
        "Per rule (top match only; a rule that fires for another rule's attack counts as a false positive):",
        "",
        "| Rule | TP | FN | FP | TN |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    lines += [f"| `{rule}` | {c['tp']} | {c['fn']} | {c['fp']} | {c['tn']} |" for rule, c in conf["per_rule"].items()]
    lines.append("")
    return lines


def render_markdown(scripted, baseline, confusion=None):
    lines = [
        "# Detection Validation Results",
        "",
        "> Generated by `python scripts/validate_detections.py --write`. Do not edit by hand;",
        "> CI fails if this file drifts from the script's output.",
        ">",
        "> All traffic is synthetic and was written by the same author as the rules.",
        "> These counts show the rules match the scripted events; they are **not**",
        "> evidence of real-world detection efficacy or real-world false-positive rates.",
        "",
        "## Scripted attack runs",
        "",
        f"**{sum(r['detected'] for r in scripted.values())}/{sum(r['runs'] for r in scripted.values())} "
        "scripted runs detected by the expected rule.** Because the attack events and the rules",
        "were written together, this is a regression check, not an efficacy measurement.",
        "",
        "| Rule | Generator | Detected |",
        "| :--- | :--- | ---: |",
    ]
    lines += [f"| `{rule}` | `{r['generator']}` | {r['detected']}/{r['runs']} |" for rule, r in sorted(scripted.items())]
    lines += [
        "",
        "## False positives on the benign baseline",
        "",
        f"**{baseline['false_positives']} false positives in {baseline['events']} baseline events** "
        f"(seed {baseline['seed']}; see [BASELINE_TRAFFIC.md](BASELINE_TRAFFIC.md))"
        + (f", **after {sum(baseline['suppressed'].values())} matches were suppressed by "
           f"{len(baseline['suppressed'])} exception(s)** (below)." if baseline.get("suppressed") else "."),
        "",
    ]
    if baseline["by_rule"]:
        lines += ["| Rule | False positives |", "| :--- | ---: |"]
        lines += [f"| `{rule}` | {n} |" for rule, n in baseline["by_rule"].items()]
        lines += ["", "| Baseline category | False positives |", "| :--- | ---: |"]
        lines += [f"| `{cat}` | {n} |" for cat, n in baseline["by_category"].items()]
    else:
        lines.append("No baseline event raised an alert.")
    if baseline.get("suppressed"):
        lines += ["", "### Suppressed by exceptions", "",
                  f"Matches allowlisted in [`rules/exceptions.yml`](../rules/exceptions.yml), evaluated as of "
                  f"{VALIDATION_DATE.isoformat()}. These are not counted above but are not hidden: the exceptions",
                  "were written for this synthetic baseline by the rule author, so the drop in false positives is",
                  "tuning against known data, not an independent measurement.", "",
                  "| Exception | Suppressed matches |", "| :--- | ---: |"]
        lines += [f"| `{exc}` | {n} |" for exc, n in baseline["suppressed"].items()]
    lines.append("")
    if confusion:
        lines += render_confusion(confusion, sum((baseline.get("suppressed") or {}).values()))
    return "\n".join(lines)


def build_report():
    return render_markdown(run_scripted(), run_baseline(), run_confusion())


def main():
    from simulator.lab_guard import lab_mode_enabled
    if not lab_mode_enabled():
        sys.exit("Refusing to run: set CYBERPULSE_LAB_MODE=true (lab use only).")
    parser = argparse.ArgumentParser(description="Replay synthetic traffic and count detections.")
    parser.add_argument("--write", action="store_true", help=f"write {os.path.relpath(RESULTS_PATH, ROOT)}")
    args = parser.parse_args()
    report = build_report()
    if args.write:
        with open(RESULTS_PATH, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report)
        print(f"wrote {RESULTS_PATH}")
    else:
        print(report)


if __name__ == "__main__":
    main()
