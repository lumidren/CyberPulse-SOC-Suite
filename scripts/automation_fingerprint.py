#!/usr/bin/env python3
"""
Fingerprint of everything that decides what CyberPulse does automatically (roadmap E100).

    python scripts/automation_fingerprint.py           # print the fingerprint and its inputs
    python scripts/automation_fingerprint.py --check   # exit 1 if CHANGELOG.md does not record it

Inputs: action tiers and reversibility, which rule proposes which action, rule confidence
and the confidence threshold, risk weights, safety defaults (rate limit, circuit breaker,
TTLs, default policy mode), playbook fingerprints, role restrictions and exception
lifetimes. Changing any of them changes the fingerprint, and the test suite then
requires a new entry under "Automation behaviour" in CHANGELOG.md that quotes it, so an
automation change cannot ship without a human-readable record.

Values are read with environment overrides removed, so the fingerprint describes the
shipped defaults, not one machine's configuration.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
CHANGELOG = os.path.join(ROOT, "CHANGELOG.md")
TUNABLE_ENV = ("CONTAINMENT_MAX_ACTIONS_PER_HOUR", "ISOLATION_BREAKER_MAX_HOSTS", "ISOLATION_BREAKER_WINDOW_MIN",
               "ISOLATION_TTL_MIN", "IP_BLOCK_TTL_MIN", "CONFIDENCE_THRESHOLD", "POLICY_MODE", "ALLOW_FULL_AUTO")


def _shipped_confidence_threshold():
    """The default in the source, not the value the running process may have read from the environment."""
    with open(os.path.join(ROOT, "soar", "risk_engine.py"), encoding="utf-8") as fh:
        return float(re.search(r'"CONFIDENCE_THRESHOLD", "([0-9.]+)"', fh.read()).group(1))


def inputs():
    clean = {k: v for k, v in os.environ.items() if k not in TUNABLE_ENV}
    with mock.patch.dict(os.environ, clean, clear=True):
        from soar import risk_engine
        from soar.action_tiers import ACTION_TIERS
        from soar.playbooks import PlaybookRegistry
        from soar.resilient_containment import ROLLBACK_PLAYBOOKS
        from soar.roles import LEAD_ONLY
        from soar.rule_exceptions import MAX_LIFETIME_DAYS
        from soar.safety import AutomationSafety
        from soar.sigma_correlation import CorrelationEngine
        from soar.sigma_engine import SigmaEngine

        safety = AutomationSafety()
        rules = SigmaEngine().rules + CorrelationEngine().rules
        return {
            "action_tiers": dict(sorted(ACTION_TIERS.items())),
            "reversibility": {k: v[0] for k, v in sorted(ROLLBACK_PLAYBOOKS.items())},
            "rule_actions": dict(sorted((r.soar.get("soc_rule_id", r.id), r.soar.get("action_recommended")) for r in rules)),
            "rule_confidence": dict(sorted(risk_engine.RULE_CONFIDENCE.items())),
            "default_rule_confidence": risk_engine.DEFAULT_RULE_CONFIDENCE,
            "confidence_threshold": _shipped_confidence_threshold(),
            "risk_weights": {"assets": risk_engine.ASSET_CRITICALITY, "accounts": risk_engine.ACCOUNT_PRIVILEGES,
                             "tactics": risk_engine.TACTIC_WEIGHTS},
            "safety": {"max_actions_per_hour": safety.max_actions_per_hour, "breaker_max_hosts": safety.breaker_max_hosts,
                       "breaker_window_sec": safety.breaker_window_sec, "ttl_minutes": dict(sorted(safety.ttl_minutes.items()))},
            "playbooks": {pb.name: pb.fingerprint() for pb in sorted(PlaybookRegistry().playbooks, key=lambda p: p.name)},
            "lead_only": [p.pattern for p in LEAD_ONLY],
            "exception_max_days": MAX_LIFETIME_DAYS,
        }


def fingerprint():
    return hashlib.sha256(json.dumps(inputs(), sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def recorded():
    with open(CHANGELOG, encoding="utf-8") as fh:
        return re.findall(r"Automation fingerprint: `([0-9a-f]{16})`", fh.read())


def main():
    parser = argparse.ArgumentParser(description="Automation behaviour fingerprint")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    current = fingerprint()
    if args.check:
        found = recorded()
        ok = bool(found) and found[0] == current
        print(f"current {current}, latest recorded {found[0] if found else 'none'}: {'OK' if ok else 'CHANGELOG ENTRY NEEDED'}")
        sys.exit(0 if ok else 1)
    print(current)
    print(json.dumps(inputs(), indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
