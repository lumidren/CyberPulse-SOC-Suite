"""MITRE Caldera operation import, stub (roadmap F22)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.caldera import CalderaNotConfigured, compare, fetch_report, parse_operation_report, summarise  # noqa: E402

# Hand-written fixture in the Caldera operation-report layout (not a real export)
REPORT = {
    "name": "fixture-op",
    "steps": {
        "abcdef": {"steps": [
            {"ability_id": "a1", "name": "Encoded PowerShell", "run": "2026-11-01T10:00:00Z", "status": 0,
             "command": "SECRET-COMMAND-TEXT", "attack": {"technique_id": "T1059.001", "tactic": "execution"}},
            {"ability_id": "a2", "name": "Remote system discovery", "run": "2026-11-01T10:01:00Z", "status": 0,
             "attack": {"technique_id": "T1018", "tactic": "discovery"}},
            {"ability_id": "a3", "name": "Failed ability", "run": "2026-11-01T10:02:00Z", "status": 1,
             "attack": {"technique_id": "T1003.001", "tactic": "credential-access"}},
            {"ability_id": "a4", "name": "No ATT&CK mapping", "run": "2026-11-01T10:03:00Z", "status": 0},
        ]},
    },
}
INCIDENTS = [
    {"incident_id": "INC-1", "created_at": "2026-11-01T10:00:02+00:00",
     "rule": {"rule_id": "SOC-RULE-004", "mitre_id": "T1059.001"}},
    {"incident_id": "INC-2", "created_at": "2026-11-01T09:00:00+00:00",
     "rule": {"rule_id": "SOC-RULE-033", "mitre_id": "T1018"}},  # before the step: not a match
]


class TestCaldera(unittest.TestCase):

    def test_parses_executed_steps_without_commands(self):
        steps = parse_operation_report(REPORT)
        self.assertEqual([s["technique"] for s in steps], ["T1059.001", "T1018", "T1003.001"])
        self.assertNotIn("SECRET-COMMAND-TEXT", str(steps))

    def test_compare_and_summary(self):
        results = {r["technique"]: r for r in compare(parse_operation_report(REPORT), INCIDENTS)}
        self.assertTrue(results["T1059.001"]["detected"])
        self.assertEqual(results["T1059.001"]["latency_sec"], 2.0)
        self.assertFalse(results["T1018"]["detected"], "alert before the step does not count")
        summary = summarise(list(results.values()))
        self.assertEqual(summary, {"steps": 3, "succeeded": 2, "detected": 1, "missed": ["T1018"]})

    def test_fetch_needs_config_and_a_lab_address(self):
        os.environ.pop("CALDERA_URL", None)
        os.environ.pop("CALDERA_API_KEY", None)
        with self.assertRaises(CalderaNotConfigured):
            fetch_report("op1")
        with self.assertRaises(CalderaNotConfigured):
            fetch_report("op1", url="https://caldera.example.com", api_key="k")


if __name__ == "__main__":
    unittest.main()
