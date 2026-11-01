"""Multi-stage attack chain emulation, initial access to exfiltration (roadmap F28)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_chain import KILL_CHAIN_STAGES, run_chain  # noqa: E402
from simulator.lab_guard import LabModeRequired  # noqa: E402


class TestAttackChain(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.results = run_chain()

    def test_chain_spans_initial_access_to_exfiltration(self):
        tactics = [s["tactic"] for s in KILL_CHAIN_STAGES]
        self.assertEqual(tactics[0], "Initial Access")
        self.assertIn("Exfiltration", tactics)
        self.assertIn("Lateral Movement", tactics)

    def test_every_stage_detected_by_expected_rule(self):
        missed = [(r["stage"], r["rule_id"]) for r in self.results if not r["detected"]]
        self.assertEqual(missed, [])

    def test_events_are_chronological_and_move_hosts(self):
        times = [r["event_time"] for r in self.results]
        self.assertEqual(times, sorted(times))
        self.assertGreater(len({r["host"] for r in self.results}), 1)

    def test_default_policy_proposes_rather_than_executes(self):
        self.assertFalse(any(r["containment_status"] == "SUCCESS" for r in self.results))

    def test_refuses_outside_lab_mode(self):
        saved = os.environ.pop("CYBERPULSE_LAB_MODE")
        try:
            with self.assertRaises(LabModeRequired):
                KILL_CHAIN_STAGES[0]["generator"]()
        finally:
            os.environ["CYBERPULSE_LAB_MODE"] = saved


if __name__ == "__main__":
    unittest.main()
