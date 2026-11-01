"""Appeals / review flow: wrong containment leads to tuning (roadmap E98)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1053_scheduled_task  # noqa: E402
from soar.roles import allowed  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class TestAppeals(unittest.TestCase):

    def setUp(self):
        self.orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        self.incident = self.orchestrator.process_event(simulate_t1053_scheduled_task())
        self.store = self.orchestrator.appeals

    def test_full_loop_open_accept_draft_tuned(self):
        appeal = self.store.open(self.incident, "alice", "false_positive", "IT maintenance task")["appeal"]
        self.assertEqual(appeal["rule_id"], "SOC-RULE-003")
        decided = self.store.decide(appeal["appeal_id"], "lead_bob", True, "confirmed with IT", self.incident)["appeal"]
        draft = decided["draft_exception"]
        self.assertEqual(draft["rule"], "SOC-RULE-003")
        self.assertIn("TaskName", draft["match"])
        self.assertIn("Draft only", draft["review_note"])
        self.assertEqual(self.store.mark_tuned(appeal["appeal_id"], "alice", "EXC-0003")["appeal"]["status"], "Tuned")
        self.assertEqual(self.store.per_rule()["SOC-RULE-003"], {"tuned": 1})
        events = [e["event"] for e in self.orchestrator.containment_engine.ledger.entries if e["event"].startswith("appeal.")]
        self.assertEqual(events, ["appeal.open", "appeal.decide", "appeal.tuned"])

    def test_validation_and_order(self):
        self.assertEqual(self.store.open(self.incident, "", "false_positive", "x")["status"], "ERROR")
        self.assertEqual(self.store.open(self.incident, "a", "bogus", "x")["status"], "ERROR")
        self.assertEqual(self.store.open(self.incident, "a", "wrong_action", " ")["status"], "ERROR")
        appeal = self.store.open(self.incident, "a", "wrong_action", "should have been alert-only")["appeal"]
        self.assertEqual(self.store.mark_tuned(appeal["appeal_id"], "a", "x")["status"], "ERROR", "needs acceptance first")
        self.store.decide(appeal["appeal_id"], "lead", False, "isolation was right")
        self.assertEqual(self.store.decide(appeal["appeal_id"], "lead", True, "again")["status"], "ERROR")

    def test_opening_an_appeal_changes_nothing_else(self):
        before = dict(self.incident["containment_action"])
        self.store.open(self.incident, "alice", "wrong_target", "wrong host")
        self.assertEqual(self.incident["containment_action"], before)

    def test_only_leads_decide(self):
        self.assertFalse(allowed("analyst", "POST", "/api/appeals/APL-1/decide"))
        self.assertTrue(allowed("analyst", "POST", "/api/incidents/INC-1/appeal"))
        self.assertTrue(allowed("lead", "POST", "/api/appeals/APL-1/decide"))


if __name__ == "__main__":
    unittest.main()
