"""Tamper-evident ledger of every automated action (roadmap E97)."""

import json
import os
import sys
import tempfile
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar.action_ledger import ActionLedger, verify  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class TestActionLedger(unittest.TestCase):

    def test_lifecycle_is_recorded_with_who_what_why(self):
        orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        engine = orchestrator.containment_engine
        incident = orchestrator.process_event(simulate_t1003_lsass_dump())
        action_id = incident["containment_action"]["action_id"]
        engine.approve_action(action_id, approver="alice", comment="confirmed LSASS read")
        engine.rollback_containment(action_id, actor="bob")
        engine.safety.engage_kill_switch("carol", "drill")
        events = [(e["event"], e["actor"]) for e in engine.ledger.entries]
        self.assertEqual(events, [("containment.pending_analyst_approval", "soar-pipeline"), ("containment.approve", "alice"),
                                  ("containment.rollback", "bob"), ("kill_switch.engage", "carol")])
        first = engine.ledger.entries[0]
        self.assertEqual(first["what"]["action_id"], action_id)
        self.assertIn("SOC-RULE-001", first["why"])
        self.assertTrue(engine.ledger.verify()["intact"])

    def test_tampering_is_detected(self):
        ledger = ActionLedger(path="")
        for i in range(3):
            ledger.record("a", "e", {"i": i}, "why")
        ledger.entries[1]["actor"] = "mallory"
        self.assertFalse(ledger.verify()["intact"])

    def test_file_persistence_continues_and_verifies_the_chain(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "actions.jsonl")
            first = ActionLedger(path=path)
            first.record("a", "e1", {}, "")
            second = ActionLedger(path=path)
            second.record("b", "e2", {}, "")
            with open(path, encoding="utf-8") as fh:
                entries = [json.loads(line) for line in fh]
            self.assertEqual([e["seq"] for e in entries], [1, 2])
            self.assertTrue(verify(entries)["intact"])
            entries[0]["why"] = "edited"
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("".join(json.dumps(e) + "\n" for e in entries))
            self.assertFalse(ActionLedger(path=path).verify()["intact"], "tampering found on load")


if __name__ == "__main__":
    unittest.main()
