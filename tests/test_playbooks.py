"""YAML response playbooks (roadmap F32)."""

import os
import shutil
import sys
import tempfile
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

from simulator.attack_simulator import simulate_t1003_lsass_dump, simulate_t1110_brute_force  # noqa: E402
from soar.playbooks import Playbook, PlaybookError, PlaybookRegistry  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


def pb(**doc):
    base = {"name": "t", "version": "1.0.0", "description": "test"}
    base.update(doc)
    return Playbook(os.path.join(ROOT, "playbooks", "t.yml"), base)


class TestPlaybookValidation(unittest.TestCase):

    def test_cannot_enable_automation_or_unknown_actions(self):
        with self.assertRaises(PlaybookError):
            pb(response={"auto_execute": True})
        with self.assertRaises(PlaybookError):
            pb(response={"action": "RUN_ARBITRARY_COMMAND"})
        with self.assertRaises(PlaybookError):
            pb(response={"min_risk": 150})
        with self.assertRaises(PlaybookError):
            pb(steps=["anything"])

    def test_duplicate_rule_claims_rejected(self):
        tmp = tempfile.mkdtemp()
        try:
            for name in ("a", "b"):
                with open(os.path.join(tmp, f"{name}.yml"), "w", encoding="utf-8") as fh:
                    yaml.safe_dump({"name": name, "version": "1.0.0", "description": "d",
                                    "match": {"rules": ["SOC-RULE-001"]}}, fh)
            with self.assertRaises(PlaybookError):
                PlaybookRegistry(tmp)
        finally:
            shutil.rmtree(tmp)


class TestPlaybookDecisions(unittest.TestCase):

    def test_min_risk_downgrades_to_alert_only(self):
        decision = {"action": "ISOLATE_HOST_AND_KILL_PROCESS", "execution_intent": "PENDING_APPROVAL", "risk_score": 40}
        out = PlaybookRegistry.apply_to_decision(pb(response={"min_risk": 70}), decision)
        self.assertEqual((out["action"], out["execution_intent"]), ("ENRICH_AND_ALERT_ANALYST", "ALERT_ONLY"))

    def test_require_approval_overrides_automatic_execution(self):
        decision = {"action": "BLOCK_SOURCE_IP_FIREWALL", "execution_intent": "EXECUTE_IMMEDIATE", "risk_score": 95}
        out = PlaybookRegistry.apply_to_decision(pb(response={"require_approval": True}), decision)
        self.assertEqual(out["execution_intent"], "PENDING_APPROVAL")

    def test_never_loosens_a_decision(self):
        for intent in ("PENDING_APPROVAL", "DRY_RUN_SIMULATION", "ALERT_ONLY"):
            decision = {"action": "ISOLATE_HOST_AND_KILL_PROCESS", "execution_intent": intent, "risk_score": 99}
            out = PlaybookRegistry.apply_to_decision(pb(response={"require_approval": False}), dict(decision))
            self.assertEqual(out["execution_intent"], intent)


class TestCommittedPlaybooks(unittest.TestCase):

    def test_load_and_route(self):
        registry = PlaybookRegistry()
        self.assertEqual(registry.default.name, "default-triage")
        self.assertEqual(registry.select({"rule_id": "SOC-RULE-001", "mitre_id": "T1003.001"}).name, "credential-theft")
        self.assertEqual(registry.select({"rule_id": "SOC-RULE-999", "mitre_id": "T9999"}).name, "default-triage")

    def test_playbook_can_force_approval_in_full_auto(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "bf.yml"), "w", encoding="utf-8") as fh:
                yaml.safe_dump({"name": "bf-strict", "version": "1.0.0", "description": "d",
                                "match": {"techniques": ["T1110"]}, "response": {"require_approval": True}}, fh)
            orchestrator = SOAROrchestrator(policy_mode="AUTOMATIC")
            self.assertEqual(orchestrator.process_event(simulate_t1110_brute_force())["policy_decision"]["execution_intent"],
                             "EXECUTE_IMMEDIATE", "opt-in full auto runs the tier-1 block with the shipped playbook")
            orchestrator = SOAROrchestrator(policy_mode="AUTOMATIC")
            orchestrator.playbooks = PlaybookRegistry(tmp)
            incident = orchestrator.process_event(simulate_t1110_brute_force())
            self.assertEqual(incident["playbook"]["name"], "bf-strict")
            self.assertEqual(incident["policy_decision"]["execution_intent"], "PENDING_APPROVAL")
        finally:
            shutil.rmtree(tmp)

    def test_incident_carries_playbook_tasks(self):
        incident = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED").process_event(simulate_t1003_lsass_dump())
        self.assertEqual(incident["playbook"]["name"], "credential-theft")
        self.assertTrue(all(t["status"] == "Open" for t in incident["playbook"]["tasks"]))


if __name__ == "__main__":
    unittest.main()
