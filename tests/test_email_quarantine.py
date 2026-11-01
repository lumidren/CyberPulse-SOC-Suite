"""Phishing email quarantine playbook (roadmap F45)."""

import os
import sys
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.soar_engine import SOAROrchestrator  # noqa: E402


def reported_mail():
    with open(os.path.join(ROOT, "rules", "tests", "email_phishing_reported_or_auth_fail.yml"), encoding="utf-8") as fh:
        return yaml.safe_load(fh)["positive"][0]["event"]


class TestEmailQuarantine(unittest.TestCase):

    def test_reported_mail_alerts_then_analyst_proposes_quarantine(self):
        orchestrator = SOAROrchestrator(policy_mode="AUTOMATIC")
        incident = orchestrator.process_event(reported_mail())
        self.assertEqual(incident["rule"]["rule_id"], "SOC-RULE-050")
        self.assertEqual(incident["playbook"]["name"], "phishing")
        # Medium risk: the policy only alerts; nothing is quarantined automatically
        self.assertEqual(incident["policy_decision"]["execution_intent"], "ALERT_ONLY")
        self.assertEqual(orchestrator.propose_action(incident["incident_id"], "")["status"], "ERROR")
        proposed = orchestrator.propose_action(incident["incident_id"], "analyst_a")
        action = proposed["action"]
        self.assertEqual((action["action_type"], action["status"]), ("QUARANTINE_EMAIL", "PENDING_ANALYST_APPROVAL"))
        engine = orchestrator.containment_engine
        self.assertEqual(engine.approve_action(action["action_id"], approver="analyst_a")["status"], "SUCCESS")
        record = engine.action_registry[action["action_id"]]
        self.assertTrue(record["quarantine_request"]["url"].endswith("/move"))
        self.assertEqual(record["quarantine_request"]["body"], {"destinationId": "CyberPulseQuarantine"})
        rollback = engine.rollback_containment(action["action_id"], actor="analyst_a")
        self.assertEqual(rollback["reversibility"], "FULL")
        self.assertIn("back to", rollback["log"])


if __name__ == "__main__":
    unittest.main()
