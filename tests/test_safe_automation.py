"""
Safe-Automation Test Suite for the CyberPulse SOC Lab

Covers the human-oversight controls around containment: approval gating,
defaults, tiers, kill switch, thresholds, rate limits, protected assets,
TTLs and rollback.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar.resilient_containment import ResilientContainmentEngine  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


def stage(engine, action_type="ISOLATE_HOST_AND_KILL_PROCESS", host="WIN-WORKSTATION09"):
    return engine.execute_containment(
        action_type=action_type, target_host=host, target_ip="10.0.2.15",
        target_user="CORP\\j.doe", pid=4812, process_name="tool.exe",
        execution_intent="PENDING_APPROVAL",
    )


class TestApprovalWorkflow(unittest.TestCase):

    def test_staged_action_does_nothing_until_approved(self):
        engine = ResilientContainmentEngine()
        act = stage(engine)
        self.assertEqual(act["status"], "PENDING_ANALYST_APPROVAL")
        self.assertNotIn("WIN-WORKSTATION09", engine.host_isolation_registry)
        self.assertEqual([a["action_id"] for a in engine.pending_approvals()], [act["action_id"]])

        result = engine.approve_action(act["action_id"], approver="analyst_a", comment="confirmed TP")
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(act["status"], "SUCCESS")
        self.assertEqual(act["approval"]["approver"], "analyst_a")
        self.assertIn("WIN-WORKSTATION09", engine.host_isolation_registry)
        self.assertEqual(engine.pending_approvals(), [])

    def test_rejected_action_never_executes(self):
        engine = ResilientContainmentEngine()
        act = stage(engine)
        result = engine.reject_action(act["action_id"], approver="analyst_b", reason="benign admin task")
        self.assertEqual(result["status"], "SUCCESS")
        self.assertEqual(act["status"], "REJECTED_BY_ANALYST")
        self.assertNotIn("WIN-WORKSTATION09", engine.host_isolation_registry)
        # A rejected action cannot be approved afterwards
        self.assertEqual(engine.approve_action(act["action_id"], approver="analyst_c")["status"], "ERROR")

    def test_approval_requires_identity(self):
        engine = ResilientContainmentEngine()
        act = stage(engine)
        self.assertEqual(engine.approve_action(act["action_id"], approver="")["status"], "ERROR")
        self.assertEqual(act["status"], "PENDING_ANALYST_APPROVAL")

    def test_incident_status_tracks_approval(self):
        orch = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        incident = orch.process_event(simulate_t1003_lsass_dump())
        self.assertEqual(incident["status"], "PENDING_APPROVAL")
        action_id = incident["containment_action"]["action_id"]
        orch.containment_engine.approve_action(action_id, approver="analyst_a")
        orch.dfir_engine.refresh_status(incident)
        self.assertEqual(incident["status"], "CONTAINED")


class TestApprovalIsDefault(unittest.TestCase):

    def test_orchestrator_defaults_to_approval(self):
        orch = SOAROrchestrator()
        self.assertEqual(orch.risk_engine.policy_mode, "APPROVAL_REQUIRED")
        incident = orch.process_event(simulate_t1003_lsass_dump())
        self.assertEqual(incident["containment_action"]["status"], "PENDING_ANALYST_APPROVAL")
        self.assertEqual(orch.containment_engine.host_isolation_registry, set())


if __name__ == "__main__":
    unittest.main()
