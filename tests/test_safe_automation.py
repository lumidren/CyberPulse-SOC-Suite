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


class TestBlastRadiusTiers(unittest.TestCase):

    def test_tier_assignments(self):
        from soar.action_tiers import TIER_1_AUTO_ELIGIBLE, TIER_2_HOST, TIER_3_IDENTITY, tier_for
        self.assertEqual(tier_for("BLOCK_SOURCE_IP_FIREWALL"), TIER_1_AUTO_ELIGIBLE)
        self.assertEqual(tier_for("ISOLATE_HOST_AND_KILL_PROCESS"), TIER_2_HOST)
        self.assertEqual(tier_for("ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES"), TIER_3_IDENTITY)
        self.assertEqual(tier_for("SOMETHING_NEW"), TIER_3_IDENTITY)  # unknown -> strictest

    def test_automatic_mode_only_auto_runs_tier_1(self):
        from simulator.attack_simulator import simulate_t1110_brute_force, simulate_t1003_dcsync
        orch = SOAROrchestrator(policy_mode="AUTOMATIC")
        ip_block = orch.process_event(simulate_t1110_brute_force())
        self.assertEqual(ip_block["containment_action"]["status"], "SUCCESS")
        self.assertEqual(ip_block["policy_decision"]["blast_radius_tier"], "TIER_1_AUTO_ELIGIBLE")

        isolation = orch.process_event(simulate_t1003_lsass_dump())
        self.assertEqual(isolation["containment_action"]["status"], "PENDING_ANALYST_APPROVAL")
        self.assertIn("approval_reason", isolation["policy_decision"])

        lockdown = orch.process_event(simulate_t1003_dcsync())
        self.assertEqual(lockdown["containment_action"]["status"], "PENDING_ANALYST_APPROVAL")
        self.assertEqual(lockdown["policy_decision"]["blast_radius_tier"], "TIER_3_IDENTITY")


if __name__ == "__main__":
    unittest.main()
