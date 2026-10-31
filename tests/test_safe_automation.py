"""
Safe-Automation Test Suite for the CyberPulse SOC Lab

Covers the human-oversight controls around containment: approval gating,
defaults, tiers, kill switch, thresholds, rate limits, protected assets,
TTLs and rollback.
"""

import os
os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
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


class TestKillSwitch(unittest.TestCase):

    def test_kill_switch_halts_execution_and_approvals(self):
        engine = ResilientContainmentEngine()
        staged = stage(engine)
        engine.safety.engage_kill_switch("lead_analyst", "suspected bad rule push")

        direct = engine.execute_containment(
            action_type="BLOCK_SOURCE_IP_FIREWALL", target_host="CORP-RDP-GW01", target_ip="203.0.113.7",
            target_user="admin", pid=None, process_name=None)
        self.assertEqual(direct["status"], "HALTED_BY_KILL_SWITCH")
        self.assertEqual(engine.blocked_ips, set())
        self.assertEqual(engine.approve_action(staged["action_id"], approver="analyst_a")["status"], "ERROR")

        engine.safety.release_kill_switch("lead_analyst", "rule reverted")
        self.assertEqual(engine.approve_action(staged["action_id"], approver="analyst_a")["status"], "SUCCESS")

    def test_kill_switch_applies_to_automatic_mode(self):
        from simulator.attack_simulator import simulate_t1110_brute_force
        orch = SOAROrchestrator(policy_mode="AUTOMATIC")
        orch.containment_engine.safety.engage_kill_switch("lead_analyst", "drill")
        incident = orch.process_event(simulate_t1110_brute_force())
        self.assertEqual(incident["containment_action"]["status"], "HALTED_BY_KILL_SWITCH")
        self.assertEqual(incident["status"], "HALTED_BY_KILL_SWITCH")


class TestConfidenceThreshold(unittest.TestCase):

    def test_low_confidence_rule_escalates_instead_of_acting(self):
        from simulator.attack_simulator import simulate_t1059_powershell_execution
        orch = SOAROrchestrator(policy_mode="AUTOMATIC")
        incident = orch.process_event(simulate_t1059_powershell_execution())  # SOC-RULE-004, confidence 0.60
        decision = incident["policy_decision"]
        self.assertEqual(decision["action"], "ESCALATE_TO_ANALYST")
        self.assertEqual(decision["execution_intent"], "ESCALATE")
        self.assertLess(decision["rule_confidence"], decision["confidence_threshold"])
        self.assertEqual(incident["containment_action"]["status"], "FLAGGED_FOR_MANUAL_REVIEW")
        self.assertEqual(incident["status"], "NEEDS_ANALYST_REVIEW")
        self.assertEqual(orch.containment_engine.disabled_users, set())

    def test_threshold_is_tunable(self):
        from simulator.attack_simulator import simulate_t1059_powershell_execution
        orch = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        orch.risk_engine.confidence_threshold = 0.5
        incident = orch.process_event(simulate_t1059_powershell_execution())
        self.assertEqual(incident["policy_decision"]["execution_intent"], "PENDING_APPROVAL")


class TestContainmentRateLimit(unittest.TestCase):

    def _block(self, engine, ip):
        return engine.execute_containment(
            action_type="BLOCK_SOURCE_IP_FIREWALL", target_host="CORP-RDP-GW01", target_ip=ip,
            target_user="admin", pid=None, process_name=None)

    def test_hourly_budget_stages_excess_actions(self):
        now = [1_000_000.0]
        engine = ResilientContainmentEngine()
        engine.safety.clock = lambda: now[0]
        engine.safety.max_actions_per_hour = 3

        results = [self._block(engine, f"203.0.113.{i}")["status"] for i in range(5)]
        self.assertEqual(results, ["SUCCESS"] * 3 + ["PENDING_ANALYST_APPROVAL"] * 2)
        self.assertEqual(len(engine.blocked_ips), 3)

        now[0] += 3601  # window rolls over
        self.assertEqual(self._block(engine, "203.0.113.99")["status"], "SUCCESS")

    def test_approvals_count_toward_budget(self):
        engine = ResilientContainmentEngine()
        engine.safety.max_actions_per_hour = 1
        staged = stage(engine)
        engine.approve_action(staged["action_id"], approver="analyst_a")
        self.assertTrue(engine.safety.rate_limit_exceeded())
        self.assertEqual(self._block(engine, "203.0.113.5")["status"], "PENDING_ANALYST_APPROVAL")


class TestIsolationCircuitBreaker(unittest.TestCase):

    def test_mass_isolation_trips_kill_switch_and_pages(self):
        pages = []
        engine = ResilientContainmentEngine()
        engine.safety.pager = pages.append
        engine.safety.breaker_max_hosts = 3
        for host in ["WKS-01", "WKS-02", "WKS-03"]:
            act = stage(engine, host=host)
            engine.approve_action(act["action_id"], approver="analyst_a")

        self.assertTrue(engine.safety.is_halted())
        self.assertEqual(engine.safety.kill_switch["actor"], "isolation-circuit-breaker")
        self.assertEqual(len(pages), 1)
        self.assertIn("3 hosts isolated", pages[0])
        self.assertTrue(engine.safety.breaker_trips[0]["paged"])

        # Nothing else runs until a human releases the switch
        fourth = stage(engine, host="WKS-04")
        self.assertEqual(engine.approve_action(fourth["action_id"], approver="analyst_a")["status"], "ERROR")

    def test_isolations_outside_window_do_not_trip(self):
        now = [0.0]
        engine = ResilientContainmentEngine()
        engine.safety.clock = lambda: now[0]
        engine.safety.breaker_max_hosts = 2
        engine.safety.breaker_window_sec = 600
        for host in ["WKS-01", "WKS-02"]:
            act = stage(engine, host=host)
            engine.approve_action(act["action_id"], approver="analyst_a")
            now[0] += 700
        self.assertFalse(engine.safety.is_halted())

    def test_orchestrator_wires_pager(self):
        orch = SOAROrchestrator()
        self.assertIsNotNone(orch.containment_engine.safety.pager)


class TestProtectedAssets(unittest.TestCase):

    def test_protected_match_rules(self):
        from soar.protected_assets import protected_match
        self.assertEqual(protected_match(ip="10.0.0.10"), "10.0.0.10")
        self.assertIsNotNone(protected_match(host="WIN-DC01.corp.local"))
        self.assertIsNotNone(protected_match(host="jump-07"))           # pattern, case-insensitive
        self.assertIsNotNone(protected_match(ip="10.0.1.15"))           # SOC subnet CIDR
        self.assertIsNone(protected_match(host="WIN-WORKSTATION09"))
        self.assertIsNone(protected_match(ip="203.0.113.9"))

    def test_dc_is_never_isolated_even_with_approval(self):
        engine = ResilientContainmentEngine()
        act = stage(engine, host="WIN-DC01.corp.local")
        self.assertEqual(act["status"], "BLOCKED_PROTECTED_ASSET")
        self.assertEqual(engine.pending_approvals(), [])
        self.assertEqual(engine.approve_action(act["action_id"], approver="analyst_a")["status"], "ERROR")
        self.assertNotIn("WIN-DC01.corp.local", engine.host_isolation_registry)

    def test_dc_ip_is_never_blocked_at_perimeter(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="BLOCK_SOURCE_IP_FIREWALL", target_host="CORP-RDP-GW01", target_ip="10.0.0.10",
            target_user="admin", pid=None, process_name=None)
        self.assertEqual(act["status"], "BLOCKED_PROTECTED_ASSET")
        self.assertEqual(engine.blocked_ips, set())

    def test_lsass_on_dc_is_flagged_not_contained(self):
        orch = SOAROrchestrator(policy_mode="AUTOMATIC")
        event = simulate_t1003_lsass_dump()
        event["computer_name"] = "WIN-DC01.corp.local"
        incident = orch.process_event(event)
        self.assertEqual(incident["containment_action"]["status"], "BLOCKED_PROTECTED_ASSET")
        self.assertEqual(incident["status"], "NEEDS_ANALYST_REVIEW")


class TestProtectedAccounts(unittest.TestCase):

    def test_account_matching_ignores_domain_and_case(self):
        from soar.protected_assets import protected_account_match
        self.assertEqual(protected_account_match("CORP\\krbtgt"), "krbtgt")
        self.assertEqual(protected_account_match("ADMINISTRATOR@corp.local"), "Administrator")
        self.assertEqual(protected_account_match("CORP\\breakglass-01"), "breakglass*")
        self.assertIsNone(protected_account_match("CORP\\j.doe"))

    def test_protected_account_is_never_locked(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES", target_host="WIN-WORKSTATION09",
            target_ip="10.0.0.45", target_user="CORP\\Administrator", pid=None, process_name=None,
            execution_intent="PENDING_APPROVAL")
        self.assertEqual(act["status"], "BLOCKED_PROTECTED_ACCOUNT")
        self.assertEqual(engine.pending_approvals(), [])
        self.assertEqual(engine.disabled_users, set())

    def test_unprotected_account_still_flows_to_approval(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET", target_host="WIN-DC01.corp.local",
            target_ip="10.0.0.45", target_user="CORP\\j.doe", pid=None, process_name=None,
            execution_intent="PENDING_APPROVAL")
        self.assertEqual(act["status"], "PENDING_ANALYST_APPROVAL")


class TestContainmentTTL(unittest.TestCase):

    def test_isolation_expires_and_rolls_back(self):
        now = [10_000.0]
        engine = ResilientContainmentEngine()
        engine.safety.clock = lambda: now[0]
        act = stage(engine)
        engine.approve_action(act["action_id"], approver="analyst_a")
        self.assertEqual(act["expires_at_epoch"], 10_000.0 + 240 * 60)
        self.assertEqual(engine.expire_actions(), [])

        now[0] += 240 * 60
        expired = engine.expire_actions()
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["actor"], "ttl-expiry")
        self.assertEqual(act["status"], "ROLLED_BACK")
        self.assertNotIn("WIN-WORKSTATION09", engine.host_isolation_registry)

    def test_extend_renews_ttl(self):
        now = [0.0]
        engine = ResilientContainmentEngine()
        engine.safety.clock = lambda: now[0]
        act = stage(engine)
        engine.approve_action(act["action_id"], approver="analyst_a")
        now[0] += 200 * 60
        self.assertEqual(engine.extend_action(act["action_id"], 120, actor="analyst_a")["status"], "SUCCESS")
        now[0] += 60 * 60  # past the original TTL, inside the extension
        self.assertEqual(engine.expire_actions(), [])
        self.assertEqual(act["status"], "SUCCESS")

    def test_orchestrator_notes_expiry_on_incident(self):
        now = [0.0]
        from simulator.attack_simulator import simulate_t1110_brute_force
        orch = SOAROrchestrator(policy_mode="AUTOMATIC")
        orch.containment_engine.safety.clock = lambda: now[0]
        incident = orch.process_event(simulate_t1110_brute_force())
        now[0] += 1440 * 60
        orch.expire_containment()
        self.assertEqual(incident["status"], "ROLLED_BACK")
        self.assertEqual(incident["analyst_notes"][-1]["author"], "ttl-expiry")


class TestRollbackEveryAction(unittest.TestCase):

    def test_every_tiered_action_has_a_rollback(self):
        from soar.action_tiers import ACTION_TIERS
        from soar.resilient_containment import ROLLBACK_PLAYBOOKS
        self.assertEqual(set(ACTION_TIERS) - set(ROLLBACK_PLAYBOOKS), set())

    def test_rollback_reports_what_was_not_restored(self):
        engine = ResilientContainmentEngine()
        for action_type in ["BLOCK_SOURCE_IP_FIREWALL", "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS",
                            "RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET"]:
            act = engine.execute_containment(
                action_type=action_type, target_host="WIN-WORKSTATION09", target_ip="203.0.113.4",
                target_user="CORP\\j.doe", pid=4812, process_name="tool.exe")
            rb = engine.rollback_containment(act["action_id"], actor="analyst_a")
            self.assertEqual(rb["status"], "SUCCESS")
            if rb["reversibility"] == "PARTIAL":
                self.assertTrue(rb["not_restored"])
        self.assertEqual(engine.blocked_ips, set())
        self.assertEqual(engine.disabled_users, set())

    def test_staged_action_cannot_be_rolled_back(self):
        engine = ResilientContainmentEngine()
        act = stage(engine)
        rb = engine.rollback_containment(act["action_id"], actor="analyst_a")
        self.assertEqual(rb["status"], "ERROR")
        self.assertIn("Reject it instead", rb["message"])
        self.assertEqual(act["status"], "PENDING_ANALYST_APPROVAL")


class TestPreActionState(unittest.TestCase):

    def _lock(self, engine, user="CORP\\j.doe"):
        return engine.execute_containment(
            action_type="ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES", target_host="WIN-WORKSTATION09",
            target_ip="10.0.0.45", target_user=user, pid=None, process_name=None)

    def test_pre_action_state_is_captured(self):
        engine = ResilientContainmentEngine()
        act = self._lock(engine)
        self.assertEqual(act["pre_action_state"]["user_disabled"], False)
        self.assertIn("captured_at", act["pre_action_state"])

    def test_rollback_keeps_state_that_existed_before(self):
        engine = ResilientContainmentEngine()
        engine.disabled_users.add("CORP\\j.doe")  # disabled by HR before the incident
        act = self._lock(engine)
        rb = engine.rollback_containment(act["action_id"], actor="analyst_a")
        self.assertIn("kept", rb["restored_state"]["user_disabled"])
        self.assertIn("CORP\\j.doe", engine.disabled_users)

    def test_rollback_does_not_release_effect_held_by_another_action(self):
        engine = ResilientContainmentEngine()
        first = engine.execute_containment(
            action_type="ISOLATE_HOST_AND_KILL_PROCESS", target_host="WKS-22", target_ip="10.0.0.80",
            target_user="CORP\\j.doe", pid=1, process_name="a.exe")
        second = engine.execute_containment(
            action_type="REVERT_DEFENDER_POLICY_AND_ISOLATE", target_host="WKS-22", target_ip="10.0.0.80",
            target_user="CORP\\j.doe", pid=2, process_name="b.exe")
        engine.rollback_containment(first["action_id"], actor="analyst_a")
        self.assertIn("WKS-22", engine.host_isolation_registry)   # second still holds it
        engine.rollback_containment(second["action_id"], actor="analyst_a")
        self.assertNotIn("WKS-22", engine.host_isolation_registry)


class TestGracefulTermination(unittest.TestCase):

    def test_plan_is_graceful_first_single_pid(self):
        from soar.process_termination import termination_plan
        plan = termination_plan(4812, "tool.exe")
        actions = [s["action"] for s in plan["steps"]]
        self.assertEqual(actions, ["snapshot_process", "request_exit", "wait", "force_terminate_if_running"])
        self.assertEqual(plan["steps"][1]["argv"], ["taskkill.exe", "/PID", "4812"])
        for step in plan["steps"]:
            self.assertNotIn("/T", step.get("argv", []))
        self.assertIn("unsaved data", plan["data_loss_risk"])

    def test_system_pids_refused(self):
        from soar.process_termination import termination_plan
        with self.assertRaises(ValueError):
            termination_plan(4, "System")

    def test_ransomware_is_force_killed_with_reason(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS", target_host="WIN-WORKSTATION09",
            target_ip="10.0.0.45", target_user="CORP\\j.doe", pid=6104, process_name="locker.exe")
        plan = act["termination_plan"]
        self.assertEqual(plan["grace_seconds"], 0)
        self.assertEqual(plan["steps"][-1]["action"], "force_terminate")

    def test_isolation_records_graceful_plan(self):
        engine = ResilientContainmentEngine()
        act = stage(engine)
        engine.approve_action(act["action_id"], approver="analyst_a")
        self.assertEqual(act["termination_plan"]["grace_seconds"], 15)


class TestEvidenceBeforeKill(unittest.TestCase):

    def test_snapshot_taken_before_termination(self):
        engine = ResilientContainmentEngine()
        act = stage(engine)
        engine.approve_action(act["action_id"], approver="analyst_a")
        snap = act["pre_containment_snapshot"]
        self.assertEqual(snap["process"]["pid"], 4812)
        self.assertEqual(snap["memory_acquisition"]["status"], "SIMULATED")
        self.assertTrue(snap["memory_acquisition"]["order"][0].startswith("1. process memory dump"))
        self.assertEqual(act["termination_plan"]["steps"][0]["action"], "snapshot_process")

    def test_ip_block_needs_no_process_snapshot(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="BLOCK_SOURCE_IP_FIREWALL", target_host="CORP-RDP-GW01", target_ip="203.0.113.7",
            target_user="admin", pid=None, process_name=None)
        self.assertNotIn("pre_containment_snapshot", act)

    def test_pipeline_collects_evidence_before_containment(self):
        from datetime import datetime
        orch = SOAROrchestrator(policy_mode="AUTOMATIC")
        from simulator.attack_simulator import simulate_t1110_brute_force
        inc = orch.process_event(simulate_t1110_brute_force())
        collected = datetime.fromisoformat(inc["evidence_package"]["collection_metadata"]["timestamp"])
        acted = datetime.fromisoformat(inc["containment_action"]["timestamp"])
        self.assertLessEqual(collected, acted)


class TestScheduledTaskExport(unittest.TestCase):

    def test_task_is_exported_then_disabled_not_deleted(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="REMOVE_SCHEDULED_TASK", target_host="WIN-WORKSTATION09", target_ip="10.0.2.15",
            target_user="CORP\\j.doe", pid=None, process_name=None,
            context={"task_name": "\\Microsoft\\Windows\\SystemHealthUpdate", "task_xml": "<Task>x</Task>"})
        export = act["task_export"]
        self.assertEqual(export["export_argv"][:2], ["schtasks.exe", "/Query"])
        self.assertEqual(len(export["sha256"]), 64)
        self.assertIn("disabled", act["execution_log"])
        self.assertIn("Not deleted", act["execution_log"])
        rb = engine.rollback_containment(act["action_id"], actor="analyst_a")
        self.assertEqual(rb["reversibility"], "FULL")

    def test_task_without_name_is_left_alone(self):
        engine = ResilientContainmentEngine()
        act = engine.execute_containment(
            action_type="REMOVE_SCHEDULED_TASK", target_host="WIN-WORKSTATION09", target_ip="10.0.2.15",
            target_user="CORP\\j.doe", pid=None, process_name=None)
        self.assertEqual(act["status"], "FLAGGED_FOR_MANUAL_REVIEW")
        self.assertNotIn("task_export", act)

    def test_pipeline_passes_task_details(self):
        from simulator.attack_simulator import simulate_t1053_scheduled_task
        orch = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        inc = orch.process_event(simulate_t1053_scheduled_task())
        context = inc["containment_action"]["context"]
        self.assertEqual(context["task_name"], "\Microsoft\Windows\SystemHealthUpdate")
        self.assertIn("<Exec>", context["task_xml"])


class TestLabModeGate(unittest.TestCase):

    def test_simulator_refuses_without_lab_flag(self):
        from simulator.lab_guard import LabModeRequired
        previous = os.environ.pop("CYBERPULSE_LAB_MODE", None)
        try:
            with self.assertRaises(LabModeRequired):
                simulate_t1003_lsass_dump()
        finally:
            if previous is not None:
                os.environ["CYBERPULSE_LAB_MODE"] = previous

    def test_simulator_runs_with_lab_flag(self):
        self.assertEqual(simulate_t1003_lsass_dump()["event_id"], 10)


class TestLabTargetAllowlist(unittest.TestCase):

    def test_all_generators_target_the_lab(self):
        from simulator.attack_simulator import SCRIPTED_GENERATORS
        for _name, gen in SCRIPTED_GENERATORS:
            gen()  # raises TargetNotAllowed if a generator drifts outside the lab

    def test_out_of_lab_targets_refused(self):
        from simulator.lab_guard import TargetNotAllowed, validate_target
        with self.assertRaises(TargetNotAllowed):
            validate_target({"computer_name": "unknown-host", "event_source": "Security"})
        with self.assertRaises(TargetNotAllowed):
            validate_target({"computer_name": "x", "target_ip": "192.168.50.5", "event_source": "Security"})
        with self.assertRaises(TargetNotAllowed):
            validate_target({"computer_name": "aws-prod-account-1", "event_source": "aws:cloudtrail"})
        self.assertTrue(validate_target({"computer_name": "x", "target_ip": "10.0.3.3", "event_source": "Security"}))


if __name__ == "__main__":
    unittest.main()
