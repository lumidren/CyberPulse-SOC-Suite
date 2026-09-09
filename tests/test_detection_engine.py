"""
Unit & Integration Test Suite for CyberPulse Enterprise SOC Platform
Tests Detection Engine, Multi-Factor Risk Scoring, Policy Evaluation,
Resilient Containment, Circuit Breakers, Rollback, DFIR, and Purple Team Replay.
"""

import unittest
import os
import sys
import json
import time

# Ensure project root in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.attack_simulator import (
    simulate_t1003_lsass_dump,
    simulate_t1110_brute_force,
    simulate_t1053_scheduled_task,
    simulate_t1059_powershell_execution,
    simulate_t1562_defender_tamper,
    simulate_t1486_ransomware_canary,
    simulate_t1558_kerberoasting,
    simulate_t1003_dcsync
)
from soar.soar_engine import SOAROrchestrator
from soar.risk_engine import RiskAndPolicyEngine
from soar.resilient_containment import ResilientContainmentEngine, CircuitBreaker
from soar.metrics_engine import SOCMetricsEngine
from simulator.purple_team_runner import PurpleTeamRunner
from soar.attack_graph import AttackGraphEngine
from soar.evidence_collector import VolatileEvidenceCollector
from soar.ai_copilot import SOCCopilot
from soar.syslog_receiver import SyslogReceiver, WebhookIngestionHandler
from soar.identity_graph import IdentityBlastRadiusEngine

class TestEnterpriseSOCPlatform(unittest.TestCase):

    def setUp(self):
        self.orchestrator = SOAROrchestrator(policy_mode="AUTOMATIC")

    def test_sigma_rules_exist_and_valid(self):
        """Verify all 7 core Sigma YAML rules exist with required schema tags"""
        sigma_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "sigma")
        expected_rules = [
            "win_lsass_dumping.yml",
            "win_brute_force_auth.yml",
            "win_scheduled_task_persistence.yml",
            "win_defender_tamper.yml",
            "win_ransomware_canary.yml",
            "win_kerberoasting.yml",
            "win_dcsync.yml"
        ]
        for rule_file in expected_rules:
            rule_path = os.path.join(sigma_dir, rule_file)
            self.assertTrue(os.path.exists(rule_path), f"Missing Sigma rule file: {rule_file}")
            with open(rule_path, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("title:", content)
                self.assertIn("detection:", content)
                self.assertIn("tags:", content)

    def test_t1003_lsass_closed_loop(self):
        """Verify T1003.001 LSASS Memory Dump executes closed loop with Host Isolation"""
        event = simulate_t1003_lsass_dump()
        incident = self.orchestrator.process_event(event)
        
        self.assertIsNotNone(incident)
        self.assertEqual(incident["rule"]["rule_id"], "SOC-RULE-001")
        self.assertEqual(incident["risk_assessment"]["risk_level"], "CRITICAL")
        self.assertGreaterEqual(incident["risk_assessment"]["final_score"], 80.0)
        self.assertEqual(incident["containment_action"]["action_type"], "ISOLATE_HOST_AND_KILL_PROCESS")
        self.assertEqual(incident["containment_action"]["status"], "SUCCESS")
        self.assertIn("CYBERPULSE-SOC", incident["thehive_case"]["title"])
        self.assertGreaterEqual(len(incident["timeline"]), 5)

    def test_t1110_brute_force_firewall_drop(self):
        """Verify T1110.001 RDP Brute Force triggers pfSense firewall drop"""
        event = simulate_t1110_brute_force()
        incident = self.orchestrator.process_event(event)
        
        self.assertIsNotNone(incident)
        self.assertEqual(incident["rule"]["rule_id"], "SOC-RULE-002")
        self.assertEqual(incident["containment_action"]["action_type"], "BLOCK_SOURCE_IP_FIREWALL")
        self.assertIn("pfSense", incident["containment_action"]["execution_protocol"])

    def test_t1562_defender_tampering(self):
        """Verify T1562.001 Defender tampering triggers policy reversion and isolation"""
        event = simulate_t1562_defender_tamper()
        incident = self.orchestrator.process_event(event)
        
        self.assertIsNotNone(incident)
        self.assertEqual(incident["rule"]["rule_id"], "SOC-RULE-005")
        self.assertEqual(incident["containment_action"]["action_type"], "REVERT_DEFENDER_POLICY_AND_ISOLATE")

    def test_t1486_ransomware_vss_recovery(self):
        """Verify T1486 Ransomware canary encryption triggers VSS recovery"""
        event = simulate_t1486_ransomware_canary()
        incident = self.orchestrator.process_event(event)
        
        self.assertIsNotNone(incident)
        self.assertEqual(incident["rule"]["rule_id"], "SOC-RULE-006")
        self.assertEqual(incident["containment_action"]["action_type"], "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS")

    def test_t1558_kerberoasting_detection(self):
        """Verify T1558.001 Kerberoasting TGS request triggers SOC-RULE-007 and account reset"""
        event = simulate_t1558_kerberoasting()
        incident = self.orchestrator.process_event(event)
        
        self.assertIsNotNone(incident)
        self.assertEqual(incident["rule"]["rule_id"], "SOC-RULE-007")
        self.assertEqual(incident["containment_action"]["action_type"], "RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET")

    def test_t1003_dcsync_detection(self):
        """Verify T1003.006 DCSync replication abuse triggers SOC-RULE-008 and privilege revocation"""
        event = simulate_t1003_dcsync()
        incident = self.orchestrator.process_event(event)
        
        self.assertIsNotNone(incident)
        self.assertEqual(incident["rule"]["rule_id"], "SOC-RULE-008")
        self.assertEqual(incident["containment_action"]["action_type"], "ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES")

    def test_multi_factor_risk_scoring_accuracy(self):
        """Verify risk engine properly factors asset criticality and user privilege"""
        risk_engine = RiskAndPolicyEngine()
        
        # High-value Domain Controller
        dc_event = {"computer_name": "WIN-DC01.corp.local", "user": "CORP\\Administrator", "tactic": "Credential Access"}
        rule = {"severity": "CRITICAL", "action_recommended": "ISOLATE_HOST_AND_KILL_PROCESS"}
        intel = {"ip_reputation": {"virustotal_positives": 42, "abuse_score": 95}}
        dc_risk = risk_engine.calculate_risk_score(dc_event, rule, intel)
        
        # Standard Low-Value Workstation
        ws_event = {"computer_name": "WIN-WORKSTATION09", "user": "CORP\\j.doe", "tactic": "Execution"}
        rule_low = {"severity": "HIGH", "action_recommended": "TERMINATE_PROCESS_TREE"}
        intel_clean = {"ip_reputation": {"virustotal_positives": 0, "abuse_score": 0}}
        ws_risk = risk_engine.calculate_risk_score(ws_event, rule_low, intel_clean)

        self.assertGreater(dc_risk["final_score"], ws_risk["final_score"])
        self.assertEqual(dc_risk["risk_level"], "CRITICAL")

    def test_containment_rollback_mechanism(self):
        """Verify automated containment action can be cleanly rolled back"""
        containment = ResilientContainmentEngine()
        act = containment.execute_containment(
            action_type="ISOLATE_HOST_AND_KILL_PROCESS",
            target_host="WIN-DC01.corp.local",
            target_ip="185.220.101.33",
            target_user="CORP\\Administrator",
            pid=4812,
            process_name="mimikatz.exe"
        )
        self.assertEqual(act["status"], "SUCCESS")
        self.assertIn("WIN-DC01.corp.local", containment.host_isolation_registry)

        # Execute Rollback
        rb = containment.rollback_containment(act["action_id"], actor="analyst_test")
        self.assertEqual(rb["status"], "SUCCESS")
        self.assertNotIn("WIN-DC01.corp.local", containment.host_isolation_registry)

    def test_dry_run_policy_mode(self):
        """Verify DRY_RUN mode simulates containment without host disruption"""
        orch_dry = SOAROrchestrator(policy_mode="DRY_RUN")
        event = simulate_t1003_lsass_dump()
        incident = orch_dry.process_event(event)
        
        self.assertEqual(incident["policy_decision"]["execution_intent"], "DRY_RUN_SIMULATION")
        self.assertEqual(incident["containment_action"]["status"], "SIMULATED_NO_DISRUPTION")

    def test_circuit_breaker_tripping_and_recovery(self):
        """Verify circuit breaker trips to OPEN upon consecutive external failures"""
        cb = CircuitBreaker(failure_threshold=2, recovery_time_sec=1)
        self.assertTrue(cb.is_available())
        cb.record_failure()
        self.assertTrue(cb.is_available())
        cb.record_failure()
        self.assertFalse(cb.is_available()) # Tripped to OPEN
        self.assertEqual(cb.state, "OPEN")
        time.sleep(1.1)
        self.assertTrue(cb.is_available()) # Half-open recovery

    def test_purple_team_runner_apt29(self):
        """Verify Purple Team Runner executes multi-stage APT29 scenario with 100% pass"""
        runner = PurpleTeamRunner(self.orchestrator)
        summary = runner.run_scenario("APT29_COZY_BEAR")
        
        self.assertEqual(summary["overall_status"], "VALIDATED_100%")
        self.assertEqual(summary["total_stages"], 3)
        self.assertEqual(summary["passed_stages"], 3)

    def test_soc_metrics_percentiles(self):
        """Verify SOC Metrics Engine computes MTTD, MTTC, and p95 latencies"""
        metrics_engine = SOCMetricsEngine()
        metrics = metrics_engine.get_soc_metrics()
        
        self.assertIn("operational_kpis", metrics)
        self.assertIn("latency_percentiles_sec", metrics)
        self.assertGreater(metrics["operational_kpis"]["mttd_sec"], 0)
        self.assertGreater(metrics["operational_kpis"]["mttc_sec"], 0)
        self.assertGreaterEqual(metrics["latency_percentiles_sec"]["p95"], metrics["latency_percentiles_sec"]["p50"])

    def test_attack_graph_generation(self):
        """Verify attack graph generates valid nodes and edges from incident data"""
        event = simulate_t1003_lsass_dump()
        incident = self.orchestrator.process_event(event)

        self.assertIn("attack_graph", incident)
        graph = incident["attack_graph"]
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)
        self.assertGreaterEqual(len(graph["nodes"]), 4)
        self.assertGreaterEqual(len(graph["edges"]), 3)
        node_types = [n.get("type") for n in graph["nodes"]]
        self.assertIn("attacker", node_types)
        self.assertIn("host", node_types)

    def test_evidence_collector_volatile_triage(self):
        """Verify volatile evidence collector produces valid forensic artifact packages"""
        event = simulate_t1003_lsass_dump()
        incident = self.orchestrator.process_event(event)

        self.assertIn("evidence_package", incident)
        evidence = incident["evidence_package"]
        self.assertIn("network_connections", evidence)
        self.assertIn("loaded_dlls", evidence)
        self.assertIn("prefetch_entries", evidence)
        self.assertIn("autoruns_persistence", evidence)
        self.assertIn("memory_strings", evidence)
        self.assertIn("collection_metadata", evidence)
        self.assertGreaterEqual(len(evidence["network_connections"]), 3)
        self.assertGreaterEqual(len(evidence["loaded_dlls"]), 3)

    def test_ai_copilot_incident_analysis(self):
        """Verify AI SOC Copilot produces complete analysis reports from incident data"""
        event = simulate_t1003_lsass_dump()
        incident = self.orchestrator.process_event(event)

        self.assertIn("ai_analysis", incident)
        analysis = incident["ai_analysis"]
        self.assertIn("executive_summary", analysis)
        self.assertIn("root_cause_analysis", analysis)
        self.assertIn("remediation_guidance", analysis)
        self.assertIn("risk_verdict", analysis)
        self.assertIn("mitre_context", analysis)
        self.assertIsInstance(analysis["executive_summary"], str)
        self.assertGreater(len(analysis["executive_summary"]), 50)
        self.assertIsInstance(analysis["remediation_guidance"], list)
        self.assertGreaterEqual(len(analysis["remediation_guidance"]), 3)
        self.assertIn(analysis["risk_verdict"]["verdict"], ["TRUE_POSITIVE", "FALSE_POSITIVE", "REQUIRES_INVESTIGATION"])

    def test_syslog_webhook_ingestion_handler(self):
        """Verify webhook ingestion handler normalizes valid events and rejects invalid ones"""
        handler = WebhookIngestionHandler()

        valid_event = {
            "event_id": 10,
            "computer_name": "WIN-DC01.corp.local",
            "source_ip": "185.220.101.33",
            "user": "CORP\\Administrator",
            "details": {
                "SourceImage": "C:\\Windows\\Temp\\mimikatz.exe",
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010"
            }
        }
        result = handler.handle_ingest(valid_event)
        self.assertEqual(result["status"], "SUCCESS")
        self.assertIn("normalized_event", result)

        invalid_event = {"random_field": "no_event_id"}
        result_bad = handler.handle_ingest(invalid_event)
        self.assertNotEqual(result_bad.get("status"), "SUCCESS")

    def test_identity_blast_radius_analysis(self):
        """Verify identity blast radius engine calculates compromise impact for AD users"""
        engine = IdentityBlastRadiusEngine()

        admin_analysis = engine.analyze_compromised_identity("Administrator")
        self.assertIn("compromised_user", admin_analysis)
        self.assertIn("blast_radius_score", admin_analysis)
        self.assertGreaterEqual(admin_analysis["blast_radius_score"], 80)
        self.assertIn("shortest_path_to_domain_admin", admin_analysis)
        self.assertIn("recommended_containment", admin_analysis)

        user_analysis = engine.analyze_compromised_identity("j.doe")
        self.assertLess(user_analysis["blast_radius_score"], admin_analysis["blast_radius_score"])

        delegation_risks = engine.get_kerberos_delegation_risks()
        self.assertIsInstance(delegation_risks, list)

if __name__ == "__main__":
    unittest.main()
