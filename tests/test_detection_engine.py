"""
Detection-as-Code (DaC) Automated Test Suite for CyberPulse SOC Suite
Validates Sigma rule syntax, MITRE ATT&CK schema mappings, and end-to-end SOAR orchestration.
"""

import os
import sys
import unittest

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.attack_simulator import (
    simulate_t1003_lsass_dump,
    simulate_t1110_brute_force,
    simulate_t1053_scheduled_task,
    simulate_t1059_powershell_execution,
    simulate_t1562_defender_tamper,
    simulate_t1486_ransomware_canary,
    generate_random_attack
)
from soar.soar_engine import SOAROrchestrator

class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.orchestrator = SOAROrchestrator()

    def test_t1003_lsass_detection(self):
        """Verify T1003.001 LSASS Memory Dump triggers SOC-RULE-001 and host isolation"""
        event = simulate_t1003_lsass_dump()
        self.assertEqual(event["event_id"], 10)
        self.assertEqual(event["technique_id"], "T1003.001")
        
        alert = self.orchestrator.process_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule"]["rule_id"], "SOC-RULE-001")
        self.assertEqual(alert["rule"]["severity"], "CRITICAL")
        self.assertEqual(alert["soar_response"]["action_type"], "ISOLATE_HOST_AND_KILL_PROCESS")
        self.assertIn("total_pipeline_latency_ms", alert["pipeline_timing"])
        self.assertLess(alert["pipeline_timing"]["total_pipeline_sec"], 6.0)

    def test_t1110_brute_force_detection(self):
        """Verify T1110.001 RDP Brute Force triggers SOC-RULE-002 and firewall drop"""
        event = simulate_t1110_brute_force()
        self.assertEqual(event["event_id"], 4625)
        self.assertEqual(event["technique_id"], "T1110.001")
        
        alert = self.orchestrator.process_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule"]["rule_id"], "SOC-RULE-002")
        self.assertEqual(alert["soar_response"]["action_type"], "BLOCK_SOURCE_IP_FIREWALL")
        self.assertIn("pfSense", alert["soar_response"]["execution_protocol"])

    def test_t1053_scheduled_task_detection(self):
        """Verify T1053.005 Scheduled Task persistence triggers SOC-RULE-003 and task purge"""
        event = simulate_t1053_scheduled_task()
        self.assertEqual(event["event_id"], 4698)
        self.assertEqual(event["technique_id"], "T1053.005")
        
        alert = self.orchestrator.process_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule"]["rule_id"], "SOC-RULE-003")
        self.assertEqual(alert["soar_response"]["action_type"], "REMOVE_SCHEDULED_TASK")

    def test_t1059_powershell_detection(self):
        """Verify T1059.001 Obfuscated PowerShell triggers SOC-RULE-004 and process tree termination"""
        event = simulate_t1059_powershell_execution()
        self.assertEqual(event["event_id"], 1)
        self.assertEqual(event["technique_id"], "T1059.001")
        
        alert = self.orchestrator.process_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule"]["rule_id"], "SOC-RULE-004")
        self.assertEqual(alert["soar_response"]["action_type"], "TERMINATE_PROCESS_TREE")

    def test_t1562_defender_tamper_detection(self):
        """Verify T1562.001 Defender tampering triggers SOC-RULE-005 and policy reversion"""
        event = simulate_t1562_defender_tamper()
        self.assertEqual(event["technique_id"], "T1562.001")
        
        alert = self.orchestrator.process_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule"]["rule_id"], "SOC-RULE-005")
        self.assertEqual(alert["soar_response"]["action_type"], "REVERT_DEFENDER_POLICY_AND_ISOLATE")

    def test_t1486_ransomware_canary_detection(self):
        """Verify T1486 Ransomware canary encryption triggers SOC-RULE-006 and VSS recovery"""
        event = simulate_t1486_ransomware_canary()
        self.assertEqual(event["technique_id"], "T1486")
        
        alert = self.orchestrator.process_event(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert["rule"]["rule_id"], "SOC-RULE-006")
        self.assertEqual(alert["soar_response"]["action_type"], "KILL_RANSOMWARE_PROCESS_AND_RESTORE_VSS")

    def test_threat_intel_and_geoip_enrichment(self):
        """Verify Threat Intel & GeoIP module enriches IP with reputation and coordinates"""
        event = simulate_t1110_brute_force()
        event["source_ip"] = "185.220.101.5"
        
        alert = self.orchestrator.process_event(event)
        self.assertIsNotNone(alert)
        intel = alert["threat_intel"]["ip_reputation"]
        self.assertEqual(intel["reputation"], "MALICIOUS")
        self.assertGreaterEqual(intel["abuse_score"], 90)
        self.assertIn("lat", intel)
        self.assertIn("lon", intel)
        self.assertEqual(intel["country"], "Germany")

    def test_sigma_rules_exist_and_valid(self):
        """Verify all 5 Sigma YAML rules are present and have required schema fields"""
        sigma_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "sigma")
        self.assertTrue(os.path.isdir(sigma_dir))
        
        files = [f for f in os.listdir(sigma_dir) if f.endswith(".yml")]
        self.assertGreaterEqual(len(files), 5)
        
        required_keys = ["title", "id", "status", "description", "logsource", "detection", "level", "tags"]
        for f in files:
            filepath = os.path.join(sigma_dir, f)
            with open(filepath, "r", encoding="utf-8") as file:
                content = file.read()
                for key in required_keys:
                    self.assertIn(f"{key}:", content, f"Sigma rule {f} missing required key '{key}'")

if __name__ == "__main__":
    unittest.main()
