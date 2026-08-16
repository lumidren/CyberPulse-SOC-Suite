"""
SOAR Engine & Detection Orchestrator for SOC SIEM/SOAR Lab
Receives telemetry, evaluates detection logic, enriches with Threat Intelligence, and triggers automated remediation actions.
"""

import json
import random
import time
from datetime import datetime, timezone

# Mock Threat Intelligence Database for Lab/Offline Mode
MOCK_THREAT_INTEL = {
    "185.220.101.5": {
        "reputation": "MALICIOUS",
        "abuse_score": 98,
        "country": "DE",
        "isp": "TOR Exit Node / Hostinger",
        "category": "SSH/RDP Brute Force, Malicious Scanner",
        "virustotal_positives": 42
    },
    "185.220.101.33": {
        "reputation": "MALICIOUS",
        "abuse_score": 95,
        "country": "RU",
        "isp": "BadHost Ltd",
        "category": "C2 Server, Credential Harvester",
        "virustotal_positives": 38
    },
    "45.142.214.12": {
        "reputation": "SUSPICIOUS",
        "abuse_score": 76,
        "country": "NL",
        "isp": "Datacenter VPN",
        "category": "Port Scanning",
        "virustotal_positives": 14
    },
    "SHA256=F058F9A5D60E36E4E2C79E89DCE9A32158814F23D6980D4181F54B00D499E0C1": {
        "reputation": "MALICIOUS",
        "threat_name": "PowerShell.Empire.Stager",
        "virustotal_positives": 54,
        "signature": "Trojan.Generic.Heuristic"
    }
}

class SOAROrchestrator:
    def __init__(self):
        self.alert_history = []
        self.containment_actions = []

    def evaluate_detection(self, event):
        """Match event telemetry against detection signature base"""
        event_id = event.get("event_id")
        details = event.get("details", {})
        technique = event.get("technique_id")

        matched_rule = None

        if event_id == 10 and details.get("TargetImage", "").endswith("lsass.exe"):
            matched_rule = {
                "rule_id": "SOC-RULE-001",
                "rule_name": "Possible LSASS Memory Dumping via Sysmon Event 10",
                "severity": "CRITICAL",
                "mitre_id": "T1003.001",
                "action_recommended": "ISOLATE_HOST_AND_KILL_PROCESS"
            }

        elif event_id == 4625 and details.get("FailedAttemptsCount", 0) >= 10:
            matched_rule = {
                "rule_id": "SOC-RULE-002",
                "rule_name": "High Volume Brute Force Authentication Spike",
                "severity": "HIGH",
                "mitre_id": "T1110.001",
                "action_recommended": "BLOCK_SOURCE_IP_FIREWALL"
            }

        elif event_id == 4698 and ("powershell" in details.get("TaskContent", "").lower() or "http" in details.get("TaskContent", "").lower()):
            matched_rule = {
                "rule_id": "SOC-RULE-003",
                "rule_name": "Suspicious Scheduled Task Creation for Persistence",
                "severity": "HIGH",
                "mitre_id": "T1053.005",
                "action_recommended": "REMOVE_SCHEDULED_TASK"
            }

        elif event_id == 1 and ("-encodedcommand" in details.get("CommandLine", "").lower() or "-nop" in details.get("CommandLine", "").lower()):
            matched_rule = {
                "rule_id": "SOC-RULE-004",
                "rule_name": "Obfuscated PowerShell Execution Detected",
                "severity": "HIGH",
                "mitre_id": "T1059.001",
                "action_recommended": "TERMINATE_PROCESS_TREE"
            }

        return matched_rule

    def enrich_threat_intel(self, event):
        """Perform automated Threat Intelligence enrichment (VirusTotal / AbuseIPDB)"""
        source_ip = event.get("source_ip")
        details = event.get("details", {})
        hash_val = details.get("Hashes") or details.get("FileHash_SHA256")

        intel = {
            "ip_reputation": MOCK_THREAT_INTEL.get(source_ip, {
                "reputation": "BENIGN / UNKNOWN",
                "abuse_score": 0,
                "country": "LOCAL / PRIVATE",
                "isp": "Internal Network",
                "category": "Clean Internal Traffic",
                "virustotal_positives": 0
            }),
            "hash_reputation": MOCK_THREAT_INTEL.get(hash_val, {
                "reputation": "UNKNOWN",
                "virustotal_positives": 0
            })
        }
        return intel

    def trigger_automated_containment(self, event, matched_rule, intel):
        """Execute automated SOAR remediation action based on playbook policies"""
        action_type = matched_rule["action_recommended"]
        target_ip = event.get("source_ip")
        target_user = event.get("user")
        target_host = event.get("computer_name")
        process_name = event.get("details", {}).get("SourceImage") or event.get("details", {}).get("Image")

        action_result = {
            "action_id": f"ACT-{random.randint(10000, 99999)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_host": target_host,
            "action_type": action_type,
            "status": "SUCCESS",
            "execution_log": ""
        }

        if action_type == "BLOCK_SOURCE_IP_FIREWALL":
            action_result["execution_log"] = f"Pushed automated firewall rule: BLOCK INBOUND TCP/UDP from {target_ip} on Perimeter Gateway."
        elif action_type == "ISOLATE_HOST_AND_KILL_PROCESS":
            action_result["execution_log"] = f"Isolated host {target_host} via EDR API. Terminated malicious process PID {event.get('details', {}).get('SourceProcessId')} ({process_name})."
        elif action_type == "REMOVE_SCHEDULED_TASK":
            task_name = event.get("details", {}).get("TaskName", "UnknownTask")
            action_result["execution_log"] = f"Purged malicious scheduled task {task_name} on {target_host} via PowerShell Remoting."
        elif action_type == "TERMINATE_PROCESS_TREE":
            action_result["execution_log"] = f"Terminated process tree for powershell.exe on {target_host}. Revoked user session for {target_user}."
        else:
            action_result["execution_log"] = "Flagged for manual SOC Tier-2 Analyst investigation."

        self.containment_actions.append(action_result)
        return action_result

    def process_event(self, event):
        """Full SOAR Pipeline Execution"""
        matched_rule = self.evaluate_detection(event)
        if not matched_rule:
            return None

        intel = self.enrich_threat_intel(event)
        containment = self.trigger_automated_containment(event, matched_rule, intel)

        alert = {
            "alert_id": f"ALT-{random.randint(1000, 9999)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": matched_rule,
            "telemetry": event,
            "threat_intel": intel,
            "soar_response": containment,
            "status": "CLOSED - AUTOMATICALLY CONTAINED"
        }

        self.alert_history.append(alert)
        return alert

if __name__ == "__main__":
    from simulator.attack_simulator import generate_random_attack
    orchestrator = SOAROrchestrator()
    sample_evt = generate_random_attack()
    res = orchestrator.process_event(sample_evt)
    print(json.dumps(res, indent=2))
