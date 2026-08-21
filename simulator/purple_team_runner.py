"""
Attack Replay & Purple Team Validation Engine for CyberPulse SOC Suite
Executes reproducible adversary campaigns (APT29 Cozy Bear, LockBit Ransomware, Insider Threat)
and produces stage-by-stage verification metrics comparing Red Tradecraft to Blue Defenses.
"""

import time
import json
from datetime import datetime, timezone

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.attack_simulator import (
    simulate_t1059_powershell_execution,
    simulate_t1562_defender_tamper,
    simulate_t1003_lsass_dump,
    simulate_t1110_brute_force,
    simulate_t1053_scheduled_task,
    simulate_t1486_ransomware_canary
)

SCENARIOS = {
    "APT29_COZY_BEAR": {
        "campaign_id": "PT-SCENARIO-APT29",
        "name": "APT29 / Cozy Bear Enterprise Intrusion Campaign",
        "description": "Multi-stage nation-state intrusion simulating initial PowerShell staging, defense impairment, and LSASS credential harvesting.",
        "threat_actor": "APT29 (Nobelium / Cozy Bear)",
        "stages": [
            {
                "sequence": 1,
                "name": "Initial Execution Cradle",
                "tactic": "Execution",
                "technique_id": "T1059.001",
                "expected_sensor": "Sysmon Event ID 1",
                "expected_rule": "SOC-RULE-004",
                "generator": simulate_t1059_powershell_execution
            },
            {
                "sequence": 2,
                "name": "Host Defense Impairment",
                "tactic": "Defense Evasion",
                "technique_id": "T1562.001",
                "expected_sensor": "Sysmon Event ID 1",
                "expected_rule": "SOC-RULE-005",
                "generator": simulate_t1562_defender_tamper
            },
            {
                "sequence": 3,
                "name": "Domain Credential Extraction",
                "tactic": "Credential Access",
                "technique_id": "T1003.001",
                "expected_sensor": "Sysmon Event ID 10",
                "expected_rule": "SOC-RULE-001",
                "generator": simulate_t1003_lsass_dump
            }
        ]
    },
    "LOCKBIT_RANSOMWARE": {
        "campaign_id": "PT-SCENARIO-LOCKBIT",
        "name": "LockBit 3.0 Ransomware Attack Lifecycle",
        "description": "Simulates perimeter password spraying, scheduled persistence creation, and canary file encryption with automated recovery.",
        "threat_actor": "LockBit RaaS Group",
        "stages": [
            {
                "sequence": 1,
                "name": "External Perimeter Brute Force",
                "tactic": "Initial Access / Credential Access",
                "technique_id": "T1110.001",
                "expected_sensor": "Security Event ID 4625",
                "expected_rule": "SOC-RULE-002",
                "generator": simulate_t1110_brute_force
            },
            {
                "sequence": 2,
                "name": "Persistence via Task Hook",
                "tactic": "Persistence",
                "technique_id": "T1053.005",
                "expected_sensor": "Security Event ID 4698",
                "expected_rule": "SOC-RULE-003",
                "generator": simulate_t1053_scheduled_task
            },
            {
                "sequence": 3,
                "name": "Impact - Canary File Encryption",
                "tactic": "Impact",
                "technique_id": "T1486",
                "expected_sensor": "Sysmon Event ID 11",
                "expected_rule": "SOC-RULE-006",
                "generator": simulate_t1486_ransomware_canary
            }
        ]
    }
}

class PurpleTeamRunner:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator

    def run_scenario(self, scenario_key="APT29_COZY_BEAR", custom_webhook_url=None):
        """Executes a defined Purple Team scenario and collects stage verification telemetry"""
        if scenario_key not in SCENARIOS:
            return {"status": "ERROR", "message": f"Unknown scenario: {scenario_key}"}

        scenario = SCENARIOS[scenario_key]
        execution_id = f"PTX-{int(time.time())}"
        start_time = datetime.now(timezone.utc).isoformat()
        stage_results = []
        all_passed = True

        for stage in scenario["stages"]:
            t0 = time.perf_counter()
            event = stage["generator"]()
            alert = self.orchestrator.process_event(event, custom_webhook_url=custom_webhook_url)
            elapsed_sec = round(time.perf_counter() - t0, 3)

            stage_verified = False
            matched_rule_id = alert.get("rule", {}).get("rule_id") if alert else None
            
            if alert and matched_rule_id == stage["expected_rule"]:
                stage_verified = True
            else:
                all_passed = False

            stage_results.append({
                "sequence": stage["sequence"],
                "stage_name": stage["name"],
                "technique_id": stage["technique_id"],
                "tactic": stage["tactic"],
                "expected_sensor": stage["expected_sensor"],
                "expected_rule": stage["expected_rule"],
                "matched_rule": matched_rule_id,
                "status": "PASS" if stage_verified else "FAIL",
                "risk_score": alert.get("risk_assessment", {}).get("final_score", 0) if alert else 0,
                "containment_action": alert.get("containment_action", {}).get("action_type", "NONE") if alert else "NONE",
                "containment_status": alert.get("containment_action", {}).get("status", "FAIL") if alert else "FAIL",
                "latency_sec": alert.get("pipeline_timing", {}).get("total_pipeline_sec", elapsed_sec) if alert else elapsed_sec
            })

        summary = {
            "execution_id": execution_id,
            "scenario_name": scenario["name"],
            "threat_actor": scenario["threat_actor"],
            "started_at": start_time,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": "VALIDATED_100%" if all_passed else "GAPS_DETECTED",
            "total_stages": len(scenario["stages"]),
            "passed_stages": sum(1 for s in stage_results if s["status"] == "PASS"),
            "stage_results": stage_results
        }
        return summary

if __name__ == "__main__":
    from soar.soar_engine import SOAROrchestrator
    orch = SOAROrchestrator()
    runner = PurpleTeamRunner(orch)
    res = runner.run_scenario("APT29_COZY_BEAR")
    print(json.dumps(res, indent=2))
