"""
End-to-End Multi-Stage Adversary Attack Chain Simulator for CyberPulse SOC Suite
Executes a chronological 5-stage kill chain to validate end-to-end detection coverage and SOAR containment.
"""

import json
import time
from datetime import datetime, timezone

# Add project root to sys.path
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.attack_simulator import (
    simulate_t1059_powershell_execution,
    simulate_t1562_defender_tamper,
    simulate_t1003_lsass_dump,
    simulate_t1053_scheduled_task,
    simulate_t1486_ransomware_canary
)
from soar.soar_engine import SOAROrchestrator

KILL_CHAIN_STAGES = [
    {
        "phase": "1. Initial Foothold & Staging",
        "tactic": "Execution",
        "technique": "T1059.001",
        "generator": simulate_t1059_powershell_execution
    },
    {
        "phase": "2. Impairing Host Defenses",
        "tactic": "Defense Evasion",
        "technique": "T1562.001",
        "generator": simulate_t1562_defender_tamper
    },
    {
        "phase": "3. Credential Harvesting",
        "tactic": "Credential Access",
        "technique": "T1003.001",
        "generator": simulate_t1003_lsass_dump
    },
    {
        "phase": "4. Establishing Persistence",
        "tactic": "Persistence",
        "technique": "T1053.005",
        "generator": simulate_t1053_scheduled_task
    },
    {
        "phase": "5. Impact & Ransomware Canary Trigger",
        "tactic": "Impact",
        "technique": "T1486",
        "generator": simulate_t1486_ransomware_canary
    }
]

def run_adversary_kill_chain(delay_between_phases=1.5, webhook_url=None):
    """Executes the complete chronological kill chain and captures timeline telemetry"""
    orchestrator = SOAROrchestrator(webhook_url=webhook_url)
    results = []

    print("\n" + "="*80)
    print(" ⚔️  EXECUTING END-TO-END ADVERSARY EMULATION KILL CHAIN (5 PHASES)")
    print("="*80)

    for stage in KILL_CHAIN_STAGES:
        print(f"\n[*] [STAGE: {stage['phase']}] - {stage['tactic']} ({stage['technique']})")
        event = stage["generator"]()
        
        t_start = time.perf_counter()
        alert = orchestrator.process_event(event, custom_webhook_url=webhook_url)
        elapsed = time.perf_counter() - t_start

        if alert:
            timing = alert["pipeline_timing"]
            soar = alert["soar_response"]
            print(f"    \033[92m[✓] Detection Fired:\033[0m {alert['rule']['rule_name']}")
            print(f"    \033[96m[⚡] Total Latency:\033[0m {timing['total_pipeline_sec']}s (Detection: {timing['stage1_detection_ms']}ms | Containment: {timing['stage3_containment_ms']}ms)")
            print(f"    \033[93m[🛡️] Containment:\033[0m {soar['action_type']} -> {soar['execution_log']}")
            
            results.append({
                "stage": stage["phase"],
                "technique_id": stage["technique"],
                "status": "DETECTED_AND_AUTO_CONTAINED",
                "rule_id": alert["rule"]["rule_id"],
                "latency_sec": timing["total_pipeline_sec"]
            })
        else:
            print(f"    \033[91m[✗] BLINDSPOT: No detection rule matched for {stage['technique']}\033[0m")
            results.append({
                "stage": stage["phase"],
                "technique_id": stage["technique"],
                "status": "UNDETECTED_GAP"
            })

        time.sleep(delay_between_phases)

    print("\n" + "="*80)
    print(" 📊 KILL CHAIN EXECUTION SUMMARY:")
    print("="*80)
    for r in results:
        print(f"  • {r['stage']} [{r['technique_id']}]: {r['status']} ({r.get('latency_sec', 0)}s)")
    print("="*80 + "\n")

    return results

if __name__ == "__main__":
    run_adversary_kill_chain(delay_between_phases=1)
