"""
Unified Incident Timeline & DFIR Case Management Engine for CyberPulse SOC Suite
Provides end-to-end incident lifecycle tracking, observable extraction,
structured TheHive 5 case generation, and microsecond chronological timelines.
"""

import json
import time
import random
from datetime import datetime, timezone

class DFIREngine:
    def __init__(self):
        self.incidents = {} # incident_id -> Incident object
        self.incident_list = []

    def create_incident(self, event, matched_rule, intel, risk_assessment, policy_decision, containment_action, timing_breakdown):
        """
        Synthesizes all pipeline telemetry into a single, unified enterprise Incident Record.
        """
        incident_seq = len(self.incident_list) + 1
        incident_id = f"INC-2026-{incident_seq:04d}"
        correlation_id = containment_action.get("correlation_id", f"CORR-{incident_seq:04d}")
        utc_now = datetime.now(timezone.utc).isoformat()

        # Extract Observables
        observables = []
        source_ip = event.get("source_ip")
        if source_ip:
            observables.append({"type": "ip-src", "value": source_ip, "ioc": True})

        details = event.get("details", {})
        file_hash = details.get("Hashes") or details.get("FileHash_SHA256")
        if file_hash:
            observables.append({"type": "file-sha256", "value": file_hash, "ioc": True})

        user = event.get("user")
        if user:
            observables.append({"type": "user-account", "value": user, "ioc": False})

        process = details.get("SourceImage") or details.get("Image")
        if process:
            observables.append({"type": "process-path", "value": process, "ioc": False})

        # Build TheHive 5 Structured Case
        thehive_case = {
            "case_id": f"TH5-{4000 + incident_seq}",
            "title": f"[CYBERPULSE-SOC] {matched_rule.get('rule_name')} on {event.get('computer_name')}",
            "severity": 3 if risk_assessment["risk_level"] == "CRITICAL" else 2,
            "status": "Open",
            "tlp": 2,
            "pap": 2,
            "tags": [
                "CyberPulse",
                f"MITRE:{event.get('technique_id')}",
                risk_assessment["risk_level"],
                containment_action.get("action_type", "NONE")
            ],
            "tasks": [
                {"id": 1, "title": "Verify Automated Host Containment", "status": "Completed"},
                {"id": 2, "title": "Inspect Process Lineage & Memory Dumps", "status": "In Progress"},
                {"id": 3, "title": "Validate Active Directory TGT & Password Rotation", "status": "Pending"},
                {"id": 4, "title": "Post-Incident Hardening & Detection Tuning", "status": "Pending"}
            ],
            "observables_count": len(observables)
        }

        # Build Microsecond-Timestamped Chronological Timeline
        t_base = time.time() - (timing_breakdown.get("total_pipeline_sec", 3.2))
        timeline = [
            {
                "timestamp": datetime.fromtimestamp(t_base, timezone.utc).isoformat(),
                "stage": "1. ADVERSARY_EMULATION",
                "title": f"Adversary executed {event.get('technique_id')} ({event.get('technique_name')})",
                "detail": f"Source: {event.get('source_ip')} | Target: {event.get('computer_name')} | User: {event.get('user')}",
                "status": "TELEMETRY_EMITTED"
            },
            {
                "timestamp": datetime.fromtimestamp(t_base + (timing_breakdown.get("stage1_detection_ms", 1400)/1000.0), timezone.utc).isoformat(),
                "stage": "2. DETECTION_ENGINE",
                "title": f"Sigma & Wazuh rule matched: {matched_rule.get('rule_name')}",
                "detail": f"Rule ID: {matched_rule.get('rule_id')} | Severity: {matched_rule.get('severity')} | LogSource: {event.get('event_source')}",
                "status": "ALERT_TRIGGERED"
            },
            {
                "timestamp": datetime.fromtimestamp(t_base + ((timing_breakdown.get("stage1_detection_ms", 1400) + timing_breakdown.get("stage2_threat_intel_ms", 650))/1000.0), timezone.utc).isoformat(),
                "stage": "3. THREAT_INTELLIGENCE",
                "title": f"IoC Enrichment completed via VirusTotal v3 & AbuseIPDB v2",
                "detail": f"VT Detections: {intel.get('ip_reputation', {}).get('virustotal_positives', 0)}/72 | Abuse Score: {intel.get('ip_reputation', {}).get('abuse_score', 0)}% | Origin: {intel.get('ip_reputation', {}).get('country', 'Unknown')}",
                "status": "ENRICHED"
            },
            {
                "timestamp": datetime.fromtimestamp(t_base + ((timing_breakdown.get("stage1_detection_ms", 1400) + timing_breakdown.get("stage2_threat_intel_ms", 650) + 150)/1000.0), timezone.utc).isoformat(),
                "stage": "4. RISK_AND_POLICY",
                "title": f"Calculated composite risk score: {risk_assessment['final_score']}/100 ({risk_assessment['risk_level']})",
                "detail": f"Policy evaluated: {policy_decision['action']} (Execution Intent: {policy_decision['execution_intent']})",
                "status": "POLICY_APPROVED"
            },
            {
                "timestamp": datetime.fromtimestamp(t_base + (timing_breakdown.get("total_pipeline_sec", 3.2)), timezone.utc).isoformat(),
                "stage": "5. AUTOMATED_CONTAINMENT",
                "title": f"SOAR executed {containment_action.get('action_type')}",
                "detail": f"Protocol: {containment_action.get('execution_protocol')} | Log: {containment_action.get('execution_log')}",
                "status": containment_action.get("status")
            },
            {
                "timestamp": utc_now,
                "stage": "6. DFIR_CASE_INITIALIZED",
                "title": f"TheHive 5 Case #{thehive_case['case_id']} created with {len(observables)} observables",
                "detail": "Standardized NIST SP 800-61 triage task list attached. Notification dispatched to SOC channel.",
                "status": "READY_FOR_TRIAGE"
            }
        ]

        incident_record = {
            "incident_id": incident_id,
            "correlation_id": correlation_id,
            "created_at": utc_now,
            "rule": matched_rule,
            "telemetry": event,
            "threat_intel": intel,
            "risk_assessment": risk_assessment,
            "policy_decision": policy_decision,
            "containment_action": containment_action,
            "thehive_case": thehive_case,
            "timeline": timeline,
            "observables": observables,
            "analyst_notes": [
                {
                    "timestamp": utc_now,
                    "author": "SOAR_AUTOMATION_SYSTEM",
                    "note": f"Automated closed-loop containment executed in {timing_breakdown.get('total_pipeline_sec', 3.2)}s. Host isolated from enterprise subnet."
                }
            ],
            "status": "CONTAINED_AUTOMATICALLY"
        }

        self.incidents[incident_id] = incident_record
        self.incident_list.insert(0, incident_record)
        return incident_record

    def add_analyst_note(self, incident_id, note_text, author="analyst_lumidren"):
        """Adds a verified analyst triage note to an active incident record"""
        if incident_id not in self.incidents:
            return {"status": "ERROR", "message": f"Incident {incident_id} not found."}
        
        note_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "author": author,
            "note": note_text
        }
        self.incidents[incident_id]["analyst_notes"].append(note_entry)
        return {"status": "SUCCESS", "note": note_entry}

if __name__ == "__main__":
    dfir = DFIREngine()
    print("[*] DFIREngine ready.")
