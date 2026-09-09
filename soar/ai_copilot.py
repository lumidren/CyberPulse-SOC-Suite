import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Knowledge base for dynamic context generation
MITRE_TECHNIQUE_KNOWLEDGE = {
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "description": "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
        "danger_level": "CRITICAL",
        "known_actors": ["APT29", "FIN7", "Sandworm Team", "Wizard Spider"],
        "typical_remediation": [
            "Enable Windows Defender Credential Guard.",
            "Restrict debug privileges (SeDebugPrivilege) to authorized administrators.",
            "Enable LSA Protection (RunAsPPL)."
        ]
    },
    "T1003.006": {
        "name": "OS Credential Dumping: DCSync",
        "description": "Adversaries may attempt to access credentials and other sensitive information by replicating Directory Services data from a Domain Controller.",
        "danger_level": "CRITICAL",
        "known_actors": ["APT29", "Lazarus Group", "Sandworm Team"],
        "typical_remediation": [
            "Restrict 'Replicating Directory Changes' permissions to authorized Domain Controllers.",
            "Monitor for unusual processes performing directory replication operations.",
            "Implement strong Tier 0 access controls."
        ]
    },
    "T1558.001": {
        "name": "Steal or Forge Kerberos Tickets: Golden Ticket",
        "description": "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.",
        "danger_level": "CRITICAL",
        "known_actors": ["APT3", "FIN6", "Lazarus Group"],
        "typical_remediation": [
            "Rotate the KRBTGT account password twice.",
            "Implement continuous monitoring for anomalous Kerberos activity.",
            "Restrict Domain Admin privileges and lateral movement."
        ]
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "description": "Adversaries may use password guessing to attempt to gain access to accounts by systematically trying different passwords.",
        "danger_level": "HIGH",
        "known_actors": ["APT28", "FIN7", "MuddyWater"],
        "typical_remediation": [
            "Enforce strong password policies and MFA.",
            "Implement account lockout policies after a set number of failed attempts.",
            "Monitor authentication logs for repeated failed logins."
        ]
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.",
        "danger_level": "MEDIUM",
        "known_actors": ["APT29", "FIN7", "Turla"],
        "typical_remediation": [
            "Audit scheduled tasks for unauthorized entries.",
            "Restrict access to task scheduling utilities.",
            "Monitor task creation and execution events (Event IDs 4698, 4699, 4700, 4701, 4702)."
        ]
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "danger_level": "HIGH",
        "known_actors": ["APT29", "FIN7", "Wizard Spider", "Lazarus Group"],
        "typical_remediation": [
            "Enable PowerShell Script Block Logging (Event ID 4104).",
            "Use Constrained Language Mode (CLM).",
            "Restrict PowerShell execution policy."
        ]
    },
    "T1562.001": {
        "name": "Impair Defenses: Disable or Modify Tools",
        "description": "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities.",
        "danger_level": "CRITICAL",
        "known_actors": ["FIN7", "Wizard Spider", "Lazarus Group"],
        "typical_remediation": [
            "Ensure security tools are tamper-protected.",
            "Monitor for service stop events or registry modifications targeting security products.",
            "Alert on command-line execution attempting to disable Windows Defender or EDR agents."
        ]
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
        "danger_level": "CRITICAL",
        "known_actors": ["Wizard Spider", "REvil", "Conti", "LockBit"],
        "typical_remediation": [
            "Maintain offline backups and test restoration procedures.",
            "Implement network segmentation to limit ransomware spread.",
            "Use application control to prevent unauthorized encryption tools."
        ]
    }
}

class SOCCopilot:
    """
    AI SOC Analyst Copilot using a rule/template-based engine for incident analysis.
    """

    def generate_incident_analysis(self, incident: dict) -> dict:
        """
        Generates an automated incident analysis report based on provided incident data.
        """
        rule = incident.get("rule", {})
        telemetry = incident.get("telemetry", {})
        risk = incident.get("risk_assessment", {})
        intel = incident.get("threat_intel", {})
        containment = incident.get("containment_action", {})
        
        technique_id = rule.get("technique_id", "Unknown")
        tech_info = MITRE_TECHNIQUE_KNOWLEDGE.get(technique_id, {
            "name": "Unknown Technique",
            "description": "No description available.",
            "danger_level": "UNKNOWN",
            "known_actors": [],
            "typical_remediation": []
        })

        severity = rule.get("severity", "Medium")
        target_host = telemetry.get("target_host", telemetry.get("hostname", "Unknown Host"))
        source_ip = telemetry.get("source_ip", "Unknown IP")
        risk_score = risk.get("risk_score", 50)
        
        # 1. Executive Summary
        action_taken = containment.get("action", "No automated containment action was taken")
        if containment.get("status") == "success":
            action_status = f"Successfully executed '{action_taken}'."
        else:
            action_status = f"Attempted '{action_taken}' but status is '{containment.get('status', 'unknown')}'."

        exec_summary = (
            f"A {severity}-severity security incident was detected on host {target_host} involving suspected {tech_info['name']}. "
            f"The activity originated from or involved {source_ip}, triggering an alert with a risk score of {risk_score}/100. "
            f"{action_status} This requires immediate review to ensure threat eradication."
        )

        # 2. Root Cause Analysis
        user = telemetry.get("user", "Unknown User")
        process_name = telemetry.get("process_name", "Unknown Process")
        
        rca = {
            "initial_vector": f"Potential exploitation or access from {source_ip} leveraging {process_name}.",
            "privilege_escalation_path": f"Monitored account '{user}' executing actions aligned with {tech_info['name']}.",
            "persistence_mechanism": f"Technique {technique_id} may be used to establish or maintain access.",
            "data_at_risk": "Credentials, system configuration, or sensitive business data accessible by the compromised user/host."
        }

        # 3. Remediation Guidance
        remediation = list(tech_info["typical_remediation"])
        remediation.append(f"Isolate {target_host} from the network to prevent lateral movement.")
        remediation.append(f"Perform a full forensic memory dump on {target_host} prior to reboot.")
        remediation.append(f"Reset credentials for user account '{user}' across all domains.")
        if intel.get("indicators"):
            remediation.append("Block identified malicious indicators (IPs, Hashes) at the perimeter firewall and EDR.")
        
        # Limit to 4-6 items
        remediation = remediation[:6]

        # 4. Risk Verdict
        if risk_score >= 80 or tech_info["danger_level"] == "CRITICAL":
            verdict = "TRUE_POSITIVE"
            confidence = min(risk_score + 10, 99)
            reason = f"High risk score ({risk_score}) and critical technique {technique_id} indicate a highly probable compromise."
        elif risk_score >= 40:
            verdict = "REQUIRES_INVESTIGATION"
            confidence = risk_score
            reason = f"Medium risk score ({risk_score}) with {technique_id} necessitates human validation."
        else:
            verdict = "FALSE_POSITIVE"
            confidence = max(100 - risk_score, 60)
            reason = f"Low risk score ({risk_score}) and pattern suggests benign administrative activity."

        risk_verdict = {
            "verdict": verdict,
            "confidence_pct": confidence,
            "reasoning": reason
        }

        # 5. MITRE Context
        actors_str = ", ".join(tech_info["known_actors"]) if tech_info["known_actors"] else "Unknown"
        mitre_ctx = (
            f"Technique {technique_id} ({tech_info['name']}): {tech_info['description']} "
            f"This technique poses a {tech_info['danger_level']} threat to the organization. "
            f"Known threat actors utilizing this technique include: {actors_str}."
        )

        return {
            "executive_summary": exec_summary,
            "root_cause_analysis": rca,
            "remediation_guidance": remediation,
            "risk_verdict": risk_verdict,
            "mitre_context": mitre_ctx
        }

if __name__ == "__main__":
    # Test data
    sample_incident = {
        "telemetry": {
            "target_host": "SRV-DC-01",
            "source_ip": "10.0.5.23",
            "user": "admin_jdoe",
            "process_name": "mimikatz.exe"
        },
        "rule": {
            "technique_id": "T1003.001",
            "severity": "Critical"
        },
        "risk_assessment": {
            "risk_score": 92
        },
        "threat_intel": {
            "indicators": ["10.0.5.23"]
        },
        "containment_action": {
            "action": "Isolate Host",
            "status": "success"
        },
        "observables": [],
        "timeline": [],
        "thehive_case": "TH-1234"
    }

    copilot = SOCCopilot()
    analysis = copilot.generate_incident_analysis(sample_incident)
    print(json.dumps(analysis, indent=2))
