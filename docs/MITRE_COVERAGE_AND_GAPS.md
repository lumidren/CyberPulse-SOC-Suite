# MITRE ATT&CK Matrix: Coverage, Fidelity, and Accepted Gaps

## 1. Overview & Detection Philosophy
In professional Detection Engineering, **claiming 100% coverage across the entire MITRE ATT&CK matrix is a recognized anti-pattern**. Real-world detection strategies balance signal-to-noise ratio, compute overhead, telemetry capabilities, and attack surface priorities.

This document details the exact detection posture of **CyberPulse SOC Suite**, explicitly documenting **active detection capabilities** alongside **consciously accepted coverage gaps and blindspots**.

---

## 2. Active High-Fidelity Detections (Production Rulebase)

| Technique ID | Technique Name | Tactic | Primary Telemetry | Rule ID & Format | Fidelity / Noise | Automated Containment Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`T1003.001`** | OS Credential Dumping: LSASS | Credential Access | Sysmon Event ID 10 | `SOC-RULE-001` (Sigma/Wazuh) | **High** (Tuned vs Defender/CSRSS) | WinRM Host Isolation + Process Termination |
| **`T1110.001`** | Password Guessing: RDP | Credential Access | Security Event ID 4625 | `SOC-RULE-002` (Sigma/Wazuh) | **High** (>10 fails/300s window) | Dynamic pfSense Perimeter Firewall Drop |
| **`T1053.005`** | Scheduled Task Persistence | Persistence | Security Event ID 4698 | `SOC-RULE-003` (Sigma/Wazuh) | **High** (Script engine keywords) | Remote Scheduled Task De-registration |
| **`T1059.001`** | PowerShell Execution | Execution | Sysmon Event ID 1 | `SOC-RULE-004` (Sigma/Wazuh) | **Medium-High** (Encoded CLI flags) | Process Tree Termination + Session Revoke |
| **`T1562.001`** | Impair Defenses: Disable AV | Defense Evasion | Sysmon Event ID 1 | `SOC-RULE-005` (Sigma/Wazuh) | **Critical** (Set-MpPreference flags) | Revert AV Policy + Host Network Isolation |
| **`T1486`** | Data Encrypted for Impact | Impact | Sysmon Event ID 11 | `SOC-RULE-006` (Sigma/Wazuh) | **Critical** (Canary directory files) | Process Kill + Volume Shadow Copy Snapshot |

---

## 3. Consciously Accepted Coverage Gaps & Blindspots

| Uncovered Technique | Tactic | Why It Is Currently Uncovered (Root Cause) | Required Telemetry / Architecture | Planned Roadmap Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **`T1055.003` (Thread Execution Hijacking)** | Privilege Escalation / Evasion | Sysmon user-mode event 10 logs open handles, but does not track thread context manipulation (`SetThreadContext`) without deep kernel ETW. | Microsoft-Windows-Threat-Intelligence (EtwTI) kernel provider. | Deploy specialized ETW kernel subscriber agent in Phase 3. |
| **`T1068` (Exploitation for Privilege Escalation - BYOVD)** | Privilege Escalation | Vulnerable signed kernel drivers (Bring Your Own Vulnerable Driver) bypass OS user-mode APIs entirely. | Driver blocklist auditing (`WDAC` / Hypervisor-Protected Code Integrity). | Enforce Microsoft Recommended Driver Block Rules via GPO. |
| **`T1078` (Valid Accounts - Low-and-Slow Spraying)** | Initial Access | Single password guesses dispersed across 200+ users over days fall below deterministic threshold rules. | UEBA (User and Entity Behavior Analytics) statistical anomaly model. | Route low-frequency authentication feeds to GUARDIAN anomaly model. |
| **`T1048` (Exfiltration Over Alternative Protocol - DNS Tunneling)** | Exfiltration | Standard endpoint event logs do not capture DNS payload entropy and TXT record volume. | Core DNS Gateway query logs / Zeek Network Security Monitoring. | Integrate CoreDNS / Zeek passive DNS log parser into Wazuh indexer. |

---

## 4. Scope and Lab Realism Statement
* **Deployment Scope**: CyberPulse is a specialized Detection Engineering laboratory engineered on virtualized enterprise components (Windows Server 2022 AD DS, Sysmon v14, pfSense 2.7, Wazuh 4.7) and a CI/CD test harness. 
* **Operational Goal**: Demonstrates rigorous Detection-as-Code development lifecycles, structured false-positive tuning, and automated closed-loop mitigation rather than speculative 100% matrix coverage claims.
