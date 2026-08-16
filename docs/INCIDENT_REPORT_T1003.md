# SOC Incident Response Report: LSASS Memory Dumping Attempt (T1003.001)

| Incident ID | Severity | Status | Assigned Analyst | Timestamp |
| :--- | :--- | :--- | :--- | :--- |
| **INC-2026-0815-01** | **CRITICAL** | **CLOSED (Auto-Contained)** | Tier-1 / SOAR Automated Playbook | 2026-08-15T14:32:00Z |

---

## 1. Executive Summary
At 14:32:00 UTC, AegisSOC SIEM triggered a **CRITICAL** alert (`SOC-RULE-001`) on domain controller `WIN-DC01.corp.local`. Telemetry indicated an unauthorized process (`C:\Windows\Temp\mimikatz.exe`) attempted to open a process memory handle targeting `lsass.exe` with access mask `0x1010` (PROCESS_VM_READ). The automated SOAR playbook immediately isolated the endpoint from the network via EDR API and terminated the malicious process tree.

---

## 2. Technical Details & IoCs

### Affected Assets
* **Host**: `WIN-DC01.corp.local` (10.0.0.10)
* **Target Account**: `CORP\Administrator`
* **Target Process**: `lsass.exe` (PID: 672)

### Indicators of Compromise (IoCs)
* **Attacker IP**: `185.220.101.33` (TOR Exit Node / BadHost Ltd, Russia)
* **Malicious File Path**: `C:\Windows\Temp\mimikatz.exe`
* **File SHA256**: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
* **Granted Access Mask**: `0x1010`

---

## 3. Incident Timeline

| Time (UTC) | Source / Component | Event Description |
| :--- | :--- | :--- |
| **14:31:58** | Attacker | Established remote shell access to `WIN-DC01` via compromised service credentials. |
| **14:32:00** | Sysmon (EventID 10) | Process access event detected: `mimikatz.exe` requested handle to `lsass.exe`. |
| **14:32:01** | Wazuh SIEM | Rule `100010` matched. Severity score: 14 (CRITICAL). Alert forwarded to SOAR engine. |
| **14:32:02** | SOAR Engine | Queried VirusTotal API for `185.220.101.33`. Reputation score: 38/70 malicious vendors. |
| **14:32:03** | SOAR Playbook | Executed playbook `PB-ISOLATE-HOST`: Network containment active on `WIN-DC01`, PID 4812 terminated. |

---

## 4. Root Cause & Containment Verification
- **Root Cause**: Weak service account password allowed initial lateral movement via SMB.
- **Containment Action**: Automated host network isolation prevented credential dump exfiltration.
- **Remediation**: Reset domain admin password, enforced LSASS RunAsPPL protection via GPO (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`).
