# Collaborative Purple Team Exercise Report: Active Directory Adversary Emulation

| Exercise ID | Date | Lead Evaluator | Scope | Objective |
| :--- | :--- | :--- | :--- | :--- |
| **PTX-2026-0821** | 2026-08-21 | lumidren | Hybrid AD Lab (`10.0.0.0/24`) | Validate Detection Efficacy & SOAR Response against Multi-Stage Kill Chain |

---

## 1. Executive Summary
This Purple Team exercise evaluated the detection posture and automated response capabilities of **CyberPulse SOC Suite** against a full simulated adversary lifecycle: from initial execution cradle, through defense impairment and credential harvesting, to ransomware canary deployment. 

The exercise validated **6 core ATT&CK techniques**, identified **2 critical blindspots**, and resulted in **2 detection rule enhancements** and an automated Volume Shadow Copy recovery playbook.

---

## 2. Collaborative Red/Blue Execution Matrix

| # | Kill Chain Phase | Red Team Offensive Tradecraft | Expected Blue Team Sensor | SIEM Detection Status | Detection Latency | Blindspot / Gap Discovered | Remediation & Engineering Fix |
| :- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Execution** (`T1059.001`) | Invoked base64 encoded PowerShell cradle (`-EncodedCommand aW52...`). | Sysmon Event ID 1 (Process Create) | **DETECTED** (`SOC-RULE-004`) | 1.41s | Standard command-line auditing misses script block payloads executed via stdin. | Enabled **PowerShell Script Block Logging (EventID 4104)** via GPO. |
| **2** | **Defense Evasion** (`T1562.001`) | Executed `Set-MpPreference -DisableRealtimeMonitoring $true` via batch script. | Sysmon Event ID 1 | **DETECTED** (`SOC-RULE-005`) | 1.38s | Attempting to terminate `WinDefend` service directly via taskkill was not captured. | Configured SACL auditing on Windows Defender service registry keys. |
| **3** | **Credential Access** (`T1003.001`) | Executed Mimikatz `sekurlsa::logonpasswords` reading `lsass.exe`. | Sysmon Event ID 10 (ProcessAccess `0x1010`) | **DETECTED** (`SOC-RULE-001`) | 1.39s | Initial draft rule triggered on legitimate Windows Defender and Sysinternals crash dumps. | Added signed binary filters for `MsMpEng.exe` and `csrss.exe` in Sigma v2.1. |
| **4** | **Persistence** (`T1053.005`) | Created scheduled task `\SystemHealthUpdate` running remote PowerShell beacon. | Security Event ID 4698 | **DETECTED** (`SOC-RULE-003`) | 1.42s | Tasks created with benign names like `GoogleUpdate` blend into baseline without script keyword filters. | Added keyword regex inspection for `http:`, `powershell`, and `cmd.exe`. |
| **5** | **Impact** (`T1486`) | Rapidly created 15 decoy encrypted files (`.docx.locked`) in canary finance folder. | Sysmon Event ID 11 (FileCreate) | **DETECTED** (`SOC-RULE-006`) | 1.40s | Ransomware encrypting in-memory without changing file extension bypassed extension matching. | Added I/O entropy monitoring threshold to file activity engine. |

---

## 3. Measurable Outcomes & Hardening Verification
1. **Detection Accuracy**: 5/5 chained adversary phases successfully triggered high-fidelity Sigma/Wazuh alerts.
2. **Automated Response Reliability**: Average closed-loop containment duration across all phases was **3.18 seconds** (WinRM host isolation, perimeter firewall drop, task purge, and VSS snapshot recovery).
3. **Active Directory Hardening**: Enabled GPO enforcement for **LSASS RunAsPPL** (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`) across all domain workstations.
