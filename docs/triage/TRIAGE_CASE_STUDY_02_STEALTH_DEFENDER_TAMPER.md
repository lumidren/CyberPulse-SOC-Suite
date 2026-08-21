# SOC Tier-1 / Tier-2 Triage Case Study 02: True-Positive Defense Evasion Triage

| Incident ID | Fired Rule | Initial Severity | Final Triage Verdict | Assigned Analyst |
| :--- | :--- | :--- | :--- | :--- |
| **TRIAGE-2026-0821-02** | `SOC-RULE-005` (Defender Tamper) | **CRITICAL** | **TRUE POSITIVE (Malicious Intrusion)** | Tier-2 Analyst (lumidren) |

---

## 1. Alert Trigger & Context
At **03:41:15 UTC on Sunday**, the SIEM triggered a CRITICAL alert on workstation `WIN-WORKSTATION09` for execution of `Set-MpPreference -DisableRealtimeMonitoring $true`.

### Initial Alert Metadata:
* **Host**: `WIN-WORKSTATION09` (10.0.0.45 / Marketing Segment)
* **User**: `CORP\j.doe` (Standard Non-Privileged User)
* **Process**: `powershell.exe` (PID: 5120)
* **Parent Process**: `cmd.exe /c start_update.bat` (PID: 2840)

---

## 2. Investigative Pivots & Root Cause Analysis

### Pivot 1: Parent Process & Foothold Artifacts
* Analyst traced parent process tree backwards:
  * `OUTLOOK.EXE` (PID 1420) ➔ spawned ➔ `WINWORD.EXE` (PID 2110) ➔ spawned ➔ `cmd.exe /c start_update.bat` (PID 2840) ➔ spawned ➔ `powershell.exe` (PID 5120).
* **Finding**: Classic macro-enabled phishing document execution. Non-technical marketing employee opened an attachment named `Invoice_Q3_Review.docm`.

### Pivot 2: Ingress Network Connections & Stager Download
* Sysmon Event ID 3 (Network Connection) revealed `powershell.exe` established an outbound HTTPS connection to `91.240.118.172:443` (Ukraine - Hostlife C2 infrastructure) immediately prior to invoking `Set-MpPreference`.
* Threat Intel enrichment scored `91.240.118.172` with an **88% Abuse Confidence Score** and 33 security vendor detections on VirusTotal.

---

## 3. Automated Containment & Manual Follow-Up

```text
[03:41:16 UTC] CyberPulse SOAR dispatches WinRM over TLS 5986 to WIN-WORKSTATION09
[03:41:17 UTC] Pushed WFP isolation filter (dropped all non-management IP connections)
[03:41:17 UTC] Terminated malicious PID 5120 and parent PID 2840
[03:41:18 UTC] Dispatched ADSI LDAP command disabling user CORP\j.doe
```

### Analyst Post-Containment Actions:
1. **Quarantine Confirmation**: Verified host network isolation via ping/connectivity tests from SOC management subnet.
2. **Credential Invalidation**: Reset Kerberos TGT and enterprise passwords for `CORP\j.doe`.
3. **Phishing Ingress Sweep**: Queried Microsoft 365 Exchange mail logs for subject line `"Invoice_Q3_Review.docm"` and purged 14 identical unread phishing emails across the organization.
