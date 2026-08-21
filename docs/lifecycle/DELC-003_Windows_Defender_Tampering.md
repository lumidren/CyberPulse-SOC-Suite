# Detection Engineering Lifecycle (DELC-003): Defense Evasion via Defender Impairment

| Lifecycle Stage | Status | Author | Target Technique | Threat Actor Alignment |
| :--- | :--- | :--- | :--- | :--- |
| **Production (v2.0)** | **Active & Enforced** | lumidren | **MITRE ATT&CK T1562.001** | Conti, DarkSide, Qakbot, BlackByte |

---

## 1. Threat Hypothesis & Adversary Tradecraft
Prior to staging payloads or encrypting hosts, ransomware operators and advanced adversaries attempt to blind host defenses by disabling Microsoft Defender Antivirus using administrative PowerShell cmdlets (`Set-MpPreference`) or manipulating registry values under `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`.

---

## 2. Telemetry Requirements & Log Analysis
Captured via **Sysmon Event ID 1 (Process Creation)** or **Windows Security Event ID 4688** with full command-line process auditing enabled.

### Raw Telemetry Schema (Sysmon Event ID 1 Excerpt):
```json
{
  "EventID": 1,
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "UtcTime": "2026-08-21 16:20:10.500",
  "ProcessId": 5120,
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "User": "CORP\\j.doe"
}
```

---

## 3. Draft Rule Implementation (v1.0) & Tuning

### Operational Tuning & Edge Cases:
* Legitimate centralized IT configuration management tools (e.g. SCCM/Intune) enforce antivirus settings via GPO Registry writes, rarely by executing raw PowerShell `-DisableRealtimeMonitoring` flags on user interactive sessions.
* The rule strictly alerts on interactive invocation of `Set-MpPreference` containing disabling flags.

```yaml
# Final Production Rule (rules/sigma/win_defender_tamper.yml)
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - 'Set-MpPreference'
            - '-DisableRealtimeMonitoring'
            - '-DisableBehaviorMonitoring'
            - '-DisableIOAVProtection'
            - '-DisableScriptScanning'
    condition: selection
```

---

## 4. Consciously Accepted Blindspots & Coverage Gaps
* **Direct Token / Service Manipulation**: Adversaries leveraging specialized tools like `Backstab` or terminating the `WinDefend` service via trusted installer token hijacking will not trigger `Set-MpPreference` process strings.
* **Mitigation Recommendation**: Enforce **Tamper Protection** via Microsoft Defender for Endpoint portal, which prevents modifications to security settings even by local Administrator accounts.
