# Detection Engineering Lifecycle (DELC-001): OS Credential Dumping (LSASS)

| Lifecycle Stage | Status | Author | Target Technique | Threat Actor Alignment |
| :--- | :--- | :--- | :--- | :--- |
| **Production (v2.1)** | **Active & Tuned** | lumidren | **MITRE ATT&CK T1003.001** | APT29, FIN7, Wizard Spider, LockBit |

---

## 1. Threat Hypothesis & Adversary Tradecraft
Adversaries seeking lateral movement or domain privilege escalation often dump cleartext credentials, NTLM hashes, and Kerberos tickets stored in the memory space of the Local Security Authority Subsystem Service (`lsass.exe`). To read process memory from user space, the adversary must acquire a process handle to `lsass.exe` using Windows API calls (`OpenProcess` / `NtOpenProcess`) requesting specific access rights:
* `PROCESS_VM_READ` (`0x0010`)
* `PROCESS_QUERY_INFORMATION` (`0x0400`)
* Combined Access Mask: `0x1010` or `0x1400` (often used by tools like Mimikatz, ProcDump, and Dumpert).

---

## 2. Telemetry Requirements & Log Analysis
To capture handle acquisition without commercial EDR hooks, we leverage **Sysmon Event ID 10 (ProcessAccess)**.

### Raw Telemetry Schema (Sysmon Event ID 10 Excerpt):
```json
{
  "EventID": 10,
  "Channel": "Microsoft-Windows-Sysmon/Operational",
  "UtcTime": "2026-08-21 14:32:01.120",
  "SourceProcessId": 4812,
  "SourceImage": "C:\\Windows\\Temp\\mimikatz.exe",
  "TargetProcessId": 672,
  "TargetImage": "C:\\Windows\\System32\\lsass.exe",
  "GrantedAccess": "0x1010",
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9a100|C:\\Windows\\System32\\KERNELBASE.dll+2c410"
}
```

---

## 3. Draft Rule Implementation (v1.0 - Initial Baseline)

```yaml
title: LSASS Process Access Detected (Draft v1.0)
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains: '0x1010'
    condition: selection
```

---

## 4. Testing, False Positive Discovery & Tuning

### Operational False Positives Discovered During Baseline Testing:
1. **Windows Defender Antivirus (`MsMpEng.exe`)**: Constantly opens read handles to `lsass.exe` for real-time behavior inspection (`GrantedAccess: 0x1410`).
2. **Client Server Runtime Subsystem (`csrss.exe`) & Service Host (`svchost.exe`)**: Legitimate OS sub-systems query LSASS status.
3. **IT Diagnostic Tools (`procdump.exe -ma`)**: Legitimate sysadmins dumping crash dumps during application failure diagnostics.

### Tuning Iteration (Production v2.1):
We implemented explicit parent/source binary exclusions for signed native system services while requiring specific granted access masks.

```yaml
# Final Production Rule (rules/sigma/win_lsass_dumping.yml)
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1400'
            - '0x1F0FFF'
    filter:
        SourceImage|endswith:
            - '\svchost.exe'
            - '\csrss.exe'
            - '\MsMpEng.exe'
            - '\lsass.exe'
    condition: selection and not filter
```

---

## 5. Consciously Accepted Blindspots & Coverage Gaps
* **Direct System Calls / Unhooked APIs**: If an adversary leverages direct syscalls (e.g. SysWhispers3 or Hell's Gate) to bypass user-mode API hooking, Sysmon kernel callbacks still log Event ID 10, but custom user-mode ETW providers may be blinded.
* **Kernel-Level Memory Scraping (BYOVD)**: Attackers deploying a vulnerable signed kernel driver (e.g. `gdrv.sys`, `mhyprot2.sys`) to read LSASS physical memory bypasses `OpenProcess` entirely and will not generate Sysmon Event ID 10.
* **Mitigation Recommendation**: Enforce **LSA Protection (RunAsPPL)** via GPO and **Credential Guard (VBS)** to block user-mode memory access at the OS kernel level.
