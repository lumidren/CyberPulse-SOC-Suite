# 3. Breaking my own rules

> Part of the series *How I built the detections*. Drafted with an AI assistant from this repository's commit history; every number is copied from a generated report linked in the post. All data is synthetic.

Testing a rule only with the event you wrote it for proves very little. So I wrote
[16 evasion cases](../EVASION.md) against five rules: the variants an attacker would try first.

**Result: 11 of 16 bypass the rule they target, and no other rule catches them.** Some examples:

- PowerShell accepts any unambiguous prefix of a parameter, so `-ec` works where the rule looks for
  `-EncodedCommand` or `-enc `. It also accepts an en dash instead of a hyphen.
- Renaming `powershell.exe` or `certutil.exe` defeats rules keyed on the image name. Sysmon records
  `OriginalFileName`; the rules do not use it yet.
- The LSASS rule's allowlist trusts any path ending in `\svchost.exe`, so `C:\Users\Public\svchost.exe`
  is invisible to it. It also misses `PROCESS_ALL_ACCESS` (0x1FFFFF).
- Two spaces in `vssadmin delete  shadows` break a literal `contains`.

Each case is pinned by a test: if a rule is improved and a bypass closes, the test fails until
the documentation says so. That keeps the page honest in both directions.

**Lesson.** Publish the bypasses. The [what I missed](../WHAT_I_MISSED.md) page puts them next to
the coverage gaps so nobody mistakes a coloured ATT&CK cell for detection.
