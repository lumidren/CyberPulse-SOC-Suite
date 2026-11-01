# YARA Scanning

Roadmap F70. `soar/yara_scan.py` scans collected files with `rules/yara/*.yar`.

- **Engine:** `yara-python` (libyara, full language) when installed
  (`pip install yara-python`). Without it, a small built-in matcher handles the subset the
  shipped rules use (text strings with `ascii`/`wide`/`nocase`, plain hex strings,
  `any|all|N of them`, `N of ($prefix*)`, `$a and/or $b`) and **refuses** any other rule
  rather than guessing. The response says which engine ran.
- **What can be scanned:** only files inside `SANDBOX_EVIDENCE_DIR`, the folder where your
  EDR or the triage process drops collected samples:
  `POST /api/evidence/yara-scan {"path": "case-42/dropper.bin"}`. Paths outside it are
  refused, so the API cannot read other files on the host. Every scan is audit-logged.
- Files are read (never executed), up to 64 MB.

**Not verified:** `yara-python` is not installed on the development machine, so the shipped
rules have only been run through the built-in matcher; the libyara path is untested here.
