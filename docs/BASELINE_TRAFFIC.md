# Benign Baseline Traffic: How the FP Test Data Is Generated

False-positive figures in this repository come from **synthetic benign
traffic**, not from a real network. This page documents exactly how that
traffic is produced so anyone can regenerate it and check the numbers.

## Generator

`simulator/benign_baseline.py` → `generate_baseline(count=600, seed=1337)`

* Deterministic: the same `count` and `seed` always produce the same events,
  so FP counts are reproducible run to run and in CI.
* Same event schema as the attack generators (`event_id`, `event_source`,
  `computer_name`, `user`, `source_ip`, `details`), plus a
  `baseline_category` field.
* Events are spread evenly (round-robin) across six categories.
* Nothing is executed. Hosts, users and IPs are lab values (RFC 1918 or
  synthetic account names).

## Categories and why they are included

| Category | What it models | Rule it stresses |
| :--- | :--- | :--- |
| `admin_scripts` | Signed maintenance PowerShell run with `-NoProfile -File` | SOC-RULE-004 (PowerShell flags) |
| `backups` | `wbadmin` backups and `vssadmin list/create shadow` | Shadow-copy / ransomware precursor rules |
| `patching` | `msiexec /qn` installs and vendor updater / maintenance scheduled tasks | SOC-RULE-003 (scheduled task) |
| `av_scanning` | Defender `MsMpEng.exe` opening `lsass.exe` (0x1410) | SOC-RULE-001 (LSASS access) |
| `normal_auth` | 1–3 mistyped passwords; AES Kerberos service tickets | SOC-RULE-002, SOC-RULE-007 |
| `cloud_ops` | CI/CD pipeline `AssumeRole` from a known build account | SOC-RULE-009 (AssumeRole) |

The categories deliberately include **near-miss** activity that resembles
attacker tradecraft, because a baseline of obviously harmless events would
make any FP rate look perfect.

## Limits of this baseline

* It is hand-modelled, not sampled from real hosts. Real environments contain
  far more variety (EDR agents, RMM tools, developer tooling, scanners), so a
  low FP count here does **not** predict real-world noise.
* It contains six categories; anything outside them is untested.
* Category proportions are uniform, unlike real traffic.

See `scripts/validate_detections.py` (E3/E4) for how the baseline is replayed
through the detection engine and how false positives are counted.
