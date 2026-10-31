# Rule Changelog

Per-rule version history (semantic versioning per rule: MAJOR = detection logic narrows or
changes meaning, MINOR = broadens/adds coverage, PATCH = metadata only).
`tests/test_rule_versioning.py` fails if a rule's detection logic changes without a version
bump here and in `rules/soar_mapping.yml`.

## SOC-RULE-001: OS Credential Dumping via LSASS Memory Access (`win_lsass_dumping.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-08-15): Initial rule.

## SOC-RULE-002: Password Brute Force Authentication Failure Spike (`win_brute_force_auth.yml`)

* **2.0.0** (2026-11-01): Breaking: replaced the deprecated `| count() by IpAddress > 10` aggregation (unsupported by modern Sigma tooling) with a threshold on the collector's `FailedAttemptsCount` field; dates normalised to ISO.
* **1.0.0** (2026-08-15): Initial rule.

## SOC-RULE-003: Suspicious Scheduled Task Creation for Persistence (`win_scheduled_task_persistence.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-08-15): Initial rule.

## SOC-RULE-004: Obfuscated PowerShell Execution Cradle (`win_powershell_obfuscation.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-08-21): Initial rule.

## SOC-RULE-005: Windows Defender Real-Time Protection Disabled via PowerShell (`win_defender_tamper.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-08-21): Initial rule.

## SOC-RULE-006: Rapid File Encryption and Ransomware Canary Modification (`win_ransomware_canary.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-08-21): Initial rule.

## SOC-RULE-007: Kerberoasting TGS Ticket Request with RC4 Encryption (`win_kerberoasting.yml`)

* **1.0.2** (2026-11-01): Corrected the ATT&CK mapping: Kerberoasting is T1558.003 (T1558.001 is Golden Ticket).
* **1.0.1** (2026-11-01): Fixed a typo in the false-positive note; date normalised to ISO; added `modified`.
* **1.0.0** (2026-08-23): Initial rule.

## SOC-RULE-008: Active Directory Replication Abuse (DCSync) via Non-DC Account (`win_dcsync.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-08-23): Initial rule.

## SOC-RULE-009: Suspicious AWS STS AssumeRole Abuse Across External Account (`cloud_aws_assumerole_abuse.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-09-09): Initial rule.

## SOC-RULE-010: Microsoft Entra ID Impossible Travel Anomaly (`cloud_entra_impossible_travel.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-09-09): Initial rule.

## SOC-RULE-011: Vulnerable Signed Driver Load (BYOVD Evasion) (`win_driver_byovd_load.yml`)

* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-09-09): Initial rule.
