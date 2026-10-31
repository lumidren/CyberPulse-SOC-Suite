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

## SOC-RULE-012: Pass-the-Hash Logon Patterns (NTLM and seclogo) (`win_pass_the_hash.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-013: Possible Golden Ticket Use via Kerberos Logon Domain Anomaly (`win_golden_ticket_domain_anomaly.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-014: Certutil Used to Download or Decode a Payload (`win_lolbas_certutil_download.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-015: Mshta Executing Remote or Inline Script (`win_lolbas_mshta_remote_script.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-016: Regsvr32 Loading a Remote Scriptlet (Squiblydoo) (`win_lolbas_regsvr32_squiblydoo.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-017: Rundll32 Executing Script or Remote Content (`win_lolbas_rundll32_script.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-018: BITSAdmin Download or Job Creation (`win_lolbas_bitsadmin_transfer.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-019: Volume Shadow Copy Deletion or Resizing (`win_ransomware_shadow_copy_deletion.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-020: Backup Catalog Deletion or Boot Recovery Disabled (`win_ransomware_recovery_inhibition.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-021: Office Application Spawning a Shell or Script Host (`win_office_spawns_shell.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-022: Process Creation via WMIC process call create (`win_wmic_process_call_create.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-023: Script Host Running a Script from a User-Writable Path (`win_script_host_user_writable.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-024: Run Key Persistence Added via reg.exe (`win_registry_run_key_persistence.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-025: Service Installed from a Suspicious Path or Command (`win_service_install_suspicious_path.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-026: Account Added to the Local Administrators Group (`win_local_admin_group_addition.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-027: WMI Event Subscription Persistence (`win_wmi_event_subscription.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-028: UAC Bypass via ms-settings Shell Open Command (`win_uac_bypass_ms_settings.yml`)

* **1.0.0** (2026-11-01): Initial rule.
