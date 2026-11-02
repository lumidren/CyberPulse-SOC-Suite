# Rule Changelog

Per-rule version history (semantic versioning per rule: MAJOR = detection logic narrows or
changes meaning, MINOR = broadens/adds coverage, PATCH = metadata only).
`tests/test_rule_versioning.py` fails if a rule's detection logic changes without a version
bump here and in `rules/soar_mapping.yml`.

2026-11-02, all rules: ATT&CK tactic tags use the current hyphenated form
(`attack.credential-access`, not `attack.credential_access`). This is metadata only,
so no rule version changed.

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

* **1.0.2** (2026-11-02): `ResultType` is written as the number 0 instead of the string '0' (sigma check NumberAsStringIssue). Matching is unchanged: the rule samples give the same results.
* **1.0.1** (2026-11-01): Metadata only: date normalised to ISO format; added `modified`.
* **1.0.0** (2026-09-09): Initial rule.

## SOC-RULE-011: Vulnerable Signed Driver Load (BYOVD Evasion) (`win_driver_byovd_load.yml`)

* **1.1.0** (2026-11-02): Uses the generic `driver_load` log source instead of the Sysmon service plus `EventID: 6` (sigma check SpecificInsteadOfGenericLogsourceIssue). Slightly broader: any Windows driver-load event (ID 6) qualifies, not only events from the Sysmon channel.
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

## SOC-RULE-029: Security Event Log Cleared (`win_security_log_cleared.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-030: Windows Firewall Disabled via netsh or PowerShell (`win_firewall_disabled.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-031: SAM or SYSTEM Registry Hive Saved to Disk (`win_sam_hive_export.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-032: NTDS.dit Extraction via ntdsutil IFM (`win_ntds_extraction.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-033: AS-REP Roasting: TGT Without Pre-Authentication over RC4 (`win_asrep_roasting.yml`)

* **1.0.1** (2026-11-02): `PreAuthType` is written as the number 0 instead of the string '0' (sigma check NumberAsStringIssue). Matching is unchanged: the rule samples give the same results.
* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-034: Active Directory Reconnaissance Commands (`win_ad_reconnaissance.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-035: PsExec-Style Remote Service Execution (`win_psexec_service.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-036: Shell Spawned by WinRM Remote Session Host (`win_winrm_remote_shell.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-037: Remote Access Tool Started from a User-Writable Path (`win_remote_access_tool.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-038: Password-Protected Archive Created with 7-Zip or WinRAR (`win_archive_with_password.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-039: Rclone Copying Data to Cloud Storage (`win_rclone_exfiltration.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-040: Backup or Security Service Stopped via net or sc (`win_service_stop_backup_security.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-041: AWS CloudTrail Logging Stopped or Deleted (`cloud_aws_cloudtrail_disabled.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-042: Entra ID Admin Consent Granted to an Application (`cloud_entra_admin_consent.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-043: Brute Force From One Source Against One Account (raw 4625 correlation) (`correlations/win_brute_force_raw_logons.yml`)

* **1.0.0** (2026-11-01): Initial correlation rule.

## SOC-RULE-044: Password Spraying From One Source (distinct accounts correlation) (`correlations/win_password_spraying.yml`)

* **1.0.0** (2026-11-01): Initial correlation rule.

## SOC-RULE-045: Mass File Write by One Process (ransomware encryption or mass rename) (`correlations/win_mass_file_write.yml`)

* **1.0.0** (2026-11-01): Initial correlation rule.

## SOC-RULE-046: Authentication Attempt Against a Honey Account (`win_honey_account_activity.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-047: Access to a Canary File (`win_honey_file_access.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-048: AWS Canary Credential Used (`cloud_aws_canary_credential_use.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-049: High-Score Behavioural Anomaly from GUARDIAN (`guardian_high_score_anomaly.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-050: Phishing Email Reported by a User or Failing DMARC with a Link or Attachment (`email_phishing_reported_or_auth_fail.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-051: High-Severity Suricata IDS Alert (`net_suricata_high_severity_alert.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-052: Executable Downloaded over HTTP by a Script Client or to a Raw IP (`net_zeek_http_executable_from_script_client.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-054: DNS Query with an Unusually Long Label (possible tunnelling) (`net_zeek_dns_long_label.yml`)

* **1.0.0** (2026-11-01): Initial rule.

## SOC-RULE-053: Many Unique Subdomains of One Domain from One Host (DNS tunnelling) (`correlations/net_dns_tunnel_unique_subdomains.yml`)

* **1.0.0** (2026-11-01): Initial correlation rule.

## SOC-RULE-055: TLS Client Fingerprint on the Local JA3/JA4 Blocklist (`net_zeek_tls_fingerprint_blocklist.yml`)

* **1.0.0** (2026-11-01): Initial rule.
