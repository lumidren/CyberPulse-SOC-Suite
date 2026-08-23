# Detection Engineering Lifecycle (DELC-005): Active Directory DCSync Replication Abuse

| Lifecycle Stage | Status | Author | Target Technique | Threat Actor Alignment |
| :--- | :--- | :--- | :--- | :--- |
| **Production (v2.0)** | **Active & Enforced** | lumidren | **MITRE ATT&CK T1003.006** | APT32, APT41, LockBit, Lapsus$ |

---

## 1. Threat Hypothesis & Adversary Tradecraft
DCSync allows an attacker with sufficient permissions (e.g. `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`) to simulate the behavior of a Domain Controller using the Directory Replication Service Remote Protocol (MS-DRSR). Using tools like Mimikatz (`lsadump::dcsync`), the attacker requests password hashes (including `krbtgt` NTLM hash) directly from a genuine Domain Controller without executing any code on the DC itself.

---

## 2. Telemetry Requirements & Log Analysis
Captured via **Windows Security Event ID 4662 (An operation was performed on an object)** with SACLs configured on the Domain NC.

### Raw Telemetry Schema (Security Event ID 4662 Excerpt):
```json
{
  "EventID": 4662,
  "Channel": "Security",
  "UtcTime": "2026-08-23 10:45:12.800",
  "SubjectUserName": "j.doe",
  "SubjectDomainName": "CORP",
  "ObjectName": "%{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
  "AccessMask": "0x100",
  "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}\n{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"
}
```

---

## 3. False Positive Analysis & Tuning
* **Legitimate Replication**: Domain Controllers replicate Active Directory objects constantly.
* **Tuning Resolution**: In [`rules/sigma/win_dcsync.yml`](../../rules/sigma/win_dcsync.yml), we exclude accounts belonging to the **Domain Controllers** security group (`SubjectUserName` ending in `$`) and explicit Azure AD Sync service accounts.

---

## 4. Automated SOAR Containment Playbook
* **Action**: `ISOLATE_ACCOUNT_AND_REVOKE_REPLICATION_PRIVILEGES`
* **Execution**: SOAR immediately disables the rogue user account via LDAP ADSI and revokes replication ACL permissions from the domain root.
