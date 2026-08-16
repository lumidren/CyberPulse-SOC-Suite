# SOC Incident Response Report: RDP Password Brute Force Attack (T1110.001)

| Incident ID | Severity | Status | Assigned Analyst | Timestamp |
| :--- | :--- | :--- | :--- | :--- |
| **INC-2026-0815-02** | **HIGH** | **CLOSED (Auto-Contained)** | Tier-1 / SOAR Automated Playbook | 2026-08-15T15:10:00Z |

---

## 1. Executive Summary
AegisSOC detected a brute-force password guessing campaign targeting the external RDP gateway server (`CORP-RDP-GW01`). Over 65 failed authentication attempts were recorded within 180 seconds originating from external IP `185.220.101.5`. The SOAR playbook automatically triggered a dynamic firewall rule on the perimeter gateway, blocking all traffic from the threat source.

---

## 2. Technical Details & IoCs

### Affected Assets
* **Host**: `CORP-RDP-GW01` (Public Endpoint)
* **Logon Type**: 10 (Remote Desktop Protocol)
* **Target Accounts**: `admin`, `administrator`, `j.smith`, `service_acct`

### Indicators of Compromise (IoCs)
* **Attacker IP**: `185.220.101.5` (Germany / Hostinger Scanner)
* **AbuseIPDB Abuse Score**: 98% Confidence of Abuse
* **Failed Attempt Count**: 65 Attempts
* **SubStatus Code**: `0xc000006a` (Bad Password)

---

## 3. Incident Timeline

| Time (UTC) | Source / Component | Event Description |
| :--- | :--- | :--- |
| **15:07:30** | Attacker | Initiated automated RDP brute-force dictionary attack against public gateway. |
| **15:09:45** | Windows Audit (Event 4625) | Accumulated 65 failed logon entries for multiple domain accounts. |
| **15:10:00** | Wazuh SIEM | Rule `100011` matched (Threshold exceeded: >10 failures in 5 mins). |
| **15:10:01** | SOAR Engine | Queried AbuseIPDB API. Flagged IP `185.220.101.5` with 98% abuse rating. |
| **15:10:02** | SOAR Playbook | Executed playbook `PB-FIREWALL-BLOCK`: Added drop rule for `185.220.101.5/32`. |

---

## 4. Remediation & Recommendations
- **Immediate Action**: Source IP blocked at perimeter firewall. Zero accounts compromised.
- **Long-term Recommendation**: Enforce Account Lockout Policy (5 attempts / 15 min lockout), mandate Multi-Factor Authentication (MFA) on RDP gateway, and place RDP interface behind a zero-trust network access (ZTNA) tunnel.
