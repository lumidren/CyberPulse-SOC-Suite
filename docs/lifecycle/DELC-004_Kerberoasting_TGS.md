# Detection Engineering Lifecycle (DELC-004): Kerberoasting TGS Extraction

| Lifecycle Stage | Status | Author | Target Technique | Threat Actor Alignment |
| :--- | :--- | :--- | :--- | :--- |
| **Production (v2.0)** | **Active & Calibrated** | lumidren | **MITRE ATT&CK T1558.001** | APT29, FIN6, Silence, Vice Society |

---

## 1. Threat Hypothesis & Adversary Tradecraft
Any authenticated Active Directory domain user can request a Kerberos Ticket Granting Service (TGS) ticket for any service with a registered Service Principal Name (SPN). Because the TGS ticket is encrypted using the password hash of the service account, an attacker can extract the ticket from memory and crack the plaintext password offline (e.g. using Hashcat / John the Ripper). Attackers frequently request **RC4-HMAC (`0x17`)** encryption because RC4 hashes are significantly faster to crack than AES-128/256.

---

## 2. Telemetry Requirements & Log Analysis
Captured via **Windows Security Event ID 4769 (A Kerberos service ticket was requested)** on the Domain Controller.

### Raw Telemetry Schema (Security Event ID 4769 Excerpt):
```json
{
  "EventID": 4769,
  "Channel": "Security",
  "UtcTime": "2026-08-23 09:12:04.100",
  "TargetUserName": "svc_mssql_prod@CORP.LOCAL",
  "ServiceName": "MSSQLSvc/sql01.corp.local:1433",
  "TicketEncryptionType": "0x17",
  "TicketOptions": "0x40810000",
  "Status": "0x0",
  "IpAddress": "10.0.0.45",
  "IpPort": 51240
}
```

---

## 3. False Positive Discovery & Tuning
* **Legacy Service Accounts**: Legacy systems that do not support AES encryption negotiate RC4 by default.
* **Tuning Resolution**: In [`rules/sigma/win_kerberoasting.yml`](../../rules/sigma/win_kerberoasting.yml), we filter out machine accounts (`ServiceName` ending in `$`) and correlate against accounts with elevated SPN privileges.

---

## 4. Automated SOAR Containment Playbook
* **Action**: `RESET_SERVICE_ACCOUNT_AND_REVOKE_KERBEROS_TICKET`
* **Execution**: SOAR dispatches WinRM / Active Directory command to invalidate the affected Kerberos ticket and queue a forced password rotation on `svc_mssql_prod`.
