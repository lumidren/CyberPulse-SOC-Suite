# Detection Engineering Lifecycle (DELC-002): RDP Password Brute Force & Spraying

| Lifecycle Stage | Status | Author | Target Technique | Threat Actor Alignment |
| :--- | :--- | :--- | :--- | :--- |
| **Production (v2.0)** | **Active & Calibrated** | lumidren | **MITRE ATT&CK T1110.001** | Initial Access Brokers, LockBit, BlackCat |

---

## 1. Threat Hypothesis & Adversary Tradecraft
Adversaries seeking initial access target exposed Remote Desktop Protocol (RDP port 3389) or SMB endpoints with automated password guessing scripts (Crowbar, Hydra, Ncrack) against known enterprise username lists (`admin`, `administrator`, `service_acct`).

---

## 2. Telemetry Requirements & Log Analysis
To detect brute force across remote authentication, we analyze **Windows Security Event ID 4625 (An account failed to log on)**.

### Raw Telemetry Schema (Security Event ID 4625 Excerpt):
```json
{
  "EventID": 4625,
  "Channel": "Security",
  "UtcTime": "2026-08-21 15:10:01.000",
  "TargetUserName": "admin",
  "TargetDomainName": "CORP",
  "LogonType": 10,
  "Status": "0xc000006d",
  "SubStatus": "0xc000006a",
  "IpAddress": "185.220.101.5",
  "IpPort": 49152,
  "WorkstationName": "ATTACKER-PC"
}
```

---

## 3. Draft Rule Implementation (v1.0 - Initial Baseline)

```yaml
title: High Volume Failed Logons (Draft v1.0)
detection:
    selection:
        EventID: 4625
    timeframe: 1m
    condition: selection | count() > 5
```

---

## 4. Testing, False Positive Discovery & Tuning

### Operational False Positives in Baseline Testing:
* **User Password Fatigue**: Setting a 1-minute threshold of 5 failures caused false alerts when legitimate employees forgot newly rotated Active Directory passwords or multiple network drives reconnected with expired cached credentials.
* **Internal Service Accounts (LogonType 3/5)**: Automated batch jobs failing repeatedly on expired service tokens triggered noisy internal alerts.

### Tuning Iteration (Production v2.0):
1. Restricted detection strictly to **`LogonType: 10` (Remote Interactive / RDP)** or external boundary IPs.
2. Expanded sliding aggregation window to **5 minutes (`300s`)** and raised threshold to **>10 failed attempts** originating from the same source IP.

```yaml
# Final Production Rule (rules/sigma/win_brute_force_auth.yml)
detection:
    selection:
        EventID: 4625
        LogonType:
            - 10 # RDP Remote Interactive
            - 3  # Network SMB
    timeframe: 5m
    condition: selection | count() by IpAddress > 10
```

---

## 5. Consciously Accepted Blindspots & Coverage Gaps
* **Low-and-Slow Password Spraying**: An attacker testing 1 password per account every 30 minutes across 500 domain accounts (1 failure per user per half-hour) will not trigger this threshold rule.
* **Detection Roadmap**: Build a secondary statistical anomaly model (GUARDIAN integration) correlating low-frequency failures across multiple distinct usernames from single ASNs.
