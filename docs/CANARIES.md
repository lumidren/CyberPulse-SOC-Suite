# Canary Tokens and Honeypots

Deception layer (roadmap F16). Decoys are things no legitimate user or process
ever touches, so a single hit is a high-confidence signal with almost no
tuning. The rules ship with **lab placeholder names**. Replace them with the
decoys you actually deploy, or the rules will never fire.

| Rule | Decoy | Telemetry needed |
| :--- | :--- | :--- |
| `SOC-RULE-046` `win_honey_account_activity.yml` | Decoy AD accounts (`svc_sql_legacy`, `adm_backup_old`) | Security log: 4624/4625/4648/4768/4769/4771/4776 on DCs |
| `SOC-RULE-047` `win_honey_file_access.yml` | Decoy files (`Passwords_2019.xlsx`, `vpn_credentials.txt`, `Payroll_Q4_FINAL.xlsx`) | Security 4663 with a SACL on each decoy |
| `SOC-RULE-048` `cloud_aws_canary_credential_use.yml` | IAM users owning planted access keys (`canary-backup-reader`, `canary-ci-deployer`) | CloudTrail management events |

## Deploying the decoys (your lab, your accounts)

Nothing here is automated: creating accounts, keys and files in a directory or
cloud account is a change you make yourself, in an environment you own.

1. **Honey accounts.** Create the account with a long random password you
   discard, no group memberships, `Account is sensitive and cannot be
   delegated`, and logon hours set to *never*. Optionally give it a believable
   description and an SPN so it shows up in Kerberoasting or BloodHound-style
   enumeration. Enable *Audit Kerberos Authentication Service* and *Audit
   Logon* on the domain controllers.
2. **Canary files.** Place the decoys on file shares and admin desktops. Add a
   SACL (Properties -> Security -> Advanced -> Auditing) for *Everyone*,
   *Read*, success, and enable *Audit File System* (Object Access) in the
   audit policy. Exclude your backup and AV processes by name in the rule's
   `filter_backup` if they read the files.
3. **Canary cloud credentials.** Create an IAM user with **no policies
   attached**, create one access key, and plant it in a believable place
   (an old config backup, a deploy script). Never put a working credential
   with permissions in a decoy. CloudTrail logs even denied calls, which is
   all the rule needs.
4. **Edit the rules** with your decoy names, bump each rule's version, and add
   a `RULE_CHANGELOG.md` entry (the version test enforces this).
5. **Test** once per quarter: trigger each decoy deliberately in an announced
   window and confirm the alert. Record the window so the alert is closed as
   a test, not an incident.

## What this does not do

- It does not emulate services or run a network honeypot. A low-interaction
  honeypot (e.g. OpenCanary) can feed alerts through `POST /api/ingest`; no
  such integration is shipped or tested here.
- Decoy names in a public repository are known to anyone who reads it. Use
  different names in any real deployment.
