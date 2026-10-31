# SOAR Service Account: Least Privilege

CyberPulse's responders are simulated in this lab. If you wire them to real
systems, run them as a **dedicated service account** with only the rights each
action needs. Never use Domain Admin, the built-in `Administrator`, or a
person's account.

| Item | Recommendation |
| :--- | :--- |
| Account | `CORP\svc_cyberpulse_soar` (already on the protected-accounts list, so SOAR can never lock itself out) |
| Interactive logon | Denied (`Deny log on locally`, `Deny log on through RDP`) |
| Password | Long random secret in a vault, rotated; prefer a gMSA where possible |
| Group membership | No privileged groups (not Domain Admins, Account Operators, Server Operators, Backup Operators) |

## Rights per action

| Action | Minimum right | How to grant |
| :--- | :--- | :--- |
| Host isolation / firewall rule (`New/Remove-NetFirewallRule`) | Run only the allowlisted cmdlets on endpoints | A **JEA** endpoint (`Register-PSSessionConfiguration`) exposing exactly the cmdlets in `soar/command_builder.py::PS_CMDLETS` |
| Process termination | Terminate processes via the JEA endpoint | Same JEA role; no local admin needed for `taskkill` on user processes, local admin only where policy requires |
| Scheduled-task export/disable | `schtasks /Query /XML`, `/Change /DISABLE` | JEA role with those commands only |
| Account disable/enable | *Disable/Enable account* on the user OUs only | AD delegation on `OU=Users` (not the domain root, never on Tier 0 OUs) |
| Password reset / force change | *Reset password* + *write pwdLastSet* on service-account OUs | AD delegation scoped to the service-account OU |
| Replication-rights removal | *Modify permissions* on the domain object | Separate, tightly held identity; this is a Tier 0 change, so keep it manual (approval-required, never auto) |
| Perimeter IP block (pfSense) | Firewall-rule API privilege only | pfSense user with `WebCfg - Firewall: Rules` only |
| AWS session revocation | `iam:PutUserPolicy`, `iam:DeleteUserPolicy` on a user path | IAM policy with a resource ARN constraint |
| Entra session revocation | `User.RevokeSessions.All` (application) | App registration with only that Graph permission |

## Enforced by the code

`soar/responder_config.py::validate_identity` (shown in `GET /api/health`)
refuses responder identities that look privileged (`Administrator`, `Domain
Admins`, `admin`, `root`, `krbtgt`) and warns if the account is not a
dedicated `svc_` account.
