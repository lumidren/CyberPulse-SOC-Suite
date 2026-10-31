# Repository History Secret Scan

**Scanned:** 2026-10-31, all branches, 81 commits (`git log -p --all`).
**Tool:** `scripts/scan_history_secrets.py` (credential patterns for AWS, GitHub,
Slack, Discord/Slack webhooks, private keys, VirusTotal/AbuseIPDB keys, plus a
high-entropy check on `password/secret/api_key/token` assignments).
gitleaks and trufflehog were not available on the scanning machine; the
gitleaks CI job (`.github/workflows/detection_ci.yml`, job `secret-scan`)
covers every future push, but **its first run has not been observed yet**.

## Findings

| Commit | Finding | Assessment |
| :--- | :--- | :--- |
| `6c9a312` | Dev API key `cyberpulse-dev-secret-key-2026` in `web/app.js` | Published development placeholder (documented in the README at the time), not a credential for any real system. Removed from the code in E65/E72. |
| `2c9779d` | `WINRM_PASSWORD=SecretWinRMPassword!` in `.env.example` | Sample value in an example file, never a real password. Replaced with `change-me` in E72. |

No real credentials, cloud keys, tokens, webhook secrets or private keys were
found. Because both findings were placeholders, **no rotation is required**,
and history is not rewritten (rewriting published history would break clones).

If you ever used either placeholder as a real password or key on a lab
system, rotate it there.

## Re-running

```bash
python scripts/scan_history_secrets.py               # reports placeholders too
python scripts/scan_history_secrets.py --allow-known # CI mode: fails only on new findings
```
