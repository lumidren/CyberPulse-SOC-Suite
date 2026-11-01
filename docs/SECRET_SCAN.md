# Repository History Secret Scan

**Scanned:** 2026-10-31, all branches, 81 commits (`git log -p --all`).
**Tool:** `scripts/scan_history_secrets.py` (credential patterns for AWS, GitHub,
Slack, Discord/Slack webhooks, private keys, VirusTotal/AbuseIPDB keys, plus a
high-entropy check on `password/secret/api_key/token` assignments).
gitleaks and trufflehog were not available on the scanning machine; the
gitleaks CI job (`.github/workflows/detection_ci.yml`, job `secret-scan`)
covers every push. It has run on GitHub since; see the 2026-11-01 update below.

## Findings

| Commit | Finding | Assessment |
| :--- | :--- | :--- |
| `c7cb58e` | Dev API key `cyberpulse-dev-secret-key-2026` in `web/app.js` | Published development placeholder (documented in the README at the time), not a credential for any real system. Removed from the code in E65/E72. |
| `0a0b256` | `WINRM_PASSWORD=SecretWinRMPassword!` in `.env.example` | Sample value in an example file, never a real password. Replaced with `change-me` in E72. |

No real credentials, cloud keys, tokens, webhook secrets or private keys were
found. Because both findings were placeholders, **no rotation is required**.

If you ever used either placeholder as a real password or key on a lab
system, rotate it there.

## Update, 2026-11-01

- On 2026-11-01 the owner rewrote the history once, to put every commit under
  one author identity. File contents did not change, but every commit hash did.
  The commit ids above are the rewritten ones (`6c9a312` became `c7cb58e`, and
  `2c9779d` became `0a0b256`).
- The history scan in CI flagged `secret_token=<TELEGRAM_WEBHOOK_SECRET>` in the
  ChatOps docs (`4f36231`). That is a template, not a value, and `--allow-known`
  now skips all-caps `<NAME>` templates.
- gitleaks flagged `token=aB3dE5gH7jK9mN1p` in `tests/test_secret_hygiene.py`
  (`c6c3f71`). It was an invented example of a non-placeholder value. The test now
  generates a random one each run, and the old value is allowlisted in
  `.gitleaks.toml` and in the history scanner.

## Re-running

```bash
python scripts/scan_history_secrets.py               # reports placeholders too
python scripts/scan_history_secrets.py --allow-known # CI mode: fails only on new findings
```
