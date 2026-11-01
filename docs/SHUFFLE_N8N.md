# Shuffle or n8n as the Orchestrator

Roadmap F40. **Off by default; tested with a stubbed HTTP layer only.**

Set `ORCHESTRATOR_WEBHOOK_URL` to a Shuffle or n8n webhook trigger and
`ORCHESTRATOR_WEBHOOK_SECRET` to a shared secret. Each incident is then POSTed as JSON,
and the result is recorded on the incident as `orchestrator_dispatch`.

**Verify the signature in the first workflow step.** Headers:
`X-CyberPulse-Timestamp` and `X-CyberPulse-Signature: sha256=<hex>`, where the digest is
HMAC-SHA256 with the secret over `timestamp + "." + raw body`; reject requests older
than five minutes. (Same scheme as `POST /api/ingest`; see `soar/ingest_auth.py`.)

| Webhook location | Payload |
| :--- | :--- |
| Lab address (private, loopback, `*.lab` / `.local` / `.internal` / `.test`) | incident and case ids, rule, policy decision, response (action id, type, status), observables, redacted telemetry, `approve_url` |
| Anything else (e.g. hosted n8n) | the pseudonymised summary used for chat (no host names, accounts or internal IPs) |

**Acting back.** A workflow approves or rejects a staged action through the normal API
with an API key: `POST /api/approvals/<action_id>/approve` (or `/reject`) with
`{"approver": "...", "comment": "..."}`. Approval in CyberPulse is still a human
decision: make the workflow ask a person (for example a Shuffle user-input step or an n8n
*Wait for approval* node) before it calls the approve endpoint. The kill switch,
protected assets, rate limits and TTLs apply exactly as for console approvals.
