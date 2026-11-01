# ChatOps Approvals (Slack, Teams, Telegram)

Roadmap F31. Approve or reject a staged containment action from chat. A button
press is a **human approval**: it goes through the same `approve_action` path
as the console, so the kill switch, protected assets/accounts, rate limits and
TTLs all still apply. Nothing becomes automatic.

| Platform | Buttons | Callback | Authentication |
| :--- | :--- | :--- | :--- |
| Slack | Approve / Reject (Block Kit) | `POST /api/chatops/slack` | Slack signing secret (`SLACK_SIGNING_SECRET`), v0 HMAC, 5-minute replay window |
| Telegram | Inline keyboard | `POST /api/chatops/telegram` | `X-Telegram-Bot-Api-Secret-Token` = `TELEGRAM_WEBHOOK_SECRET` |
| Teams | "Review in console" | none (opens the console) | Incoming-webhook cards cannot call back without a registered bot |

Only users listed in `CHATOPS_APPROVERS` (`slack:U0123ABCD,telegram:123456789`)
can decide; every attempt, allowed or refused, is written to the audit log.
Messages and replies use host pseudonyms and never include host names,
usernames or internal IPs, because they travel through an external service.
When an approval cannot be applied, the reply says so without the reason; the
reason is in the console and audit log.

## Setup (your workspace, your bot)

1. **Slack:** create an app with *Interactivity* enabled, request URL
   `https://<your-soc-host>/api/chatops/slack`, and copy its signing secret to
   `SLACK_SIGNING_SECRET`. The CyberPulse server must be reachable from Slack,
   for example through a reverse proxy with TLS; do not expose the whole API.
2. **Telegram:** create a bot with BotFather, then register the webhook with
   `setWebhook` (`url=https://<your-soc-host>/api/chatops/telegram`,
   `secret_token=<TELEGRAM_WEBHOOK_SECRET>`).
3. Put the approvers' platform user ids in `CHATOPS_APPROVERS`.

Message builders: `slack_approval_message`, `telegram_approval_message` and
`teams_approval_card` in `soar/chatops.py`.

**Not verified:** tested with locally signed requests only; no real Slack app
or Telegram bot has been connected.
