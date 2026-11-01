# LLM-Assisted Triage Summary

Roadmap F96. A Claude model can draft a short triage summary for one incident. It is
**off by default**, it only drafts, and nothing it writes reaches the record or changes
anything until an analyst accepts it.

> **Not verified against the live API.** The request is built with the official `anthropic`
> Python SDK and tested with a stub client (`tests/test_llm_triage.py`). No request has been
> sent to the Claude API from this repository, and the quality of the summaries has not been
> measured.

## What the analyst keeps

- The draft is stored as `llm_summary` with status `DRAFT` and `advisory: true`.
- Only `accept` (optionally with edited text) or `reject` from a named analyst ends it. An
  accepted summary is added as an analyst note labelled *AI-drafted by <model>, reviewed by
  <analyst>*, with *edited* when the text was changed; the original draft is kept.
- The model is never asked to choose an action, and its text is never parsed: a draft
  that says "approve isolation" approves nothing. Containment still goes through the normal
  approval workflow.
- Requests, acceptances and rejections are written to the hash-chained action ledger along
  with the model and the list of fields sent. Each request is also audit-logged.

## What is sent

Only a pseudonymised view (`soar.llm_triage.build_payload`):

| Sent | Never sent |
| :--- | :--- |
| Incident id, rule id and name, severity, ATT&CK technique | Host names, user names, internal IPs |
| Host **pseudonym** (`host-1a2b3c4d`, keyed HMAC) | Command lines, process paths, PIDs, raw events, logs |
| Source IP only if public or RFC 5737 documentation, otherwise "internal" | Analyst notes, evidence, case contents |
| Risk score, level and factor values; whether intel was corroborated | |
| Policy decision, playbook name, proposed action type and status | |
| The rule's description and known false positives (from its Sigma file) | |
| Counts of timeline events and observables | |

Before anything is sent, `find_leaks` scans the serialised payload for the incident's own
host and user values (raw and JSON-escaped) and for any private IPv4 address. A hit refuses
the request with HTTP 400. Nothing is sent automatically: each request is one analyst action.

## Enabling it

```bash
pip install anthropic
export LLM_TRIAGE_ENABLED=true
export ANTHROPIC_API_KEY=<your key>
# optional
export LLM_TRIAGE_MODEL=claude-opus-5-5   # default
export LLM_TRIAGE_TIMEOUT=60              # seconds
```

You are bound by Anthropic's terms for the key you supply. Each request is one Messages API
call with `output_config.effort: low` and up to 4,000 output tokens. It opts into server-side
refusal fallbacks (`fallbacks: "default"`, beta `server-side-fallback-2026-07-01`). A refusal
from the whole chain is stored as status `REFUSED` with no text. The SDK retries twice on
transient errors.

## API

| Method | Path | Body | Result |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/incidents/<id>/llm-summary` | | `{enabled, llm_summary}` |
| `POST` | `/api/incidents/<id>/llm-summary` | `{"analyst": "a.name"}` | Draft (503 when disabled or not configured) |
| `POST` | `/api/incidents/<id>/llm-summary/review` | `{"analyst", "decision": "accept" or "reject", "text"?}` | Accepted or rejected record |

Leads and analysts may request and review drafts; auditors can only read them.

## Limits

- The summary only knows the pseudonymised fields, so it cannot reason about the specific
  host or account. That is intended.
- The rule description sent to the model is repository text, and the event's free-text
  fields are not sent. That limits, but does not rule out, prompt injection through rule
  content you write yourself.
- A language model can state things that are not in its input. Treat every draft as a
  starting point, which is why acceptance is a separate, recorded step.
