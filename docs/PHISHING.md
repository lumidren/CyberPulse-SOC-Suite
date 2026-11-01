# Phishing: Detection, Quarantine and Triage

## Detection and quarantine (roadmap F45)

`SOC-RULE-050` (`rules/sigma/email_phishing_reported_or_auth_fail.yml`) fires on a
delivered message that a recipient reported, or that failed DMARC and carries a link or
attachment. It reads **message metadata only** (Microsoft 365 `EmailEvents`-style fields:
sender, recipient, subject, authentication results, URLs, attachment hashes, delivery
action), sent as `event_source: m365:email`; message bodies are never ingested.

The `phishing` playbook (`playbooks/phishing.yml`) proposes `QUARANTINE_EMAIL`, which
moves the one message to a `CyberPulseQuarantine` folder through Microsoft Graph
(`POST /users/{upn}/messages/{id}/move`). It is TIER_2: always analyst-approved, even in
opt-in automatic mode, because quarantining a real invoice disrupts a person. Rollback
moves the message back to the inbox (FULL reversibility).

A user report usually scores *medium* risk, so the policy only alerts. To act anyway, an
analyst proposes the playbook's action on the incident:

```
POST /api/incidents/<incident_id>/propose   {"analyst": "alice"}            # playbook action
POST /api/incidents/<incident_id>/propose   {"analyst": "alice", "action": "QUARANTINE_EMAIL"}
```

The proposal is staged `PENDING_ANALYST_APPROVAL` and still needs an approval, where the
kill switch, protected accounts and rate limits apply. The responder is **simulated**: it
builds and records the Graph request but does not call Graph.

## Triage (roadmap F46)

Every email incident gets `phishing_triage` (`soar/phishing_triage.py`), computed offline
from the metadata already in the event (no body, no network calls):

- **Authentication:** SPF, DKIM and DMARC results from `AuthenticationResults`.
- **Sender:** Reply-To on another domain; a display name that embeds a different address
  or names a watched person (`PHISHING_WATCHED_NAMES`) on external mail; look-alikes of
  your domains (`PHISHING_ORG_DOMAINS`) by edit distance, character swaps (rn/m, 0/o, 1/l),
  punycode or embedding (`corp-example-billing.net`).
- **URLs:** raw IP hosts, punycode, `@` tricks, shorteners, look-alike hosts and links to a
  domain other than the sender's, all shown defanged (`hxxps://evil[.]example`).

The result is a 0-100 score with the reason for every point and a verdict (`likely
phishing`, `suspicious`, `no strong indicators`). It informs the analyst; it never acts.
A low score does not make a message safe. URL detonation is opt-in through the lab
sandbox (F47).
