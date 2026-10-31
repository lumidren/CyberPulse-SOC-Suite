# Privacy & Data Handling

CyberPulse is a lab. Out of the box it only processes **synthetic** data that
its own simulator generates. This page states what it stores, where, for how
long, and what changes if you feed it real telemetry.

## What is stored

| Data | Where | Lifetime | Contents |
| :--- | :--- | :--- | :--- |
| Incidents (alert, telemetry, risk, actions, notes) | Server process memory | Until restart, or `RETENTION_DAYS` (default 30), whichever is first | Hostnames, usernames, IPs, process paths and command lines from the triggering event |
| Containment action records | Server process memory | Deleted with their incident (`RETENTION_DAYS`) | Targets, approvals (approver name, comment), rollback records |
| Syslog / webhook events | Server process memory, capped at `SYSLOG_MAX_EVENTS` (10,000) | `RETENTION_DAYS`, or earlier when the cap is reached | Normalised event fields |
| Dashboard sessions | Server process memory | `SESSION_TTL_MIN` (default 8 h) | Random session token, CSRF token, timestamps (no personal data) |
| Operational + audit log | stderr, plus `LOG_FILE` if set | stderr: your log pipeline decides. `LOG_FILE`: rotated daily, `RETENTION_DAYS` files kept | Client IPs, actions, approver names, incident IDs |

There is no database: restarting the server erases incident data.

## Personal data

* The demo directory (`soar/identity_graph.py`) and all simulated events use
  **invented** accounts and hosts. No real employee, client or internship data
  is included anywhere in this repository.
* If you ingest real telemetry, events will contain real usernames, hostnames
  and command lines. Treat the server as holding personal data: restrict who
  can sign in, keep it on loopback or behind TLS, and limit retention.

## Data minimisation

Ingested events keep only the top-level fields the pipeline uses and an
allowlist of detail fields read by detection rules, risk scoring and the
triage views (`soar/input_validation.py::DETAIL_FIELD_ALLOWLIST`). Anything
else is dropped before storage; the ingest response lists the dropped field
*names* (never their values). Extend the list with `INGEST_EXTRA_FIELDS` only
when a new rule needs a field.

## Never commit real telemetry

Only synthetic data belongs in this repository. Real event logs (`.evtx`,
`.etl`), packet captures (`.pcap`/`.pcapng`), memory dumps (`.dmp`), server
logs and exported dossiers are git-ignored, and `tests/test_no_real_telemetry.py`
fails CI if one is ever tracked. If you need a sample, generate it with
`simulator/` or anonymise it fully first.

## Masking

Account names are **masked by default** in the console, in API responses that
carry incident data, and in generated reports (`CORP\j.doe` -> `CORP\j***e`),
so demos and screenshots never show them. Detection, scoring and containment
use the real values server-side. Set `PRIVACY_MASK_USERNAMES=false` only when
you need full names for a real investigation. Take screenshots with masking on.

## What leaves the machine

* Notification webhooks (Discord/Slack), only if you configure a URL; SSRF-guarded.
* The integration health check (`GET /api/health`) currently sends reachability
  probes to `api.virustotal.com` and `api.abuseipdb.com`. No indicator or
  personal data is included, but the request itself reveals that this host
  runs the lab.
* No incident data is sent to any third party.
