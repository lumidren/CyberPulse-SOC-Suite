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
| Enrichment cache (LRU) | Server process memory, at most `ENRICHMENT_CACHE_SIZE` (512) entries | `ENRICHMENT_CACHE_TTL_SEC` (1 h) per entry; emptied on restart or by `POST /api/enrichment/cache/clear` | Public IPs / file hashes and the verdicts providers returned; nothing else |
| Dashboard sessions | Server process memory | `SESSION_TTL_MIN` (default 8 h) | Random session token, CSRF token, timestamps (no personal data) |
| Operational + audit log | stderr, plus `LOG_FILE` if set | stderr: your log pipeline decides. `LOG_FILE`: rotated daily, `RETENTION_DAYS` files kept | Client IPs, actions, approver names, incident IDs |

There is no database: restarting the server erases incident data.

## Personal data

* The demo directory (`soar/identity_graph.py`) and all simulated events use
  **invented** accounts and hosts. No real employee, client or internship data
  is included anywhere in this repository.
* The identity graph, blast-radius analysis and BloodHound export always run
  on that synthetic directory; their API responses carry a `data_source`
  field saying so and the console labels the card **SYNTHETIC DIRECTORY**.
  Ingested telemetry never populates the directory.
* If you ingest real telemetry, events will contain real usernames, hostnames
  and command lines. Treat the server as holding personal data: restrict who
  can sign in, keep it on loopback or behind TLS, and limit retention.

## Who can view telemetry

Incident data contains the underlying Sysmon/Security event fields. Anyone
holding the API key, or a dashboard session created with it, can read it;
there is no finer-grained role yet. Every read of a telemetry-bearing
endpoint (`/api/incidents*`, `/api/alerts`, `/api/approvals`, `/api/syslog*`)
writes a `DATA_ACCESS` audit-log line with the client IP and how the caller
authenticated (`api-key` or `session`). Review those lines to see who viewed
the Sysmon streams, and share the API key only with people who need it.

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

* Notification webhooks (Discord/Slack/custom), only if you configure a URL; SSRF-guarded.
  Messages carry the incident id, rule, severity, technique, a host **pseudonym**
  (`host-1a2b3c4d`, keyed HMAC; set `CYBERPULSE_PSEUDONYM_KEY` for stable labels across
  restarts), a public or documentation source IP (internal IPs are withheld) and the
  response status. No hostnames, usernames, internal IPs or execution logs; circuit-breaker
  pages give the host count, not the host list.
* Optional user sign-in notifications (`USER_NOTIFY_ENABLED`, off by default): an email to
  the affected account's address from your own address book, over STARTTLS, with no
  links and no incident details; never for simulated events, service or protected
  accounts, and at most once per account per day.
* External threat-intel enrichment and the related health-check probes are
  **off by default** (`EXTERNAL_ENRICHMENT_ENABLED=false`, or toggle at runtime
  with `POST /api/enrichment/config`). While off, nothing is sent to
  VirusTotal or AbuseIPDB, not even a reachability probe.
* Optional LLM triage drafts (`LLM_TRIAGE_ENABLED`, off by default, one request per analyst
  action): the same pseudonymised fields as the webhooks plus risk factors and the rule's
  description, sent to the Anthropic API. A leak check refuses any payload containing the
  incident's host, user or a private IP ([LLM_TRIAGE.md](LLM_TRIAGE.md)).
* Otherwise, no incident data is sent to any third party unless you configure an integration.

## External threat-intel enrichment: what leaves your environment

When you turn enrichment on (`EXTERNAL_ENRICHMENT_ENABLED=true` plus an API
key), the following **leaves your environment** and is processed by a third
party under *their* terms and retention policies, not yours:

| Provider | Sent | Never sent |
| :--- | :--- | :--- |
| VirusTotal (`www.virustotal.com`, API v3) | Public source IP addresses; MD5/SHA-1/SHA-256 file hashes; your API key | Internal/RFC 1918 IPs, hostnames, usernames, command lines, file names, file contents (no file is uploaded) |
| AbuseIPDB (`api.abuseipdb.com`, API v2) | Public source IP addresses; your API key | Everything else listed above |

Things to weigh before enabling it:

* A lookup tells the provider that *your* API key is interested in that IP or
  hash. Querying an attacker's own infrastructure can, in principle, be seen
  by them if they monitor such services.
* Providers may log queries; you cannot delete them from this lab.
* The guards are enforced in code (`soar/enrichment.py`): non-routable IPs and
  any non-hash value are refused before a request is built, and tests replay
  every scenario to check that no hostname or username reaches a URL.

