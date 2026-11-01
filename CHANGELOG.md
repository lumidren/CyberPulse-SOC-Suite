# Changelog

All notable changes to CyberPulse SOC Suite are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Automation behaviour

Every change to what CyberPulse does automatically is listed here (roadmap E100). The
fingerprint below covers action tiers, reversibility, rule-to-action mapping, rule
confidence, risk weights, safety limits, playbooks, role restrictions and exception
lifetimes (`python scripts/automation_fingerprint.py`); the test suite fails if it changes
without a new entry here.

- **Correlation rules** (SOC-RULE-043/044/045) can now raise incidents and propose
  `BLOCK_SOURCE_IP_FIREWALL` or ransomware containment, subject to the usual policy.
- **Rule exceptions** suppress matching alerts until they expire (at most 180 days);
  EXC-0001 and EXC-0002 suppress two benign baseline patterns.
- **YAML playbooks** choose the proposed action and may force approval or a minimum risk;
  they can only make handling more conservative. Opt-in automatic mode keeps running the
  TIER_1 firewall block for brute force.
- **ChatOps**: listed Slack/Telegram users can approve or reject staged actions (same checks
  as the console).
- **Email quarantine** (`QUARANTINE_EMAIL`, TIER_2, always approved) is proposed for
  reported or DMARC-failing phishing; analysts can propose a playbook action on any incident.
- **Entra ID responder** revokes sessions and adds the account to an MFA step-up group when
  `ENTRA_RESPONDER_ENABLED=true` (TIER_3, always approved); otherwise simulated.
- **Roles**: only leads can approve, reject, change policy or enrichment, release the kill
  switch, push to MISP or decide appeals; auditors are read-only.
- **User notification** emails about suspicious sign-ins, off by default, never for
  simulated events.
- **Hand-offs** to TheHive, Shuffle/n8n and the lab sandbox happen automatically when
  configured (all off by default); none of them can execute containment.
- **Action ledger**: every containment decision and kill-switch change is recorded in a
  hash-chained ledger.
- **Network detections** (SOC-RULE-051 Suricata severity-1 alerts, SOC-RULE-052 executables over HTTP from script clients or raw IPs) raise alert-only incidents from signed Zeek/Suricata batches.

Automation fingerprint: `f87517ccf5c6e668`

## [2.5.0] - 2026-10-31

### Fixed
- **Routing**: `GET /api/incidents/{id}/attack-graph`, `/evidence`, `/ai-analysis`,
  `/identity`, and `/report` were shadowed by the generic incident-detail route and
  always returned `404 Incident not found`. Sub-resource routing is now dispatched
  explicitly and covered by integration tests.
- The NIST report endpoint no longer sends `Access-Control-Allow-Origin: *`; it uses
  the same origin-restricted CORS policy as every other endpoint.
- `POST .../rollback` on an incident without a recorded containment action now
  returns `409` instead of raising internally.
- Added the missing `rules/sigma/win_powershell_obfuscation.yml` referenced by
  SOC-RULE-004 in the detection catalogue.

### Added
- **Production mode** (`CYBERPULSE_ENV=production`): the server refuses to start
  without an explicit `CYBERPULSE_API_KEY` (no dev default key in production).
- **Rate limiting**: per-client sliding-window limiter for all `/api/*` traffic and
  a stricter throttle on repeated authentication failures (both configurable).
- **Request hardening**: 1 MiB request-body cap (`413`), strict JSON body
  validation (`400`), and baseline security headers on every response.
- **SSRF guard** on analyst-supplied webhook URLs: only `http(s)` targets, with
  private/loopback/link-local addresses blocked by default
  (`ALLOW_INTERNAL_WEBHOOKS=true` to opt out).
- **Observability**: structured logging, a dedicated audit log for state-changing
  actions (simulate, rollback, policy change), unauthenticated `/healthz` liveness
  probe, and `GET /api/version`.
- **Pagination** (`limit`/`offset`) on `GET /api/incidents`.
- **Concurrency**: the API now runs on `ThreadingHTTPServer`; a slow client no
  longer blocks the entire console. Graceful shutdown on SIGINT/SIGTERM.
- **Deployment**: hardened Dockerfile (non-root user, pinned deps, container
  healthcheck), compose healthcheck plus required `CYBERPULSE_API_KEY` wiring.
- **CI**: Python 3.10–3.12 test matrix, flake8 critical-error lint, full
  dependency install, and a detection-catalogue reference integrity check.
- **Tests**: new live-server REST API integration suite (auth, routing,
  pagination, payload limits, security headers, rate limiter, SSRF validator).
- Project hygiene: `.gitignore`, `LICENSE` (MIT), `SECURITY.md`, this changelog;
  removed committed `__pycache__` artifacts.

### Changed
- API key comparison is now timing-safe (`hmac.compare_digest`).
- `HOST`/`PORT` and logging level are environment-driven, matching `.env.example`.

## [2.4.0] - 2026-09-09

Historical baseline: closed-loop detection engineering, SOAR containment and
rollback, purple team replay, DFIR dossiers, identity blast radius, BloodHound
export, WDAC/BYOVD coverage, cloud detections, and the web console.
