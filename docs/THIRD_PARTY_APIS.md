# Third-Party API Use: Terms, Limits and Attribution

CyberPulse can optionally query **VirusTotal** and **AbuseIPDB**, and (F41) **AlienVault
OTX**, **URLhaus**, **GreyNoise**, **Shodan** and **Censys**. All are off
by default (`EXTERNAL_ENRICHMENT_ENABLED=false`). If you enable them you are
bound by each provider's terms, and you supply your own API keys.

> **Verify before relying on this page.** The summaries below reflect the
> providers' published terms as understood when this was written (2026-11).
> Terms, quotas and plan names change; the provider's own documentation always
> wins. Links: VirusTotal Terms of Service and API documentation
> (<https://docs.virustotal.com/>), AbuseIPDB API documentation and terms
> (<https://www.abuseipdb.com/>).

## VirusTotal (API v3)

* **Public API is for non-commercial use.** The free Public API may not be
  used in commercial products or services, or for commercial purposes.
  Commercial use requires a Premium (private) API licence.
* The code enforces this: with `VIRUSTOTAL_API_TIER=public` (default) and
  `CYBERPULSE_COMMERCIAL_USE=true`, the client refuses every VirusTotal lookup.
  Set `VIRUSTOTAL_API_TIER=premium` only if you hold a Premium licence.
* Lookups only: CyberPulse never uploads files or URLs to VirusTotal.
* **Rate limit: 4 requests per minute** on the Public API, plus daily and
  monthly quotas. The client enforces `VT_RATE_LIMIT_PER_MIN=4` and
  `VT_DAILY_QUOTA` (default 500) *before* sending, so the limits are never
  exceeded by CyberPulse. Over-limit lookups return `RATE_LIMITED` with a
  `retry_after_sec` instead of a request. After an HTTP 429 or 5xx the client
  backs off exponentially (60 s, 120 s, ... capped at 15 min).

## AbuseIPDB (API v2)

* **Daily quotas per plan.** The free plan allows a limited number of `check`
  requests per day (1,000 at the time of writing). Set
  `ABUSEIPDB_DAILY_QUOTA` to your plan's limit; the client stops sending once
  it is reached and returns `RATE_LIMITED`. HTTP 429/5xx responses trigger the
  same exponential backoff as for VirusTotal.
* Only the `check` endpoint is used, with `maxAgeInDays=90`. CyberPulse never
  *reports* IPs to AbuseIPDB (no `report` calls), so it cannot submit false
  abuse reports about anyone.
* Check AbuseIPDB's terms for attribution and redistribution rules.
  CyberPulse attributes every AbuseIPDB verdict it displays and does not
  redistribute their data (see the sections below).

## OTX, URLhaus, GreyNoise, Shodan, Censys (F41)

Each is enabled by its own key and goes through the same client as VirusTotal and
AbuseIPDB: external enrichment must be on, only public IPs and file hashes are sent,
answers are cached, and failures degrade to `UNAVAILABLE`. Client-side limits are
conservative defaults; set them to your plan with `<NAME>_RATE_LIMIT_PER_MIN` and
`<NAME>_DAILY_QUOTA` (names below). None has been called with a real key from this repo.

| Provider | Key variable(s) | Sends | Default limits | Used as |
| :--- | :--- | :--- | :--- | :--- |
| AlienVault OTX | `OTX_API_KEY` | IP, hash | 60/min, 10000/day | reputation (pulse count; flags at 3+ pulses) |
| URLhaus (abuse.ch) | `URLHAUS_AUTH_KEY` | IP (host), SHA-256 | 30/min, 5000/day | reputation (malware URLs hosted / known payload) |
| GreyNoise Community | `GREYNOISE_API_KEY` | IP | 10/min, 50/day | reputation (`malicious` flags; `benign`/RIOT never flags) |
| Shodan | `SHODAN_API_KEY` | IP | 60/min, 100/day | **context only** (ports, CVEs), never scored |
| Censys Search v2 | `CENSYS_API_ID`, `CENSYS_API_SECRET` | IP | 10/min, 250/day | **context only** (services), never scored |

Several of these have free tiers restricted to non-commercial or community use
(GreyNoise Community, Shodan, Censys); check each provider's terms for your use before
setting a key. Shodan takes its key as a query parameter by design; it is never logged by
CyberPulse. Censys has been moving users to its newer Platform API, so the v2 endpoint
may need updating.

## Attribution

Every verdict from a provider carries an `attribution` string naming the
source and linking to it. The console shows these under the incident's
observables, and the NIST-style report lists them under *Threat-intel
sources*. When no external lookup was made, both say the result came from the
synthetic lab fixture only.

## No redistribution

* Provider responses live only in the in-memory cache (`IocCache`); nothing is
  written to disk, and the cache empties on restart.
* Dossier exports (`start_lab.py` option 7) strip `threat_intel.external`
  before writing (`soar.enrichment.strip_provider_data`).
* The threat-intel fixture committed in `soar/soar_engine.py` is synthetic lab
  data (RFC 5737 IPs, fictional providers), not derived from either provider.
* `tests/test_enrichment.py` fails if provider response data is committed
  anywhere outside the enrichment client and its tests.

## When enrichment fails

* A provider outage, timeout or HTTP error becomes an `UNAVAILABLE` verdict;
  it never crashes the pipeline, and it triggers the provider's backoff.
* If enrichment is degraded (any provider unavailable, rate-limited or refused
  by terms), **no containment runs automatically**: AUTOMATIC mode stages it
  for an analyst instead.
* Containment never runs automatically on reputation alone: if the risk score
  would stay below the containment threshold without the threat-intel factor
  (`score_without_intel`), an analyst must approve.

## Corroboration

No single reputation score triggers containment. `soar/reputation.py`
combines all signals (live verdicts plus the lab fixture's two simulated
signals); the threat-intel factor counts at full weight only when at least two
independent sources flag the indicator, otherwise at half weight with
`corroborated: false`. Together with the intel-alone rule above, one
provider's opinion can never block an address by itself.

