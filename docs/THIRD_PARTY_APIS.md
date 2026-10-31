# Third-Party API Use: Terms, Limits and Attribution

CyberPulse can optionally query **VirusTotal** and **AbuseIPDB**. Both are off
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
