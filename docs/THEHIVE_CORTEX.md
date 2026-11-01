# TheHive 5 and Cortex

Roadmap F36. **Off by default; needs your own TheHive/Cortex.** Tested against a
stubbed HTTP layer only, never a running server.

## TheHive

Set `THEHIVE_ENABLED=true`, `THEHIVE_URL` and `THEHIVE_API_KEY` (an API key of a
TheHive user with the *analyst* profile). Every new incident is then sent as a
TheHive alert (`POST /api/v1/alert`):

- `sourceRef` = the CyberPulse case id (F35), so alerts of one intrusion can be merged
  into one TheHive case;
- title, severity (1-4), tags (`rule:`, `attack:`, `simulated`), and a description with
  rule, technique, risk, response status and the playbook task list;
- observables with **PAP:RED and an `internal` tag for host names, accounts and internal
  IPs**, PAP:AMBER for public IPs and file hashes, so Cortex analyzers that call outside
  services are not run on internal identifiers.

`THEHIVE_URL` must be a lab address (private, loopback, or `*.lab`/`.local`/`.internal`/
`.test`); anything else is refused. Failures never stop the pipeline: the result is
recorded on the incident as `thehive_sync` (`DISABLED`, `SENT`, `REFUSED` or `ERROR`).
Without TheHive, the incident still carries a local case record in TheHive 5 format.

## Cortex

`CortexClient.run_analyzer(analyzer_id, value)` (`CORTEX_URL`, `CORTEX_API_KEY`, lab
address only) runs a Cortex analyzer on a **public IP or file hash only**; any other
value is refused before a request is made. Analyzers that contact third parties
(VirusTotal, AbuseIPDB, ...) are subject to those services' terms and rate limits,
exactly as in [THIRD_PARTY_APIS.md](THIRD_PARTY_APIS.md).
