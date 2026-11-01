# MISP IoC Sharing

Roadmap F37. **Off by default; needs your MISP.** Tested with a stubbed HTTP layer only.

| Endpoint | What it does |
| :--- | :--- |
| `GET /api/cases/<id>/misp` | Preview the MISP event a case would produce (nothing is sent) |
| `POST /api/cases/<id>/misp/push` | Create the event in MISP; needs `MISP_SHARING_ENABLED=true`, `MISP_URL` (https) and `MISP_API_KEY` |

What is shared: **public IP addresses and SHA-256 hashes only**, each `to_ids` with the
rule id and ATT&CK technique as comment. Never host names, accounts, internal IPs,
command lines or telemetry. Events are created with distribution 0 (your organisation
only) and `tlp:amber`; widening distribution is a decision for a human in MISP.

Synthetic indicators from the simulator would pollute a sharing community, so simulated
incidents are skipped (the response says how many). Pushing is never automatic: an
analyst calls the push endpoint, and the push is written to the audit log.

`MispClient.fetch_iocs(last="1d")` reads `to_ids` IP and hash attributes from
`/attributes/restSearch`, keeping only public IPs and valid hashes, for use as a local
blocklist.
