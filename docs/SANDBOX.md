# Sandbox Submission

Roadmap F47. **Lab sandbox only, off by default; tested with a stubbed HTTP layer only.**

`soar/sandbox.py` talks to a self-hosted [CAPE](https://github.com/kevoreilly/CAPEv2)
sandbox (`/apiv2`). Public sandboxes are refused by design: a sample can contain personal
or customer data, and public reports are visible to everyone, including whoever sent it.
`SANDBOX_URL` must be a lab address (private, loopback or `*.lab`/`.local`/`.internal`/`.test`).

| What | When | Setting |
| :--- | :--- | :--- |
| Look up existing analyses of a SHA-256 seen in the event | every incident with a file hash or attachment hash | `SANDBOX_URL` (+ `SANDBOX_API_TOKEN`) |
| Detonate phishing URLs | only if opted in: visiting a link can tip off the sender | `SANDBOX_AUTO_DETONATE_URLS=true` |
| Submit a collected file | on request (`SandboxClient.submit_file`), only from the evidence folder | `SANDBOX_EVIDENCE_DIR` |

Results are attached to the incident as `sandbox` (task ids to open in CAPE). Failures
never stop the pipeline. CyberPulse collects telemetry, not files, so file submission
depends on your EDR or the triage package (F49) placing samples in
`SANDBOX_EVIDENCE_DIR`; paths outside it are refused, so the API cannot be used to read
other files on the host.
