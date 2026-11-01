# Triage Package

Roadmap F49. `GET /api/incidents/<id>/triage-package` returns a zip with everything needed
to start working an incident (`soar/triage_package.py`):

| File | Content |
| :--- | :--- |
| `incident.json` | the incident record, third-party intel payloads removed (provider terms) |
| `telemetry.json` | the triggering event, redacted as stored |
| `timeline.json` | pipeline and analyst timeline |
| `evidence.json` | volatile evidence collected before any containment |
| `response.json` | policy decision, executed and proposed actions |
| `case.json` | the case the incident belongs to |
| `tasks.md` | the playbook checklist |
| `manifest.json` | SHA-256 and size of every file above |
| `README.txt` | what is and is not included |

The response carries `X-Package-SHA256`; every download is written to the audit log with
that hash. Account names are masked when masking is on. Verify a package with
`soar.triage_package.verify_zip(data)`.

Set `TRIAGE_PACKAGE_DIR` to also write a package automatically for every new incident.
That folder then holds incident data: keep it outside the repository (it is git-ignored
by name) and restrict access. The package holds telemetry, not disk or memory images.
