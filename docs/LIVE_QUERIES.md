# Live Endpoint Queries (osquery / Velociraptor)

Roadmap F71. **Off by default; needs your Fleet or Velociraptor server. Tested with a stubbed
HTTP layer only.**

Analysts can run **only reviewed queries from this repository**, never free-form SQL or VQL:

| Engine | Catalogue | Server call | Settings |
| :--- | :--- | :--- | :--- |
| osquery via [Fleet](https://fleetdm.com/) | numbered blocks in `rules/osquery/hunting_queries.sql` (`osq-1` ... `osq-5`); each must be a read-only `SELECT` | `POST {FLEET_URL}/api/v1/fleet/queries/run` | `FLEET_URL`, `FLEET_API_TOKEN` |
| [Velociraptor](https://docs.velociraptor.app/) | `CLIENT` artifacts in `rules/velociraptor/*.yaml` | `POST {VELOCIRAPTOR_URL}/api/v1/CreateHunt` through a REST gateway in front of the gRPC API | `VELOCIRAPTOR_URL`, `VELOCIRAPTOR_API_TOKEN` |

- `GET /api/live-query/catalogue` lists what can run.
- `POST /api/live-query` `{"engine": "osquery", "query_id": "osq-2", "targets": [12, 13]}` or
  `{"engine": "velociraptor", "artifact": "Windows.Detection.LsassMemoryAccess", "targets": ["C.0123456789abcdef"]}`.
- Both server URLs must be lab addresses; at most 100 targets per run; every run is
  audit-logged with the engine, query and target count. Results stay in Fleet or
  Velociraptor; CyberPulse returns the campaign or hunt id.
- Adding a query is a code change: add it to the catalogue file, get it reviewed, merge.
