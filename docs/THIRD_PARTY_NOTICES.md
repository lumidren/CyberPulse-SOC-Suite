# Third-Party Notices & Credits

CyberPulse builds on, configures or integrates with the projects below. They
are credited here; their names and licences belong to their owners. Licence
names reflect each project's published terms at the time of writing (2026-11).
**Check the upstream licence before redistributing anything**; upstream always
wins over this summary.

CyberPulse does **not** bundle or redistribute any of these projects'
binaries. Configuration files in `deploy/` and `integrations/` are written for
this lab in the formats those tools consume.

## Platforms and tools configured by this repository

| Project | Used for | Licence (upstream) | Notes |
| :--- | :--- | :--- | :--- |
| [Wazuh](https://wazuh.com) | SIEM rules/decoders in `rules/wazuh/`, `deploy/wazuh/`; container in `deploy/docker-compose.yml` | GPLv2 (Wazuh manager/agent) | Our XML rules are original lab content. |
| [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) (Microsoft Sysinternals) | Telemetry schema emulated by the simulator; `deploy/sysmon/sysmonconfig.xml` | Sysinternals Software License Terms (proprietary, free to use) | Binary is downloaded by the Vagrantfile from Microsoft at provision time, never redistributed here. |
| [Sigma](https://github.com/SigmaHQ/sigma) | Rule format for `rules/sigma/` | Sigma specification: LGPL; SigmaHQ rule repository: Detection Rule License (DRL) 1.1 | See `rules/sigma/README.md` for rule provenance. |
| [pfSense](https://www.pfsense.org) (Netgate) | Simulated perimeter-block responder | pfSense CE: Apache 2.0 | Only described/simulated; no pfSense code included. |
| [OpenSearch](https://opensearch.org) | Indexer container | Apache 2.0 | |
| [TheHive](https://strangebee.com/thehive/) (StrangeBee) | Case template `integrations/thehive/` | TheHive 5: StrangeBee licence (community/commercial editions) | Template is original lab content. |
| [MISP](https://www.misp-project.org) | Event sample `integrations/misp/` | AGPL-3.0 | Sample contains only synthetic indicators. |
| [Splunk](https://www.splunk.com) | `integrations/splunk/*.conf` | Proprietary | Config files are original lab content. |
| [Shuffle](https://shuffler.io) | Playbook export `integrations/shuffle_soar/` | AGPL-3.0 | |
| [Velociraptor](https://docs.velociraptor.app) | VQL artifacts `rules/velociraptor/` | AGPL-3.0 | Artifacts are original lab content. |
| [osquery](https://osquery.io) | Hunting queries `rules/osquery/` | Apache 2.0 / GPLv2 (dual) | |
| [YARA](https://virustotal.github.io/yara/) | `rules/yara/` | BSD-3-Clause | |
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) (SpecterOps) | Export format of `soar/bloodhound_exporter.py` | Apache 2.0 | Only the JSON schema is produced; no BloodHound code included. |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (Red Canary) | Referenced by technique only in `simulator/atomic_tests/` | MIT | No tests are shipped (reference-only manifests). |

## Libraries and assets used by the code or console

| Component | Licence (upstream) | Notes |
| :--- | :--- | :--- |
| [PyYAML](https://pyyaml.org) | MIT | Runtime dependency |
| [Leaflet](https://leafletjs.com) | BSD-2-Clause | Loaded from unpkg CDN |
| [Font Awesome Free](https://fontawesome.com) | Icons CC BY 4.0, fonts SIL OFL 1.1, code MIT | Loaded from cdnjs |
| Map tiles: [CARTO](https://carto.com/attributions) basemaps with [OpenStreetMap](https://www.openstreetmap.org/copyright) data | OSM data: ODbL; CARTO basemap terms | **Attribution required**: the console map shows "© OpenStreetMap contributors © CARTO". |

Development tools (pytest, flake8, ruff, bandit, pip-audit, gitleaks) are used
only in development/CI and are not distributed.
