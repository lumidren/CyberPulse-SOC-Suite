# Detection Rule Metadata Standard

Every rule in `rules/sigma/` must carry the fields below. `tests/test_rule_metadata_standard.py`
enforces the standard; a rule that does not meet it fails CI.

| Field | Required | Rule |
| :--- | :---: | :--- |
| `title` | yes | Short, specific, unique. |
| `id` | yes | Random UUID v4; never reused or changed after publication. |
| `status` | yes | `experimental` until tested against real-world noise (all lab rules today). |
| `description` | yes | What the rule detects and on which telemetry; at least 40 characters. |
| `references` | yes | At least one `https://` link (ATT&CK technique page first). |
| `author` | yes | `lumidren (CyberPulse SOC Suite)`; keep original authors first when adapting (DRL 1.1). |
| `date` | yes | Creation date, `YYYY-MM-DD`. |
| `modified` | yes | Last change, `YYYY-MM-DD`, not earlier than `date` (see versioning). |
| `tags` | yes | `attack.<tactic>` and at least one `attack.tNNNN[.NNN]` technique tag. |
| `logsource` | yes | `product` + `category` or `service` the engine can map. |
| `detection` | yes | Selections plus `condition`; only engine-supported syntax. |
| `falsepositives` | yes | Concrete benign scenarios (tools, roles, conditions), never "unknown" or "none". |
| `level` | yes | Severity: `low`, `medium`, `high` or `critical`. |

Lab-specific fields (SOC rule id, display name, response playbook, rule
version) live in `rules/soar_mapping.yml`, keyed by the Sigma `id`, so the Sigma
files stay vendor-neutral. Every rule also needs positive/negative samples in
`rules/tests/<rule file>.yml`.
