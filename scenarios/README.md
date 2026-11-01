# Red vs Blue Scenario Pack

Roadmap F99. Four reusable red-vs-blue exercises as plain YAML: what the red team does, the
synthetic telemetry each step leaves, and what the blue team is expected to detect. Use them
to train analysts, to regression-test detections, or as a starting point for your own pack.

| File | Scenario | Difficulty | Expected outcome |
| :--- | :--- | :--- | :--- |
| `rvb-01.yml` | Phishing to credential theft | easy | Blue detects every step |
| `rvb-02.yml` | Password spray to ransomware | medium | Blue detects every step |
| `rvb-03.yml` | Living off the land, quietly | hard | **Red wins 3 of 4 steps**, using bypasses documented in [EVASION.md](../docs/EVASION.md) |
| `rvb-04.yml` | Domain dominance | medium | Blue detects every step |

Current results: [docs/SCENARIO_RESULTS.md](../docs/SCENARIO_RESULTS.md).

## Safety

The events are **synthetic log records**. Nothing in the pack runs a command, touches a
host or sends a packet. The runner checks every scenario before replaying it, including
packs written by someone else, and refuses if any check fails:

- `CYBERPULSE_LAB_MODE=true` must be set;
- every event's host must be in the lab inventory inside the lab CIDRs (`CYBERPULSE_LAB_CIDRS`),
  or an allowlisted lab cloud tenant;
- every IPv4 address in an event must be in the lab CIDRs or an RFC 5737 documentation range
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so no real third party is named;
- credential-attack events may only name lab accounts (`lab.*`) and must carry no password
  material;
- the file must declare `synthetic: true`.

Replay feeds events to the detection engine only. No incident is opened, and no
containment, notification or enrichment runs.

## Running

```bash
CYBERPULSE_LAB_MODE=true python scripts/run_scenarios.py                    # write docs/SCENARIO_RESULTS.md
CYBERPULSE_LAB_MODE=true python scripts/run_scenarios.py --json             # results as JSON
CYBERPULSE_LAB_MODE=true python scripts/run_scenarios.py --pack my-pack --json
```

Exit status 2 means a step did not end as expected. Either a detection regressed, or a
bypass was fixed and its scenario should now expect `detected`.

## Format

```yaml
id: RVB-01                       # unique in the pack
title: Phishing to credential theft
summary: One paragraph for the exercise brief.
difficulty: easy                 # free text: easy / medium / hard
lab_host: WIN-WORKSTATION09
synthetic: true                  # required
steps:
  - id: RVB-01-S1                # unique in the scenario
    name: Macro spawns a shell
    technique: T1204.002         # ATT&CK id
    red: What the red team does, in one sentence.
    blue:
      expect: detected           # or "missed" for a known, documented gap
      rules: [SOC-RULE-021]      # any of these firing counts as detected
      question: A triage question for the exercise debrief.
    events:                      # one or more synthetic events in the lab's event format
      - event_id: 1
        event_source: Microsoft-Windows-Sysmon/Operational
        computer_name: WIN-WORKSTATION09
        timestamp: '2026-11-01T09:07:00Z'
        details: {Image: ..., CommandLine: ..., ParentImage: ...}
```

Events use the lab's event format (fields as in `rules/tests/*.yml`). To use the pack with
another SIEM, map those fields to yours. The `red`, `blue.question` and `summary` fields are
there so a facilitator can run the exercise without reading the rules.

## As a tabletop exercise

1. Give the blue team the scenario `title` and `summary` only.
2. Replay one step at a time (or show its events). Blue says what fired, what it means and
   what they would do, then answers `blue.question`.
3. Score one point per step: blue when the expected rule fires and is triaged correctly, red
   otherwise. RVB-03 shows what losing looks like, and why the gaps are documented.

## Reuse

The pack is released under the repository's MIT licence ([LICENSE](../LICENSE)). The events were
copied from this project's own rule samples and evasion cases; they are synthetic and
contain no real hosts, accounts or addresses.
