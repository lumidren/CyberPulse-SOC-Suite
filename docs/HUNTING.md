# Threat Hunting

The hunting workbench (`/hunt.html`) works on the events this server has evaluated
recently, including the ones that never alerted (`soar/event_store.py`, bounded by
`HUNT_EVENT_BUFFER`, purged with retention). For history, hunt in your SIEM.

| Tool | Roadmap | What it does |
| :--- | :--- | :--- |
| Pivot | F66 | Every event where a field equals a value, plus the top related values of every other field, each one click to pivot again |
| Hypothesis templates | F67 | `hunts/templates/*.yml`: hypothesis, ATT&CK techniques, data needed, ordered steps, usual benign explanations, next steps |
| Notebooks | F68 | `notebooks/`: repeatable hunts as code |
| Stack counting | F69 | Counts of every value of a field, rarest first, long tail flagged |
| YARA | F70 | Scan collected files with `rules/yara` ([YARA.md](YARA.md)) |
| Live queries | F71 | Reviewed osquery / Velociraptor queries on lab hosts ([LIVE_QUERIES.md](LIVE_QUERIES.md)) |
| Beaconing | F73 | Near-constant connection intervals in Zeek conn logs |
| Hunt to detection | F75 | Draft a Sigma rule and samples from a pivot |

## From a finding to a detection (F75)

1. Pivot to the finding, then **Draft a detection from this pivot**
   (`POST /api/hunt/draft-rule {"field", "value"}`).
2. You get a rule in the project's metadata standard with the right logsource, a selection
   on the pivoted field and the technique tag when known, a samples file whose positive
   cases are the matching events, and a checklist. TODO markers show what only a human can
   decide. The draft is checked against the engine and matches its own samples.
3. It is **not saved or enabled**. Narrow the selection, write real false positives and a
   negative sample, run the evasion and regression checks, add the mapping and changelog
   entry, and open a pull request (CONTRIBUTING.md).
