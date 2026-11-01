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
| Plain-English queries | F97 | A question such as "failed logons for user svc_backup from 203.0.113.0/24" becomes Sigma, Splunk SPL and Microsoft KQL |

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

## Plain-English queries (F97)

**Ask in plain English** (`POST /api/hunt/translate {"text"}`, `soar/nl_hunt.py`) turns a
question into a Sigma detection. The existing converter then produces Splunk SPL and
Microsoft KQL from it, and the same rule runs on the stored events so you see how many it
matches.

It is a **fixed phrase grammar**, not a language model: offline, deterministic and tested.
Words it does not recognise come back under *not understood* and are ignored, so check that
list before trusting the query. It knows:

| Phrase | Becomes |
| :--- | :--- |
| `processes`, `executions`, `ran`, `launched` | Sysmon 1 / 4688 process creation |
| `failed logons`, `successful logons` (or logins, sign-ins) | Security 4625 / 4624 |
| `network connections`, `dns queries`, `files written`, `registry`, `powershell scripts` | The matching Sysmon / PowerShell event type |
| `named X`, `X.exe` | `Image` ends with `\X.exe` |
| `with parent X`, `spawned by X`, `launched by X` | `ParentImage` ends with `\X.exe` |
| `containing X` (quote values with spaces) | `CommandLine` contains, or the file, registry, script or DNS field for those event types |
| `on host X` | `Computer` equals |
| `for user X` | `TargetUserName` for logons, otherwise `User` contains |
| `from 203.0.113.7`, `from 10.0.0.0/8` | `IpAddress` (CIDR when a prefix is given) |
| `to 198.51.100.20`, `to port 4444` | `DestinationIp`, `DestinationPort` |
| `for domain example.org` | `QueryName` ends with |
| `in path C:\Users\Public` | `TargetFilename`, `TargetObject` or `Image` starts with |
| `in the last 24 hours`, `past 30 minutes`, `today` | SPL `earliest=-24h`, KQL `ago(24h)`, and the same window on stored events |

The SPL and KQL inherit the converter's limits. Field names follow its mapping: Sysmon
names for Splunk, Defender / Sentinel columns for KQL. None of the output has been run
against a live SIEM. A Defender Advanced Hunting query uses `Timestamp`, not
`TimeGenerated`, so change the time filter there.
