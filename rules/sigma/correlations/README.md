# Correlation rules

Multi-event Sigma rules (roadmap F12), evaluated by `soar/sigma_correlation.py`.
Each file holds one or more named *base* rules followed by a `correlation:`
document (Sigma v2 correlation format). Base rules referenced by a correlation
do not alert on their own.

Supported: `event_count`, `value_count`, `temporal`; `group-by`; `timespan`
(`s`/`m`/`h`/`d`); one condition operator (`gt`, `gte`, `lt`, `lte`, `eq`).
State is in memory per server process and is lost on restart.

Correlation rules are **not** included in `rules/converted/` (F5): each SIEM
expresses windowed aggregation differently (Splunk `stats`/`streamstats`,
Elastic EQL sequences or threshold rules, KQL `summarize ... by bin()`), and a
translation that has not been run on the target SIEM would be unverified.
