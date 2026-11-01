# 2. Correlations: when one event is not enough

> Part of the series *How I built the detections*. Drafted with an AI assistant from this repository's commit history; every number is copied from a generated report linked in the post. All data is synthetic.

Some attacks are only visible as a pattern: ten failed logons, fifty unique DNS names, a hundred
file writes in a minute. The original brute-force rule cheated: it expected a collector to have
already counted failures and put `FailedAttemptsCount` on the event. Raw Windows event forwarding
never does that, so on real logs the rule could not fire.

**The correlation engine.** `soar/sigma_correlation.py` implements three Sigma v2 correlation
types: `event_count`, `value_count` and `temporal`, over named base rules, with `group-by`,
event-time windows and one alert per burst. Base rules do not alert on their own.

**The rules.**

- SOC-RULE-043: 10+ failed network/RDP logons for one account from one IP in 5 minutes, on raw 4625s.
- SOC-RULE-044: one IP failing as 10+ different accounts in 30 minutes (password spraying).
- SOC-RULE-045: one process writing 100+ files under user or share paths in a minute. Sysmon has no
  rename event, so in-place renames are only seen when written as new files; the rule says so.
- SOC-RULE-053: 50+ unique subdomains of one domain from one host in 5 minutes (DNS tunnelling).

**What does not work yet.** The [threshold tuning report](../THRESHOLD_TUNING.md) shows that no
benign event in the synthetic baseline ever reaches these correlations, so their thresholds are
untuned. Spraying slower than 30 minutes still gets through; that needs a long-window baseline
(GUARDIAN), not a correlation rule.
