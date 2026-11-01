# CyberPulse SOC Suite

A detection-engineering and SOAR **lab**: Sigma rules and correlations, a risk and policy
engine, human-approved containment with rollback, case management, hunting and the
documentation to run it responsibly.

!!! warning "Synthetic data"
    Every detection result on this site comes from synthetic telemetry written by the same
    person as the rules. It shows that the mechanisms work, not how well they would detect
    real attacks. Start with [What I missed](WHAT_I_MISSED.md).

## Where to start

| If you want to... | Read |
| :--- | :--- |
| Know what can go wrong before turning anything on | [Risk register](RISK_REGISTER.md), [Automated actions](AUTOMATED_ACTIONS.md) |
| Run an exercise in your lab | [Rules of Engagement](RULES_OF_ENGAGEMENT.md), [Atomic Red Team](ATOMIC_RED_TEAM.md) |
| Understand a detection | [Rule write-ups](rules/README.md), [Runbooks](runbooks/README.md) |
| See coverage and its limits | [Gap report](coverage/GAPS.md), [Evasion tests](EVASION.md) |
| Tune noisy rules | [Tuning guidance](TUNING.md), [Known false positives](FALSE_POSITIVES.md) |
| Hunt | [Hunting workbench](HUNTING.md) |
| Connect your tools | [TheHive](THEHIVE_CORTEX.md), [MISP](MISP.md), [ChatOps](CHATOPS.md), [Network sensors](NETWORK_SENSORS.md) |

## Principles

- **Humans decide.** Containment is staged for approval by default; opt-in automation is limited
  to narrow, reversible actions and sits behind a kill switch, rate limits and TTLs.
- **Internal identifiers stay internal.** Host names, accounts and internal IPs are never sent to
  external services.
- **Honest numbers.** Every figure is produced by a script in the repository, or marked
  "not yet measured".

The project's README, setup instructions and changelog live in the
[repository](https://github.com/lumidren/CyberPulse-SOC-Suite).
