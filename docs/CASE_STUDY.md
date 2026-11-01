# Case Study: Building CyberPulse Honestly

What worked, what failed, and what I would change. Every figure on this page comes from a
generated report in the repository, linked where it is used. `tests/test_case_study.py`
fails if a figure here no longer matches its source. All detection data is synthetic, and
the same person wrote the rules, the attacks and the tests.

## The starting point

CyberPulse began as a portfolio SOC demo. It looked complete, but most of it was
narrative:

- **Detections were Python, not Sigma.** Six Sigma files sat next to hard-coded checks that
  did the real matching. The Sigma files were documentation.
- **The brute-force rule could not fire on real logs.** It expected a collector to have
  counted failures already (`FailedAttemptsCount`). Raw Windows events never carry that field.
- **The "AI copilot" was templates.** It filled text from incident fields, but the project
  presented it as more than that.
- **Numbers were typed in by hand.** Latency and coverage figures came from somewhere
  nobody could reproduce.

The goal of the rebuild was not more features. It was that every claim could be checked.

## What worked

**Detection as code with evidence.** The engine now evaluates the Sigma files themselves
([blog part 1](blog/01-sigma-engine.md)). It has
51 single-event rules and 4 correlation rules. Each rule has positive and negative samples,
a versioned SOAR mapping with a fingerprint of its logic, and a changelog entry. A golden
regression corpus catches one rule silently taking over another's alerts. Scripted attack
runs are detected 60/60 by the expected rule ([METRICS.md](METRICS.md)). That is a
regression check, not efficacy.

**Humans stay in the loop.** Containment is staged for approval by default. Opt-in
automation is limited to reversible actions behind a kill switch, rate limits, a
protected-asset list, TTLs and rollback ([AUTOMATED_ACTIONS.md](AUTOMATED_ACTIONS.md)).
Every action is in a hash-chained ledger. Later features followed the same rule. The LLM
triage summary is a draft until an analyst accepts it
([LLM_TRIAGE.md](LLM_TRIAGE.md)). The plain-English hunt translator reports the words it
did not understand instead of guessing ([HUNTING.md](HUNTING.md)).

**Generated, test-enforced documentation.** Coverage, gaps, rule quality, validation,
evasion, purple-team results, the leaderboard and the metrics page are all produced by
scripts. Tests fail when a page is stale, so a number in the docs cannot drift from the
code that produces it.

**Publishing the bad numbers.** The pages that make the project look worse are the most
useful. They are [What I missed](WHAT_I_MISSED.md), the [evasion tests](EVASION.md) and the
red win in the [scenario pack](SCENARIO_RESULTS.md).

## What failed

**Precision.** Before exceptions, the rules alerted on 119 of 600 benign baseline events: a
precision of 0.335 ([METRICS.md](METRICS.md)). Two exceptions bring that to 0/600. They
were tuned on the same baseline they are measured on, so the zero is overfitted by
construction.

**Evasion.** 11/16 evasion variants bypass the rule they target
([EVASION.md](EVASION.md)). The causes are simple and common: PowerShell parameter
prefixes, renamed binaries (the rules key on `Image`, not `OriginalFileName`), an extra
space, and a filter that trusted any path ending in `svchost.exe`. The
[scenario pack](SCENARIO_RESULTS.md) turns three of them into an exercise that blue loses.

**Coverage.** 27/36 target techniques have a rule ([GAPS.md](coverage/GAPS.md)), and the
author chose the targets. Masquerading, RDP abuse and volume-based exfiltration need
telemetry or baselines that the lab does not have.

**Behavioural baseline.** The rare parent-child signal flags 28/28 attack samples, and
also 26/26 benign near misses, because the synthetic baseline has only 4 distinct pairs
([BEHAVIORAL_BASELINE.md](BEHAVIORAL_BASELINE.md)). It proves the mechanism and nothing
about discrimination.

**Correlation thresholds are untuned.** No benign baseline event ever reaches a
correlation rule, so their thresholds are guesses ([THRESHOLD_TUNING.md](THRESHOLD_TUNING.md)).
Slow password spraying still gets through.

**Mistakes caught during the rebuild.** None of these were found by a feature test. Each
was found by a check written for a rule of the project:

- Chat webhooks sent host names, internal IPs and execution logs to external services.
  Fixed with a pseudonymised external summary that every outbound path now uses.
- A JSON helper in the console called itself recursively and broke the page.
- A playbook keyed on a technique would have quarantined mail for a host-only macro alert.
  It is now restricted to the phishing rule.
- The README's latency figures were stale. They were re-measured with the benchmark script,
  and the result is linked rather than copied.

## What I would change

1. **Hold out the tuning data.** Tune exceptions on one baseline and report precision on
   another, so the false-positive figure means something.
2. **Use `OriginalFileName` and normalise command lines** before matching. That one change
   closes most of the documented bypasses.
3. **Get real, consented telemetry** from a lab with real users and administrators. A
   synthetic baseline with 4 process pairs cannot tune anything.
4. **Write the evasion cases before the rule**, not after. Every rule tested so far has
   a bypass.
5. **Verify the integrations against live services early.** TheHive, MISP, Entra, the
   threat-intel providers, the Claude API and the network sensors are built to their
   documentation and tested with stubs, but never run end to end
   ([WHAT_I_MISSED.md](WHAT_I_MISSED.md), section 5).
6. **Rank correlation rules too.** The [leaderboard](coverage/LEADERBOARD.md) covers only
   single-event rules.

## What this project is, and is not

It is a detection-engineering and SOAR lab with honest measurement: a mechanism you can
read, test and extend. It is not evidence of real-world detection performance. Real
detection rate, real false-positive rate, mean time to detect on real infrastructure and
analyst time saved have not been measured, and this page does not quote numbers for them.
