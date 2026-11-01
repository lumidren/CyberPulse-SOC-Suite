# 1. From six rules to a real Sigma engine

> Part of the series *How I built the detections*. Drafted with an AI assistant from this repository's commit history; every number is copied from a generated report linked in the post. All data is synthetic.

The first version of CyberPulse "detected" attacks with hard-coded Python checks that happened
to share names with six Sigma files. The Sigma files were documentation; the Python was the
detection. That is the most common way a portfolio SOC project misleads its reader, and it was
the first thing to fix.

**The engine.** `soar/sigma_engine.py` now loads every rule in `rules/sigma/` and evaluates the
selections and conditions itself: field modifiers (`contains`, `endswith`, `re`, `cidr`, numeric
comparisons), `1 of`, `all of`, `not`, and logsource constraints that map a rule's
`product/category` to event IDs. It deliberately supports a subset of Sigma and raises an
error on anything else, because silently ignoring a modifier is worse than refusing the rule.

**Evidence, not adjectives.** Every rule needs positive and negative samples in `rules/tests/`,
a SOAR mapping with a version and a SHA-256 of its detection logic, and a changelog entry; tests
refuse a logic change without a version bump. A golden regression corpus records which rules
match every sample, so a new rule that steals another rule's alerts shows up in review.

**What the numbers say.** The [validation report](../VALIDATION_RESULTS.md) shows 60/60 scripted
attack runs detected. That sounds better than it is: the attacks and the rules were written by
the same person, so it is a regression check. The same report shows the honest part: before two
documented exceptions, the rules matched 119 of 600 benign baseline events, a precision of
0.335. The exceptions were tuned on that same baseline, so "0 false positives" afterwards is not
an efficacy claim.

**Lesson.** A detection project earns trust by publishing the number that makes it look worse.
