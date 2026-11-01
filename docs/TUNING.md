# Rule Exclusions and Tuning Guidance

Roadmap E95. How to make a noisy rule quieter **without** making it blind. Known
false-positive scenarios for each rule are in [FALSE_POSITIVES.md](FALSE_POSITIVES.md).

## Decide what kind of noise it is

| Situation | Right tool | Wrong tool |
| :--- | :--- | :--- |
| One known-benign pattern (a signed admin script, one maintenance task) | An **exception** in `rules/exceptions.yml` | Editing the rule's detection |
| The rule is too broad for everyone (matches normal admin flags) | Change the **rule logic**, with a version bump | An exception that matches half the traffic |
| A threshold fires on normal volume | **Threshold tuning** on your own history | Raising the threshold until it never fires |
| The rule needs data you do not collect | Record it as an accepted gap | Disabling the rule silently |

## 1. Exceptions (preferred for one known pattern)

Add an entry to [`rules/exceptions.yml`](../rules/exceptions.yml):

```yaml
- id: EXC-0003
  rule: SOC-RULE-004
  reason: Vendor agent updater runs encoded PowerShell, signed by Vendor Ltd
  owner: alice
  created: 2026-11-01
  expires: 2027-02-01          # at most 180 days; it stops suppressing after this
  match:                       # every field must match (Sigma selection syntax)
    ParentImage|endswith: '\VendorAgent.exe'
    Signed: true
```

Rules for a good exception:

- **Match on at least two independent fields**, ideally something an attacker cannot
  easily copy (a full signed path, a parent process, a service account) rather than a
  file name alone. `ParentImage|endswith: '\svchost.exe'` alone is easy to fake
  (see EV-09 in [EVASION.md](EVASION.md)).
- Never use a wildcard-only value; the loader rejects it.
- The test suite rejects an exception that would hide one of the rule's own attack
  samples, so the exception cannot switch off what the rule exists for.
- Suppressions are counted per exception (`GET /api/exceptions`). An exception that never
  suppresses anything is dead weight; one that suppresses thousands deserves a second look.
- When it expires, review it: renew with a new expiry, or delete it.

## 2. Changing the rule

When the rule itself is wrong for everyone:

1. Prefer narrowing over removing: add a `filter_*` selection and `and not filter_*`.
2. Bump the rule's `version`, update `detection_sha256` in `rules/soar_mapping.yml` and add a
   `rules/RULE_CHANGELOG.md` entry (tests enforce all three).
3. Add a negative sample for the benign case and keep every positive sample matching.
4. Run `python scripts/regression_corpus.py`; if other rules' results changed on purpose,
   `--accept` and review the JSON diff.
5. Re-run the evasion tests (`python scripts/evasion_report.py`): a filter must not open a
   new bypass.

## 3. Thresholds

For rules with numeric thresholds and the correlation rules, replay your own history:

```bash
python scripts/tune_thresholds.py --benign my_benign.jsonl --malicious known_bad.jsonl --fp-budget 2
```

It prints firings per candidate threshold and the most sensitive value within your false-
positive budget. Your exported logs are printed, never written into the repository.
The committed [THRESHOLD_TUNING.md](THRESHOLD_TUNING.md) uses synthetic data only, so its
suggestions reflect the generator; no threshold has been changed from it.

## 4. Rare-process noise

The parent-child baseline ([BEHAVIORAL_BASELINE.md](BEHAVIORAL_BASELINE.md)) only becomes
useful after weeks of real process telemetry. Until then, treat its hints as hunting leads,
not alerts.

## 5. After tuning

- `CYBERPULSE_LAB_MODE=true python scripts/validate_detections.py --write` and check the
  false-positive and suppression counts in [VALIDATION_RESULTS.md](VALIDATION_RESULTS.md).
- Record why in the commit body. Tuning is a detection change and is reviewed like one.
- If analysts appealed the alert (see the appeals flow), close the appeal with a link to
  the change.
