# Contributing to CyberPulse SOC Suite

Thanks for helping. This is a defensive lab, so contributions follow a few ethical rules
as strictly as the technical ones. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
first.

## Ethical-use rules (pull requests that break these are closed)

1. **Telemetry, never tooling.** The simulator emits synthetic log records. Do not add
   working malware, credential theft, exploits, payloads, persistence implants, or code
   that touches a real host's security controls. Attack emulation means writing the
   *event a technique leaves behind*, not performing the technique.
2. **Lab-only by construction.** New simulator generators use `@lab_only`, stay inside
   the lab CIDR allowlist, use RFC 5737 / RFC 1918 / `*.example` values, and tag events
   `simulation: true`.
3. **No real data.** Never commit real logs, telemetry, incident records, credentials,
   API keys, customer or employee names. Test data is synthetic and says so.
4. **Automation stays human-approved.** Nothing may make containment run without
   approval by default, bypass the kill switch, protected assets, rate limits or TTLs, or
   remove a rollback path. New responders need a rollback (or an explicit "not
   reversible" note) and a tier in `soar/action_tiers.py`.
5. **Internal identifiers stay internal.** Host names, usernames and internal IPs are
   never sent to external services (enrichment, chat, sharing). Use the existing
   pseudonymisation and indicator filters.
6. **Honest numbers.** Do not add metrics, benchmarks or results that a script in the
   repo cannot reproduce. If it is not measured, say "not yet measured".
7. **Respect third-party terms.** New integrations document the provider's terms,
   rate limits and attribution in `docs/THIRD_PARTY_APIS.md` and are off by default.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python -m unittest discover -s tests -p "test_*.py"
python -m ruff check . && python -m mypy
```

Run the console locally with `CYBERPULSE_LAB_MODE=true python server.py` and sign in with
the key it prints.

## Adding or changing a detection

- Add the Sigma rule under `rules/sigma/` (or `rules/sigma/correlations/`), a mapping in
  `rules/soar_mapping.yml` with `version` and `detection_sha256`, a
  `rules/RULE_CHANGELOG.md` entry, and positive *and* negative samples in `rules/tests/`.
- Changing detection logic means bumping the rule version and fingerprint (a test
  enforces it) and regenerating the derived files:
  `python scripts/convert_rules.py`, `python scripts/export_navigator.py`,
  `python scripts/coverage_report.py`, `CYBERPULSE_LAB_MODE=true python scripts/validate_detections.py --write`,
  and `python scripts/regression_corpus.py --accept` if a match intentionally changed.
- Document known false positives in the rule, and prefer an expiring exception in
  `rules/exceptions.yml` over weakening the rule.

## Commits and pull requests

- Small, focused commits using Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`,
  `refactor:`, `chore:`, `ci:`, `security:`), subject under 72 characters, imperative.
- The body says *why*. Every commit leaves tests and lint passing.
- Changes to automated behaviour (policy, playbooks, responders, safety limits) need a
  `CHANGELOG.md` entry under "Automation behaviour".

## Reporting vulnerabilities

Privately, as described in [SECURITY.md](SECURITY.md). Do not open a public issue.
