# CyberPulse SOC Suite — Ethics, Safety & Feature Roadmap

This checklist tracks the 200-item roadmap (E1–E100 ethics/safety/honesty,
F1–F100 features). Each item is implemented in its own commit whose footer is
`Roadmap: <ID>`, so `git log --grep "Roadmap: E14"` finds the change.

Status notes appended to an item:

* **Done** — implemented; the note names the main file(s) or test.
* **Done earlier** — already satisfied by a commit made before this roadmap.
* **Merged into Xn** — redundant with another item; implemented there.
* **Stubbed** — needs something only the owner can supply (API keys, a real
  lab, accounts); implemented behind config and documented, not live-tested.
* **Skipped** — conflicts with the project's hard rules, or cannot be done
  honestly from inside the repo; the reason is recorded.

Hard rules that override any item: no fabricated metrics, no working
credential-theft or malware code, automation defaults to approval-required,
internal identifiers never go to external APIs.

---

## Phase 1 — Honest claims & README (E1–E12)

- [x] **E1** Drop "enterprise-grade"; describe the project as a lab. — **Done**: lab wording across UI/CLI/docs; guard in `tests/test_honest_claims.py`.
- [x] **E2** Label every metric as lab-measured on emulated traffic. — **Done**: real timings in `soar/soar_engine.py`; `scripts/benchmark_pipeline.py`; README/UI labels.
- [x] **E3** Replace "0% false positives" with "0 false positives in N baseline runs", stating N. — **Done**: `scripts/validate_detections.py` → `docs/VALIDATION_RESULTS.md` (currently 319 FPs in 600 baseline events); sync test.
- [x] **E4** Replace "100% true-positive" with an "X/Y scripted runs detected" count. — **Done**: catalogue + `docs/VALIDATION_RESULTS.md` show '60/60 scripted runs detected'; guard bans '100% True-Positive'.
- [x] **E5** Document how the baseline traffic for the FP test is generated. — **Done**: `simulator/benign_baseline.py`, `docs/BASELINE_TRAFFIC.md`, `tests/test_benign_baseline.py`.
- [x] **E6** Remove the "15–25 min manual analyst benchmark" or cite a source. — **Done**: phrase verified absent (introduced in d0342e0, since removed); guard pattern in `tests/test_honest_claims.py`.
- [x] **E7** Stop comparing a 20 min manual MTTR to automated pipeline seconds. — **Done**: removed `analyst_baseline_sec` and the 'Manual Baseline: 20m' KPI caption; guard pattern.
- [x] **E8** Add a Limitations section to the README. — **Done**: README '⚠️ Limitations' section; `tests/test_readme_sections.py`.
- [x] **E9** State that the rules are untested against real-world noise. — **Done**: Sigma `status: experimental`; README/DELC/coverage caveats; API flag `real_world_noise_tested=false`.
- [x] **E10** Mark INC-2026-0815-01 and -02 as simulated incidents. — **Done**: simulated banner + '(SIMULATED)' IDs on both incident reports and both triage case studies; test in `tests/test_readme_sections.py`.
- [x] **E11** Remove "Formal" from incident report headings, or label them exercises. — **Done**: report/triage/purple-team headings, HTML generator header + signoff, JSON `report_type`; guard pattern.
- [x] **E12** Make the README resume block accurate, or move it out of the repo. — **Done**: README 'Portfolio Summary' block rewritten with verifiable, lab-scoped lines; guard pattern.

## Phase 2 — Human oversight & safe automation (E13–E30)

- [x] **E13** Remove "no human-in-the-loop" as a selling point. — **Done**: SOAR tab/header wording, README 'Human Oversight' section, policy rationale text; guard pattern.
- [x] **E14** Add an approval mode: an analyst confirms before containment runs. — **Done**: `approve_action`/`reject_action` in `soar/resilient_containment.py`, `/api/approvals` endpoints, UI buttons; `tests/test_safe_automation.py`.
- [x] **E15** Make approval the default; full-auto is opt-in. — **Done**: default `APPROVAL_REQUIRED`; AUTOMATIC needs `CYBERPULSE_ALLOW_FULL_AUTO=true` (403 otherwise); tests in both suites.
- [x] **E16** Tier actions by blast radius (auto IP block; approval for host isolation and account lockdown). — **Done**: `soar/action_tiers.py`; enforced in `RiskAndPolicyEngine._containment_intent`; SOAR tab tier table; tests.
- [x] **E17** Add a global kill switch that halts all automation. — **Done**: `soar/safety.py` kill switch enforced in `ResilientContainmentEngine`; `/api/safety/kill-switch`; console button; tests.
- [x] **E18** Add a dry-run mode that logs what it would do. — **Done earlier**: DRY_RUN policy mode records `SIMULATED_NO_DISRUPTION` actions (`soar/resilient_containment.py`, test `test_dry_run_policy_mode`).
- [x] **E19** Add a confidence threshold; below it, escalate instead of acting. — **Done**: `RULE_CONFIDENCE` + `CONFIDENCE_THRESHOLD` in `soar/risk_engine.py`; escalation path; tests.
- [x] **E20** Rate-limit containment actions per hour. — **Done**: rolling-hour budget in `soar/safety.py`, enforced in `execute_containment`; tests with an injected clock.
- [x] **E21** Circuit breaker: if N hosts are isolated in M minutes, stop and page a human. — **Done**: isolation breaker in `soar/safety.py`; pager via `WebhookDispatcher.dispatch_text`; tests.
- [x] **E22** Allowlist of assets that can never be auto-isolated (DCs, SOC hosts, jump boxes). — **Done**: `soar/protected_assets.py` defaults (DC, SOC subnet, JUMP-*/PAW-*) + `PROTECTED_ASSETS`; enforced in the engine and on approval; tests.
- [x] **E23** Protected-accounts list that can never be auto-locked. — **Done**: `protected_account_match` in `soar/protected_assets.py`; enforced in the engine and on approval; tests.
- [x] **E24** Protect the DC specifically: never auto-isolate 10.0.0.10. — 🔀 **Merged into E22**: `10.0.0.10` (and `WIN-DC01*` via the lab inventory) is a default protected asset; test `test_dc_is_never_isolated_even_with_approval`.
- [x] **E25** Auto-expiry (TTL) on isolation rules. — **Done**: TTL stamping + `expire_actions`/`extend_action` in the engine, sweeper thread in `server.py`, `/api/actions/<id>/extend`; tests.
- [x] **E26** One-click rollback for every action. — **Done**: `ROLLBACK_PLAYBOOKS` covers every action in `ACTION_TIERS` with FULL/PARTIAL reversibility; endpoint/UI updated; tests.
- [x] **E27** Store pre-action state so rollback restores it. — **Done**: `pre_action_state` snapshot in `_apply_action`; state-aware `_release_state`; tests.
- [x] **E28** Replace `taskkill /F /T` with graceful-first termination, or document the data-loss risk. — **Done**: `soar/process_termination.py`; plan recorded on kill actions; risk documented in `docs/ARCHITECTURE.md`; tests.
- [x] **E29** Snapshot memory/process info before killing a process. — **Done**: `snapshot_process` in `soar/evidence_collector.py`, recorded by the engine before kills/isolation; pipeline reordered; tests.
- [x] **E30** Export scheduled-task XML before removing a task. — **Done**: `task_export` + disable-not-delete in `_apply_action`; pipeline passes task details; FULL rollback; tests.

## Phase 2b — Simulator safety (E31–E42)

- [x] **E31** Bold warning: lab use only, never on production or networks you don't own. — **Done**: warning in README, simulator docstrings and `start_lab.py` banner; test.
- [x] **E32** Simulator refuses to run unless a lab flag is set. — **Done**: `simulator/lab_guard.py` decorator on every generator; API 403; scripts/CLI/CI/.env updated; tests.
- [x] **E33** Target allowlist limited to the lab CIDR. — **Done**: `validate_target` in `simulator/lab_guard.py` (lab CIDRs + lab cloud targets) applied to every generator; tests.
- [x] **E34** Block the simulator from running against public IPs. — **Done**: `is_global` checks on targets and on `CYBERPULSE_LAB_CIDRS` in `simulator/lab_guard.py`; tests.
- [x] **E35** Confirm the LSASS "dump" is simulated, not a real credential dump. — **Done**: `tests/test_simulator_is_telemetry_only.py` (AST + runtime); generator docstring and README statement.
- [x] **E36** If it touches real credentials, document that and use dummy accounts only. — 🔀 **Merged into E35**: not applicable. The simulator never touches real or dummy credentials (verified by `tests/test_simulator_is_telemetry_only.py`), so there is nothing to restrict to dummy accounts.
- [x] **E37** Don't ship working credential-theft tooling; emulate the telemetry instead. — **Done**: `simulator/atomic_tests/*.yaml` now reference-only (`execution: none`); test `TestNoShippedAttackTooling`.
- [x] **E38** Brute-force simulation targets only lab accounts with fake passwords. — **Done**: `validate_credential_attack` in `simulator/lab_guard.py`; scenario uses `lab.admin` with `CredentialMaterial: none`; tests.
- [x] **E39** Rate-limit the brute-force simulation. — **Done**: `SimulationThrottle` in `simulator/lab_guard.py`, enforced on the simulate and purple-team endpoints; tests.
- [x] **E40** Tag all simulated events with `simulation=true`. — **Done**: `tag_simulated` in `simulator/lab_guard.py`; baseline + ingest + incident `simulated` flag; tests.
- [x] **E41** Dashboard visibly shows when data is simulated. — **Done**: `simulatedBadge()` in `web/app.js` on the incident table and dossier; test.
- [x] **E42** Test-mode banner in the UI. — **Done**: sticky `#labModeBanner` in `web/index.html`/`styles.css`, text from `/api/version` `lab_mode`; test.

## Phase 3 — Securing the tool itself (E65–E78)

- [x] **E65** Authentication on the localhost:5000 dashboard. — **Done**: `soar/auth.py` sessions, `/api/session` login/logout, `web/login.html`, page gating in `server.py`; `tests/test_dashboard_auth.py`.
- [x] **E66** Bind to 127.0.0.1 by default; document the 0.0.0.0 risk. — **Done**: `HOST`/`SYSLOG_HOST` default 127.0.0.1, startup warning, compose publishes on loopback; risk documented; tests.
- [x] **E67** CSRF protection on the simulation trigger endpoints. — **Done**: `_csrf_ok` in `server.py` (token + Origin check) on every cookie-auth POST; console sends `X-CSRF-Token`; tests.
- [x] **E68** HMAC-signature authentication on the SOAR webhook receiver. — **Done**: `soar/ingest_auth.py` verifier, enforced on `/api/ingest`; `/api/ingest/manual`; `scripts/send_signed_event.py`; `tests/test_ingest_hmac.py`.
- [x] **E69** Validate and sanitize all webhook inputs. — **Done** (2 commits): `soar/input_validation.py` on webhook + syslog input; output escaping in the report and console; tests.
- [x] **E70** Prevent command injection in taskkill/netsh/iptables calls; never concatenate strings. — **Done**: `soar/command_builder.py` validators + argv builders used by the engine; invalid input → manual review; `tests/test_command_builder.py`.
- [x] **E71** Parameterized, validated arguments for WinRM and PowerShell. — **Done**: `ps_invocation`/`graph_revoke_sessions` in `soar/command_builder.py`; engine uses them; tests.
- [x] **E72** Never hardcode API keys; use environment variables or a secrets manager. — **Done**: random dev key in `server.py`, compose/.env placeholders, `tests/test_secret_hygiene.py`.
- [x] **E73** Add `.env.example` and a `.gitignore` for secrets. — **Done earlier** (62c8760, 176e547): `.env.example` documents every setting; `.gitignore` excludes `.env*`.
- [x] **E74** Scan repo history for leaked keys (gitleaks/trufflehog). — **Done**: `scripts/scan_history_secrets.py` run over 81 commits (2 known placeholders, no real secrets) → `docs/SECRET_SCAN.md`; gitleaks CI job (first run not yet observed).
- [x] **E75** WinRM over HTTPS with certificate validation, not skip-verify. — **Done**: `validate_winrm` in `soar/responder_config.py`, surfaced in `/api/health`; tests. Not exercised against a real WinRM host.
- [x] **E76** Least privilege: dedicated SOAR service account, not Domain Admin. — **Done**: `docs/SERVICE_ACCOUNT.md`; `validate_identity` in `soar/responder_config.py`; tests.
- [x] **E77** Pin dependencies in a requirements file with hashes. — **Done**: `requirements.txt` (pyyaml==6.0.3, 73 hashes) + `requirements-dev.txt` (pip-compile); `--require-hashes` in CI/Docker/README; `requests` dropped (unused).
- [x] **E78** Dependabot and a CI security scan. — **Done**: `.github/dependabot.yml`; CI job `security-scan` (pip-audit + bandit). Both clean locally; CI run not yet observed.

## Phase 4 — Privacy & data handling (E43–E56)

- [x] **E43** Privacy section explaining what data is stored. — **Done**: `docs/PRIVACY.md` + README '🔏 Privacy' section; test.
- [x] **E44** Redact secrets in logged command lines. — **Done**: `soar/redaction.py` applied at ingest, incident storage, evidence and logging; `tests/test_redaction.py`.
- [x] **E45** Mask usernames in demo data and screenshots. — **Done**: `soar/privacy.py`, masking in `_send_json` for incident endpoints and in reports (default on); `tests/test_privacy.py`.
- [x] **E46** Don't commit real telemetry or logs. — **Done**: verified 0 tracked telemetry files; `.gitignore` patterns; `tests/test_no_real_telemetry.py`; PRIVACY.md rule.
- [x] **E47** Set and enforce a log retention period. — **Done**: `apply_retention` (sweeper), bounded syslog deque, rotating `LOG_FILE`; PRIVACY.md updated; tests.
- [x] **E48** Data minimization: ingest only the fields detections need. — **Done**: `DETAIL_FIELD_ALLOWLIST` in `soar/input_validation.py`; dropped field names reported; PRIVACY.md section; tests.
- [x] **E49** Document that IPs sent to VirusTotal/AbuseIPDB leave your environment. — **Done**: PRIVACY.md 'External threat-intel enrichment: what leaves your environment' section; test.
- [x] **E50** Never send internal/RFC1918 IPs to external APIs. — **Done**: `soar/enrichment.py` (`is_shareable_ip`, opt-in client) wired into `enrich_threat_intel`; `tests/test_enrichment.py`. Not run against live APIs (needs your keys).
- [x] **E51** Never send hostnames, usernames or file contents to enrichment APIs. — **Done**: `classify_indicator`/`lookup` in `soar/enrichment.py`; pipeline sends only IP + hash; spy test over all scenarios.
- [x] **E52** Option to disable external enrichment. — **Done**: health probes gated on enrichment; `/api/enrichment` + `/api/enrichment/config`; PRIVACY.md updated; tests.
- [x] **E53** Document the local LRU IoC cache and how to clear it. — **Done**: `IocCache` in `soar/enrichment.py`; `/api/enrichment/cache/clear`; PRIVACY.md row; tests.
- [x] **E54** Use synthetic data in the public demo. — **Done**: RFC 5737 IPs + 'Fictional ... (lab data)' providers everywhere; `tests/test_synthetic_demo_data.py`.
- [x] **E55** Audit-log note on who can view the Sysmon streams. — **Done**: `DATA_ACCESS` audit lines in `server.py`; PRIVACY.md 'Who can view telemetry'; test.
- [x] **E56** Dashboard doesn't expose real employee data. — **Done**: `data_source` on identity responses, console badge, PRIVACY.md note; tests.

## Phase 4b — Third-party API compliance (E57–E64)

- [x] **E57** Follow the VirusTotal API terms (free tier is non-commercial). — **Done**: `virustotal_allowed()` enforcement in `soar/enrichment.py`; `docs/THIRD_PARTY_APIS.md`; tests. Terms summary should be re-verified against VirusTotal's current ToS.
- [x] **E58** Respect the VirusTotal rate limit (4 req/min free) with backoff. — **Done**: `ProviderLimiter` in `soar/enrichment.py` for VirusTotal; docs; tests with an injected clock.
- [x] **E59** Respect AbuseIPDB limits and terms. — **Done**: AbuseIPDB limiter in `soar/enrichment.py`; THIRD_PARTY_APIS.md section; tests. Quota default should be set to your actual plan.
- [x] **E60** Attribute VirusTotal and AbuseIPDB where required. — **Done**: `attributed()` on every provider verdict; console + report attribution; docs; tests.
- [x] **E61** Don't redistribute their data in the repo. — **Done**: `strip_provider_data` used by dossier export; THIRD_PARTY_APIS.md 'No redistribution'; repo-scan test.
- [x] **E62** Enrichment down means no auto-containment on enrichment alone. — **Done**: `_call` + `enrichment_degraded` in `soar/enrichment.py`; `score_without_intel` gating in `soar/risk_engine.py`; docs; tests.
- [x] **E63** A single reputation score never triggers a block; require corroboration. — **Done**: `soar/reputation.py` consensus used by `RiskAndPolicyEngine`; docs 'Corroboration'; tests.
- [x] **E64** Show source and timestamp for every enrichment verdict. — **Done**: provenance on every signal in `soar/reputation.py`; dossier verdict table (`#intelVerdicts`) and report table; tests.

## Phase 4c — Legal, licensing & attribution (E79–E88)

- [x] **E79** Verify the MIT license file exists. — **Done earlier** (176e547): `LICENSE` (MIT) exists at the repo root.
- [x] **E80** Credit Wazuh, Sysmon, Sigma and pfSense; respect their licenses. — **Done**: `docs/THIRD_PARTY_NOTICES.md`; README credits section; OSM/CARTO attribution restored in `web/app.js`; test.
- [x] **E81** Check the license of any reused Sysmon config and credit the author. — **Done**: provenance header in `sysmonconfig.xml`, credit in `Vagrantfile`, notices section. sysmon-modular's licence is referenced, not restated.
- [x] **E82** Credit sources of any adapted Sigma rules. — **Done**: `rules/sigma/README.md` provenance + DRL 1.1 adaptation rules; normalised authors; `tests/test_sigma_metadata.py`.
- [x] **E83** MITRE ATT&CK attribution and terms notice. — **Done**: `docs/LEGAL.md` ATT&CK section; README '⚖️ Legal'; `tests/test_legal_notices.py`.
- [x] **E84** Trademark disclaimer (Microsoft, Fortinet, pfSense, VirusTotal). — *(Process note: a flaky test aborted this item's own commit and its changes landed in the E85 commit 2572b4a; history was not rewritten.)* **Done**: 'Trademarks' section in `docs/LEGAL.md`; test.
- [x] **E85** "Not affiliated with" statement. — **Done**: 'Not affiliated' in `docs/LEGAL.md` + README; test.
- [x] **E86** Disclaimer of warranty and liability for the automation. — **Done**: 'No warranty; no liability for automated actions' in `docs/LEGAL.md` + README; test.
- [x] **E87** Notice that users need authorization before deploying on any network. — **Done**: 'Authorisation required before deployment' in `docs/LEGAL.md` + README; test.
- [x] **E88** Clarify no real client data was used. — **Done**: verified no client/internship data (search 2026-11-01); 'No real client or employer data' in `docs/LEGAL.md` + README; test.

## Phase 4d — Documentation, transparency & accountability (E89–E100)

- [x] **E89** SECURITY.md with a vulnerability reporting process. — **Done earlier** (176e547): `SECURITY.md` includes a vulnerability reporting process.
- [x] **E90** CODE_OF_CONDUCT.md. — **Done**: `CODE_OF_CONDUCT.md`.
- [x] **E91** CONTRIBUTING.md with ethical-use rules. — **Done**: `CONTRIBUTING.md`.
- [x] **E92** "Responsible Use" section in the README. — **Done**: README "Responsible Use"; `tests/test_doc_links.py` checks relative links.
- [x] **E93** Document every automated action and its failure mode. — **Done**: `scripts/document_actions.py` → `docs/AUTOMATED_ACTIONS.md` (12 actions + 9 side effects), test-enforced.
- [x] **E94** Known false-positive scenarios per rule. — **Done**: `scripts/rule_docs.py` → `docs/FALSE_POSITIVES.md` (all 50 rules and correlations), test-enforced.
- [x] **E95** Rule exclusions and tuning guidance. — **Done**: `docs/TUNING.md`, linked from README and `FALSE_POSITIVES.md`.
- [x] **E96** Rules of Engagement doc for the lab. — **Done**: `docs/RULES_OF_ENGAGEMENT.md` (fill-in template matching the code's allowlists), linked from README.
- [x] **E97** Log every automated action (who/what/why/when) in tamper-evident form. — **Done**: `soar/action_ledger.py` (hash-chained who/what/why/when), hooked into every containment entry point and the kill switch, `GET /api/audit/actions`, `--verify` CLI. Tamper-evident, not tamper-proof (documented).
- [x] **E98** Appeals/review flow: analysts mark containment wrong, the rule gets tuned. — **Done**: `soar/appeals.py`, appeal/decide/tuned endpoints (decide is lead-only), draft exceptions never auto-applied, `docs/APPEALS.md`.
- [x] **E99** Ethics and risk register (outage, wrongful lockout, missed detections). — **Done**: `docs/RISK_REGISTER.md` (11 risks, judgement ratings, controls, residual risk), linked from README.
- [x] **E100** Changelog records every change in automation behavior. — **Done**: CHANGELOG "Automation behaviour" section + `scripts/automation_fingerprint.py`; test fails on unrecorded automation changes.

## Phase 5 — Engineering quality (F86–F95)

- [x] **F86** ⭐ Docker Compose for a one-command lab start. — **Done** (container run unverified: Docker daemon not running here; `docker compose config` validates): root `compose.yaml`; README quickstart; `tests/test_compose.py`.
- [x] **F87** ⭐ GitHub Actions CI: lint, test, security scan. — **Done**: lint/test/security jobs (earlier commits + E74/E78) plus least-privilege `permissions`, concurrency and timeouts; `tests/test_ci_workflow.py`. CI not yet observed on GitHub.
- [x] **F88** Unit and integration tests with coverage badges. — **Done**: `.coveragerc` (floor 75%), CI coverage + job summary, dated README badge (79%, measured 2026-11-01).
- [x] **F89** Terraform or Vagrant for lab provisioning. — **Done** (not executed: Vagrant not installed here): `deploy/vagrant/Vagrantfile` provisions DC + workstation (Sysmon, WinRM HTTPS) + Wazuh host; `tests/test_vagrant.py` static checks.
- [x] **F90** Ansible roles to deploy Sysmon and Wazuh agents. — **Done** (not executed: Ansible not installed here): `deploy/ansible/` playbook + `sysmon`/`wazuh_agent` roles; `tests/test_ansible.py` static checks.
- [x] **F91** Structured logging and metrics (Prometheus, Grafana). — **Done**: `soar/observability.py`, `LOG_FORMAT=json`, `/metrics`; `deploy/monitoring/` Prometheus + Grafana examples (statically tested only); tests.
- [x] **F92** Plugin architecture for new enrichers and responders. — **Done**: `soar/plugins.py` registry + allowlisted loader; `plugins/` examples; engine/pipeline wiring; `tests/test_plugins.py`.
- [x] **F93** Config file with schema validation. — **Done**: `soar/config.py` schema + `python -m soar.config --check`; `config/cyberpulse.example.yml`; startup validation in `server.py`; `tests/test_config.py`.
- [x] **F94** Type hints and static analysis (mypy, ruff). — **Done**: `pyproject.toml` ruff + mypy config; codebase ruff-clean; 10 modules strictly typed; CI lint/type steps; `requirements-typecheck.txt` (hash-pinned).
- [x] **F95** Release process with tags and semantic versioning. — **Done**: `docs/RELEASING.md`, `.github/workflows/release.yml`, `scripts/release_notes.py`, `tests/test_release.py`. No tag created (maintainer's decision).

## Phase 6 — Detection engineering (F1–F20)

- [x] **F1** ⭐ Expand to 40+ rules covering ATT&CK tactics end to end. — **Done** (6 commits): 22 new rules (SOC-RULE-021..042) across initial access → impact and cloud; 42 rules total; coverage test enforces ≥40 rules / ≥12 tactics.
- [x] **F2** ⭐ Detection-as-code pipeline: rules in Git, CI lints and tests every rule. — **Done**: `soar/sigma_engine.py` + `rules/soar_mapping.yml`; orchestrator uses Sigma; rule lint in `tests/test_sigma_engine.py` (CI). FPs 319 → 119 / 600.
- [x] **F3** ⭐ Unit-test each rule with positive and negative log samples. — **Done**: `rules/tests/*.yml` (2+ samples per rule, incl. exclusions); `tests/test_rule_samples.py` enforces coverage for every rule.
- [x] **F4** Validate Sigma syntax in CI with sigma-cli. — **Done** (sigma-cli step unverified locally: pySigma's `jq` dependency does not build on 32-bit Windows): CI `sigma check rules/sigma`; local spec test in `tests/test_sigma_metadata.py`; ISO dates.
- [x] **F5** Convert Sigma to Wazuh, Splunk SPL, Elastic and KQL automatically. — **Done** (not validated against live SIEMs): `soar/sigma_convert.py` + `scripts/convert_rules.py` → `rules/converted/{splunk,elastic,kql,wazuh}`; `tests/test_sigma_convert.py`.
- [x] **F6** Rule metadata standard: author, date, severity, FP notes, references. — **Done**: `rules/METADATA_STANDARD.md`; `modified` on every rule; `tests/test_rule_metadata_standard.py`.
- [x] **F7** Rule versioning and a changelog per rule. — **Done**: `version` + `detection_sha256` in `rules/soar_mapping.yml`; `rules/RULE_CHANGELOG.md`; `soar/rule_versioning.py`; `tests/test_rule_versioning.py`.
- [x] **F8** Rule-quality score (coverage, FP risk, data-source dependency). — **Done**: `docs/coverage/QUALITY.md` (generated; documented weights; baseline FPs counted per rule with `match_all`).
- [x] **F9** ⭐ Coverage heatmap exported as an ATT&CK Navigator layer. — **Done**: `scripts/export_navigator.py` → `docs/coverage/attack_navigator_layer.json`; README section; `tests/test_navigator_layer.py`.
- [x] **F10** Data-source coverage analysis. — **Done**: `scripts/coverage_report.py` → `docs/coverage/DATA_SOURCES.md`; `tests/test_coverage_reports.py`.
- [x] **F11** Detection gap report: techniques with no rule. — **Done**: `rules/coverage_targets.yml` → `docs/coverage/GAPS.md` (24/35 targets covered, 11 accepted gaps with blockers, 0 open).
- [x] **F12** Sigma correlation rules (multi-event chains). — **Done**: `soar/sigma_correlation.py` (event_count / value_count / temporal) + `rules/sigma/correlations/`: SOC-RULE-043 raw-4625 brute force, SOC-RULE-044 password spraying, SOC-RULE-045 mass file write (closes the F19 mass-rename note; Sysmon has no rename event, see rule description). Not converted to SIEM queries (documented).
- [x] **F13** Behavioral baselining (rare parent-child process pairs). — **Done**: `soar/process_baseline.py`, `scripts/rare_process_pairs.py` → `docs/BEHAVIORAL_BASELINE.md`. Triage hint only, never drives containment. Honest result: does not discriminate on the 4-pair synthetic baseline.
- [x] **F14** Threshold tuning with historical data. — **Done**: `scripts/tune_thresholds.py` (`--benign/--malicious` JSONL, `--fp-budget`) → `docs/THRESHOLD_TUNING.md` on synthetic data. No thresholds changed: synthetic data cannot justify it.
- [x] **F15** Allowlist/exception management per rule. — **Done**: `soar/rule_exceptions.py` + `rules/exceptions.yml` (owner, reason, ≤180-day expiry, no wildcard-only matches, cannot hide positive samples), `GET /api/exceptions`. EXC-0001/0002 suppress the 119 synthetic-baseline FPs; the report shows them as suppressed, not gone.
- [x] **F16** Canary-token and honeypot detection layer. — **Done**: SOC-RULE-046/047/048 + `docs/CANARIES.md`. Lab placeholder decoy names; deploying real decoys is the user's step (documented). No network honeypot shipped.
- [x] **F17** Kerberoasting, DCSync, Pass-the-Hash and Golden Ticket detections. — **Done** (3 commits): Kerberoasting re-mapped to T1558.003; Pass-the-Hash and Golden Ticket rules added; DCSync existed (SOC-RULE-008).
- [x] **F18** Living-off-the-Land binary (LOLBAS) detections. — **Done**: SOC-RULE-014..018 (certutil, mshta, regsvr32, rundll32, bitsadmin) with samples.
- [x] **F19** Ransomware precursor detections (shadow copy deletion, mass rename). — **Done**: SOC-RULE-019 shadow-copy deletion, SOC-RULE-020 recovery inhibition (T1490); mass-rename via correlation in F12.
- [x] **F20** Cloud attack detections (Azure AD, AWS CloudTrail). — **Done earlier** (8b3196c): SOC-RULE-009 (AWS AssumeRole) and SOC-RULE-010 (Entra impossible travel); extended in F1.

## Phase 7 — Adversary emulation & validation (F21–F30)

- [x] **F21** ⭐ Integrate Atomic Red Team for standardized test execution. — **Done (reference-only)**: `scripts/atomic_coverage.py` (maps, never executes or copies commands), 8 manifests in `simulator/atomic_tests/`, `docs/ATOMIC_RED_TEAM.md`. Executing atomics is the user's manual lab step (hard rule: no attack tooling). Not run against a real atomics checkout here; tested on a fixture.
- [x] **F22** Integrate MITRE Caldera for automated campaigns. — **Stub**: `soar/caldera.py`, `scripts/caldera_compare.py`, `docs/CALDERA.md`. Needs the user's Caldera server (`CALDERA_URL`/`CALDERA_API_KEY`, off by default). Tested on a hand-written fixture only; report layout unverified against a live server.
- [x] **F23** ⭐ Automated purple-team report: what ran, what fired, what missed. — **Done**: `scripts/purple_team_report.py` → `docs/PURPLE_TEAM_REPORT.md` (16/16 synthetic steps; default policy proposes, never executes). Real-lab runs go through `caldera_compare.py`.
- [x] **F24** Detection-latency histogram per technique. — **Done**: `scripts/benchmark_pipeline.py --histogram` → `docs/LATENCY_HISTOGRAM.md` (lab-measured, machine-specific; stated in the file). Also fixed the stale README latency table (3e6563e).
- [x] **F25** True/false-positive confusion matrix with real counts. — **Done**: confusion matrix section in `docs/VALIDATION_RESULTS.md` (generated, CI-checked). 660 synthetic events; pre-exception precision 0.335 published alongside.
- [x] **F26** Benign-activity generators (admin scripts, backups, patching). — 🔀 **Merged into E5**: `simulator/benign_baseline.py` already covers admin scripts, backups, patching, AV scanning, auth and cloud ops.
- [x] **F27** Regression testing: a rule change must not break old detections. — **Done**: `scripts/regression_corpus.py`, `tests/regression/expected_matches.json` (130 events), `tests/test_regression_corpus.py`.
- [x] **F28** Multi-stage attack chain emulation (initial access to exfil). — **Done**: `simulator/attack_chain.py` `run_chain()` (10 stages, 2 hosts, telemetry only, lab_only), `tests/test_attack_chain.py`. Fixed the old "DETECTED_AND_AUTO_CONTAINED" claim: reports the real (proposed) status.
- [x] **F29** Evasion tests (obfuscation, renamed binaries); document bypasses. — **Done**: `scripts/evasion_cases.py` (16 synthetic variants), `scripts/evasion_report.py` → `docs/EVASION.md`. **11/16 bypass**, all unfixed and documented with suggested fixes.
- [x] **F30** Publish a "what I missed" report. — **Done**: `scripts/what_i_missed.py` → `docs/WHAT_I_MISSED.md` (generated from evasion, gaps, regression corpus, baseline; hand-kept never-verified list).

## Phase 8 — SOAR & automation (F31–F50)

- [x] **F31** ⭐ Approval workflows via Slack, Teams or Telegram buttons. — **Done (needs your Slack app / Telegram bot)**: `soar/chatops.py`, `POST /api/chatops/slack|telegram`, `docs/CHATOPS.md`. Teams opens the console (incoming webhooks can't call back). Tested with locally signed requests only.
- [x] **F32** ⭐ Playbooks as YAML that analysts edit without touching Python. — **Done**: `soar/playbooks.py`, `playbooks/*.yml` (6 playbooks + README), wired into `process_event`; included in the container image. Playbooks can only tighten policy.
- [x] **F33** Visual playbook editor in the UI. — **Done**: `web/playbooks.html`/`playbooks.js`, `GET /api/playbooks`, `POST /api/playbooks/validate` (no writes; changes via review). Checked in the browser against a local server.
- [x] **F34** Playbook versioning and testing. — **Done**: fingerprints in `playbooks/meta/versions.yml`, `playbooks/CHANGELOG.md`, 8 behaviour cases in `playbooks/tests/cases.yml` (`python -m soar.playbooks --test`).
- [x] **F35** Case management: auto-open tickets with full context. — **Done**: `soar/case_manager.py`, `GET/POST /api/cases`, `docs/CASE_MANAGEMENT.md`. In-memory like incidents.
- [x] **F36** Integrate TheHive and Cortex. — **Done (needs your TheHive/Cortex)**: `soar/thehive.py` (`THEHIVE_ENABLED`, lab URLs only, PAP:RED on internal observables), `docs/THEHIVE_CORTEX.md`. Fixed the misleading "TheHive case created" timeline entry. Tested with a stubbed HTTP layer only.
- [x] **F37** Integrate MISP for IoC sharing. — **Done (needs your MISP)**: `soar/misp.py`, `GET /api/cases/<id>/misp`, `POST /api/cases/<id>/misp/push`, `docs/MISP.md`. Public IPs/hashes only, org-only distribution, simulated excluded, never automatic. Stubbed HTTP only.
- [x] **F38** Integrate the CIPHER project's feeds live. — **Stub (needs CIPHER's feed)**: `soar/threat_feeds.py` (JSON + STIX 2.1, local matching, ETag refresh), `GET /api/feeds`, `docs/THREAT_FEEDS.md`. CIPHER's real format not checked.
- [x] **F39** Consume GUARDIAN anomaly alerts as an ingest source. — **Stub (needs GUARDIAN)**: `soar/guardian.py`, `POST /api/ingest/guardian` (HMAC), SOC-RULE-049 (alert-only), `docs/GUARDIAN.md`. GUARDIAN's real schema not checked.
- [x] **F40** Shuffle or n8n integration as an alternative orchestrator. — **Done (needs your Shuffle/n8n)**: `soar/orchestrator_hook.py`, `docs/SHUFFLE_N8N.md`. Signed POST; full payload only to lab addresses; approvals via the normal API. Stubbed HTTP only.
- [x] **F41** Enrichment from OTX, URLhaus, Shodan, GreyNoise and Censys. — **Done (needs your keys)**: `soar/intel_providers.py` (OTX, URLhaus, GreyNoise score; Shodan, Censys context only), per-provider limits, `docs/THIRD_PARTY_APIS.md`. Never called with real keys.
- [x] **F42** Multi-source reputation scoring with weighted consensus. — **Done**: weighted consensus with `agreement` in `soar/reputation.py`, `REPUTATION_WEIGHTS`, documented defaults (judgement, not measured).
- [x] **F43** Automatic user notification for suspicious logins. — **Done (needs your SMTP + address book)**: `soar/user_notify.py` (off by default, STARTTLS, no links, never for simulated/service/protected accounts, 24 h cooldown). No email actually sent.
- [x] **F44** MFA step-up or session revocation for Entra ID. — **Done (needs your tenant)**: `soar/entra_responder.py` (revokeSignInSessions + CA step-up group, rollback), `docs/ENTRA_RESPONDER.md`. Approval-only (TIER_3). Stubbed Graph only.
- [x] **F45** Email quarantine playbook for phishing. — **Done (simulated responder)**: SOC-RULE-050, `QUARANTINE_EMAIL` (TIER_2, rollback to inbox), `playbooks/phishing.yml`, `POST /api/incidents/<id>/propose`, `docs/PHISHING.md`. Graph request built, not sent.
- [x] **F46** Phishing triage playbook (URL detonation, header analysis). — **Done**: `soar/phishing_triage.py` (offline header + URL analysis, defanged, explained score), attached to email incidents, `docs/PHISHING.md`. Detonation is F47's opt-in sandbox.
- [x] **F47** Automatic sandbox submission for suspicious files. — **Done (needs your CAPE)**: `soar/sandbox.py` (lab URL only, hash look-up automatic, URL detonation opt-in, files only from `SANDBOX_EVIDENCE_DIR`), `docs/SANDBOX.md`. Stubbed HTTP only.
- [x] **F48** Memory acquisition before isolation. — 🔀 **Merged into E29**: memory acquisition order (process dump before kill, host image before isolation) is recorded in `pre_containment_snapshot`; simulated in the lab.
- [x] **F49** Automatic evidence collection (triage package) per incident. — **Done**: `soar/triage_package.py`, `GET /api/incidents/<id>/triage-package`, optional `TRIAGE_PACKAGE_DIR`, `docs/TRIAGE_PACKAGE.md`.
- [x] **F50** Chain-of-custody hashing for collected evidence. — **Done**: `soar/custody.py` (hash-chained, verify + artifact check), `GET /api/incidents/<id>/custody`, `custody.json` in triage packages. In-process; write-once storage advised in docs.

## Phase 9 — Dashboard & UX (F51–F65)

- [x] **F51** ⭐ Attack timeline view per incident. — **Done**: `web/triage.html` + `triage.js` + shared `session.js`, `GET /api/cases/<id>/timeline` (`soar/views.py`).
- [x] **F52** ⭐ Alert triage queue with severity, status and assignee. — **Done**: `GET /api/triage/queue` (`views.triage_queue`), queue + case controls in `web/triage.html`.
- [x] **F53** Process tree visualization. — **Done**: `views.process_tree`, `GET /api/cases/<id>/process-tree`, tree panel in the triage workspace.
- [x] **F54** Network graph of attacker-to-host relationships. — **Done**: `views.network_graph`, `GET /api/graph/network`, SVG panel in the triage workspace.
- [x] **F55** MTTD/MTTR trend chart over time. — **Done**: `views.mttd_mttr_trend`, `GET /api/metrics/trend`, SVG chart (unmeasured = "not yet measured").
- [x] **F56** Top-talkers and top-rules widgets. — **Done**: `views.top_stats`, `GET /api/stats/top`, widgets in the triage workspace.
- [x] **F57** Geo-map of attacker IPs. — **Done earlier** (dd759e8): Leaflet geo-map on the Overview tab plots attacker IP origins (synthetic geo data).
- [x] **F58** Dark/light mode. — **Done**: `web/theme.js` + light tokens in `styles.css`, toggle on console, triage and playbook pages (login follows OS / saved choice).
- [x] **F59** Global search across alerts, hosts and IoCs. — **Done**: `views.search`, `GET /api/search?q=` (audited, masked), search box in the triage workspace.
- [x] **F60** Saved hunts and queries. — **Done**: `soar/hunts.py` (shared, optional `HUNTS_FILE`), `/api/hunts` endpoints, hunt chips in the triage workspace.
- [x] **F61** Role-based views (analyst, lead, auditor). — **Done**: `soar/roles.py`, server-side checks on every POST, role in sessions and audit log, `data-requires` UI hiding, README + `.env.example`.
- [x] **F62** Keyboard shortcuts for triage. — **Done**: shortcuts j/k / a i r n ? in `web/triage.js` with a help panel; disabled in text fields.
- [x] **F63** Mobile-friendly status view. — **Done**: `web/status.html` + `status.js`, `GET /api/status/summary`; checked at 375 px.
- [x] **F64** Executive summary view. — **Done**: `views.executive_summary`, `GET /api/summary/executive`, printable `web/executive.html`.
- [x] **F65** PDF export for incident reports. — **Done**: `soar/pdf_report.py` (no dependency), `GET /api/incidents/<id>/report.pdf`, console PDF button. Structure tested; parsed by pypdf.

## Phase 10 — Threat hunting (F66–F75)

- [x] **F66** Hunting workbench with pivot queries. — **Done**: `soar/event_store.py`, `views.pivot`, `GET /api/hunt/pivot`, `web/hunt.html` with click-to-pivot and breadcrumbs.
- [x] **F67** Hypothesis-driven hunt templates mapped to ATT&CK. — **Done**: 5 templates in `hunts/templates/`, `soar/hunt_templates.py` (validated, read-only), `/api/hunt/templates` + run, cards in `web/hunt.html`.
- [x] **F68** Jupyter notebook set for hunts. — **Done**: 3 notebooks in `notebooks/` + README; `tests/test_notebooks.py` executes every cell (no stored outputs). Jupyter itself not run here; cells run via the test.
- [x] **F69** Stack counting and long-tail analysis. — **Done**: `views.stack`, `GET /api/hunt/stack`, stack panel with pivots in `web/hunt.html`.
- [x] **F70** YARA scanning integration. — **Done**: `soar/yara_scan.py` (yara-python or a built-in subset that refuses unsupported syntax), `POST /api/evidence/yara-scan` (evidence dir only), `docs/YARA.md`. libyara path untested (not installed).
- [x] **F71** Velociraptor or osquery integration for live endpoint queries. — **Done (needs Fleet/Velociraptor)**: `soar/live_query.py` (catalogue-only, lab URLs), `GET /api/live-query/catalogue`, `POST /api/live-query`, `docs/LIVE_QUERIES.md`. Stubbed HTTP only.
- [x] **F72** Zeek/Suricata network sensor with detections. — **Done (needs your sensors)**: `soar/network_sensors.py`, `POST /api/ingest/network` (HMAC, batched), SOC-RULE-051/052, `docs/NETWORK_SENSORS.md`. No live sensor connected.
- [x] **F73** DNS tunneling and beaconing detection. — **Done**: SOC-RULE-053 (unique-subdomain correlation), SOC-RULE-054 (long labels), `soar/beaconing.py` + `/api/hunt/beacons` (leads, not alerts). Synthetic records only.
- [x] **F74** JA3/JA4 TLS fingerprint detections. — **Done**: SOC-RULE-055 (placeholders marked synthetic), `scripts/update_tls_blocklist.py`, ja3/ja4/SNI pivots. No real fingerprint list shipped (unverifiable); user loads one.
- [x] **F75** Hunt-to-detection workflow: a hunt finding becomes a rule. — **Done**: `soar/hunt_to_rule.py`, `POST /api/hunt/draft-rule` (never saved or enabled), workbench button, `docs/HUNTING.md`.

## Phase 10b — Reporting & documentation (F76–F85)

- [x] **F76** ⭐ Auto-generate NIST 800-61 incident reports from case data. — **Done earlier** (eb1755d): `soar/report_generator.py` builds NIST SP 800-61 HTML/JSON reports from case data.
- [x] **F77** Post-incident review templates. — **Done**: `docs/templates/POST_INCIDENT_REVIEW.md`, `soar/post_incident.py`, `GET /api/cases/<id>/review` (Markdown), triage button.
- [x] **F78** Runbooks for each detection. — **Done**: `docs/runbooks/` (55 runbooks + index) generated by `scripts/rule_docs.py`, test-enforced, linked from README.
- [ ] **F79** ⭐ Short demo video or GIF at the top of the README.
- [ ] **F80** Architecture diagram in the README that renders properly.
- [ ] **F81** Docs site (MkDocs or GitHub Pages).
- [ ] **F82** Blog series: "how I built each detection".
- [ ] **F83** Detection write-up per rule: mechanics, telemetry, tuning.
- [ ] **F84** Video walkthrough of an incident from alert to closure.
- [ ] **F85** Metrics page with honest, sourced numbers.

## Phase 10c — Differentiators (F96–F100)

- [ ] **F96** ⭐ LLM-assisted triage summary; the analyst keeps final say.
- [ ] **F97** Natural-language hunt queries translated to SPL/KQL.
- [ ] **F98** Detection-quality leaderboard across the rules.
- [ ] **F99** Public "red vs blue" scenario pack others can reuse.
- [ ] **F100** ⭐ Honest case study: what worked, what failed, what I'd change.
