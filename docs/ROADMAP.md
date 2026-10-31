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
- [ ] **E7** Stop comparing a 20 min manual MTTR to automated pipeline seconds.
- [ ] **E8** Add a Limitations section to the README.
- [ ] **E9** State that the rules are untested against real-world noise.
- [ ] **E10** Mark INC-2026-0815-01 and -02 as simulated incidents.
- [ ] **E11** Remove "Formal" from incident report headings, or label them exercises.
- [ ] **E12** Make the README resume block accurate, or move it out of the repo.

## Phase 2 — Human oversight & safe automation (E13–E30)

- [ ] **E13** Remove "no human-in-the-loop" as a selling point.
- [ ] **E14** Add an approval mode: an analyst confirms before containment runs.
- [ ] **E15** Make approval the default; full-auto is opt-in.
- [ ] **E16** Tier actions by blast radius (auto IP block; approval for host isolation and account lockdown).
- [ ] **E17** Add a global kill switch that halts all automation.
- [x] **E18** Add a dry-run mode that logs what it would do. — **Done earlier**: DRY_RUN policy mode records `SIMULATED_NO_DISRUPTION` actions (`soar/resilient_containment.py`, test `test_dry_run_policy_mode`).
- [ ] **E19** Add a confidence threshold; below it, escalate instead of acting.
- [ ] **E20** Rate-limit containment actions per hour.
- [ ] **E21** Circuit breaker: if N hosts are isolated in M minutes, stop and page a human.
- [ ] **E22** Allowlist of assets that can never be auto-isolated (DCs, SOC hosts, jump boxes).
- [ ] **E23** Protected-accounts list that can never be auto-locked.
- [ ] **E24** Protect the DC specifically: never auto-isolate 10.0.0.10.
- [ ] **E25** Auto-expiry (TTL) on isolation rules.
- [ ] **E26** One-click rollback for every action.
- [ ] **E27** Store pre-action state so rollback restores it.
- [ ] **E28** Replace `taskkill /F /T` with graceful-first termination, or document the data-loss risk.
- [ ] **E29** Snapshot memory/process info before killing a process.
- [ ] **E30** Export scheduled-task XML before removing a task.

## Phase 2b — Simulator safety (E31–E42)

- [ ] **E31** Bold warning: lab use only, never on production or networks you don't own.
- [ ] **E32** Simulator refuses to run unless a lab flag is set.
- [ ] **E33** Target allowlist limited to the lab CIDR.
- [ ] **E34** Block the simulator from running against public IPs.
- [ ] **E35** Confirm the LSASS "dump" is simulated, not a real credential dump.
- [ ] **E36** If it touches real credentials, document that and use dummy accounts only.
- [ ] **E37** Don't ship working credential-theft tooling; emulate the telemetry instead.
- [ ] **E38** Brute-force simulation targets only lab accounts with fake passwords.
- [ ] **E39** Rate-limit the brute-force simulation.
- [ ] **E40** Tag all simulated events with `simulation=true`.
- [ ] **E41** Dashboard visibly shows when data is simulated.
- [ ] **E42** Test-mode banner in the UI.

## Phase 3 — Securing the tool itself (E65–E78)

- [ ] **E65** Authentication on the localhost:5000 dashboard.
- [ ] **E66** Bind to 127.0.0.1 by default; document the 0.0.0.0 risk.
- [ ] **E67** CSRF protection on the simulation trigger endpoints.
- [ ] **E68** HMAC-signature authentication on the SOAR webhook receiver.
- [ ] **E69** Validate and sanitize all webhook inputs.
- [ ] **E70** Prevent command injection in taskkill/netsh/iptables calls; never concatenate strings.
- [ ] **E71** Parameterized, validated arguments for WinRM and PowerShell.
- [ ] **E72** Never hardcode API keys; use environment variables or a secrets manager.
- [x] **E73** Add `.env.example` and a `.gitignore` for secrets. — **Done earlier** (62c8760, 176e547): `.env.example` documents every setting; `.gitignore` excludes `.env*`.
- [ ] **E74** Scan repo history for leaked keys (gitleaks/trufflehog).
- [ ] **E75** WinRM over HTTPS with certificate validation, not skip-verify.
- [ ] **E76** Least privilege: dedicated SOAR service account, not Domain Admin.
- [ ] **E77** Pin dependencies in a requirements file with hashes.
- [ ] **E78** Dependabot and a CI security scan.

## Phase 4 — Privacy & data handling (E43–E56)

- [ ] **E43** Privacy section explaining what data is stored.
- [ ] **E44** Redact secrets in logged command lines.
- [ ] **E45** Mask usernames in demo data and screenshots.
- [ ] **E46** Don't commit real telemetry or logs.
- [ ] **E47** Set and enforce a log retention period.
- [ ] **E48** Data minimization: ingest only the fields detections need.
- [ ] **E49** Document that IPs sent to VirusTotal/AbuseIPDB leave your environment.
- [ ] **E50** Never send internal/RFC1918 IPs to external APIs.
- [ ] **E51** Never send hostnames, usernames or file contents to enrichment APIs.
- [ ] **E52** Option to disable external enrichment.
- [ ] **E53** Document the local LRU IoC cache and how to clear it.
- [ ] **E54** Use synthetic data in the public demo.
- [ ] **E55** Audit-log note on who can view the Sysmon streams.
- [ ] **E56** Dashboard doesn't expose real employee data.

## Phase 4b — Third-party API compliance (E57–E64)

- [ ] **E57** Follow the VirusTotal API terms (free tier is non-commercial).
- [ ] **E58** Respect the VirusTotal rate limit (4 req/min free) with backoff.
- [ ] **E59** Respect AbuseIPDB limits and terms.
- [ ] **E60** Attribute VirusTotal and AbuseIPDB where required.
- [ ] **E61** Don't redistribute their data in the repo.
- [ ] **E62** Enrichment down means no auto-containment on enrichment alone.
- [ ] **E63** A single reputation score never triggers a block; require corroboration.
- [ ] **E64** Show source and timestamp for every enrichment verdict.

## Phase 4c — Legal, licensing & attribution (E79–E88)

- [x] **E79** Verify the MIT license file exists. — **Done earlier** (176e547): `LICENSE` (MIT) exists at the repo root.
- [ ] **E80** Credit Wazuh, Sysmon, Sigma and pfSense; respect their licenses.
- [ ] **E81** Check the license of any reused Sysmon config and credit the author.
- [ ] **E82** Credit sources of any adapted Sigma rules.
- [ ] **E83** MITRE ATT&CK attribution and terms notice.
- [ ] **E84** Trademark disclaimer (Microsoft, Fortinet, pfSense, VirusTotal).
- [ ] **E85** "Not affiliated with" statement.
- [ ] **E86** Disclaimer of warranty and liability for the automation.
- [ ] **E87** Notice that users need authorization before deploying on any network.
- [ ] **E88** Clarify no real client data was used.

## Phase 4d — Documentation, transparency & accountability (E89–E100)

- [x] **E89** SECURITY.md with a vulnerability reporting process. — **Done earlier** (176e547): `SECURITY.md` includes a vulnerability reporting process.
- [ ] **E90** CODE_OF_CONDUCT.md.
- [ ] **E91** CONTRIBUTING.md with ethical-use rules.
- [ ] **E92** "Responsible Use" section in the README.
- [ ] **E93** Document every automated action and its failure mode.
- [ ] **E94** Known false-positive scenarios per rule.
- [ ] **E95** Rule exclusions and tuning guidance.
- [ ] **E96** Rules of Engagement doc for the lab.
- [ ] **E97** Log every automated action (who/what/why/when) in tamper-evident form.
- [ ] **E98** Appeals/review flow: analysts mark containment wrong, the rule gets tuned.
- [ ] **E99** Ethics and risk register (outage, wrongful lockout, missed detections).
- [ ] **E100** Changelog records every change in automation behavior.

## Phase 5 — Engineering quality (F86–F95)

- [ ] **F86** ⭐ Docker Compose for a one-command lab start.
- [ ] **F87** ⭐ GitHub Actions CI: lint, test, security scan.
- [ ] **F88** Unit and integration tests with coverage badges.
- [ ] **F89** Terraform or Vagrant for lab provisioning.
- [ ] **F90** Ansible roles to deploy Sysmon and Wazuh agents.
- [ ] **F91** Structured logging and metrics (Prometheus, Grafana).
- [ ] **F92** Plugin architecture for new enrichers and responders.
- [ ] **F93** Config file with schema validation.
- [ ] **F94** Type hints and static analysis (mypy, ruff).
- [ ] **F95** Release process with tags and semantic versioning.

## Phase 6 — Detection engineering (F1–F20)

- [ ] **F1** ⭐ Expand to 40+ rules covering ATT&CK tactics end to end.
- [ ] **F2** ⭐ Detection-as-code pipeline: rules in Git, CI lints and tests every rule.
- [ ] **F3** ⭐ Unit-test each rule with positive and negative log samples.
- [ ] **F4** Validate Sigma syntax in CI with sigma-cli.
- [ ] **F5** Convert Sigma to Wazuh, Splunk SPL, Elastic and KQL automatically.
- [ ] **F6** Rule metadata standard: author, date, severity, FP notes, references.
- [ ] **F7** Rule versioning and a changelog per rule.
- [ ] **F8** Rule-quality score (coverage, FP risk, data-source dependency).
- [ ] **F9** ⭐ Coverage heatmap exported as an ATT&CK Navigator layer.
- [ ] **F10** Data-source coverage analysis.
- [ ] **F11** Detection gap report: techniques with no rule.
- [ ] **F12** Sigma correlation rules (multi-event chains).
- [ ] **F13** Behavioral baselining (rare parent-child process pairs).
- [ ] **F14** Threshold tuning with historical data.
- [ ] **F15** Allowlist/exception management per rule.
- [ ] **F16** Canary-token and honeypot detection layer.
- [ ] **F17** Kerberoasting, DCSync, Pass-the-Hash and Golden Ticket detections.
- [ ] **F18** Living-off-the-Land binary (LOLBAS) detections.
- [ ] **F19** Ransomware precursor detections (shadow copy deletion, mass rename).
- [x] **F20** Cloud attack detections (Azure AD, AWS CloudTrail). — **Done earlier** (8b3196c): SOC-RULE-009 (AWS AssumeRole) and SOC-RULE-010 (Entra impossible travel); extended in F1.

## Phase 7 — Adversary emulation & validation (F21–F30)

- [ ] **F21** ⭐ Integrate Atomic Red Team for standardized test execution.
- [ ] **F22** Integrate MITRE Caldera for automated campaigns.
- [ ] **F23** ⭐ Automated purple-team report: what ran, what fired, what missed.
- [ ] **F24** Detection-latency histogram per technique.
- [ ] **F25** True/false-positive confusion matrix with real counts.
- [x] **F26** Benign-activity generators (admin scripts, backups, patching). — 🔀 **Merged into E5**: `simulator/benign_baseline.py` already covers admin scripts, backups, patching, AV scanning, auth and cloud ops.
- [ ] **F27** Regression testing: a rule change must not break old detections.
- [ ] **F28** Multi-stage attack chain emulation (initial access to exfil).
- [ ] **F29** Evasion tests (obfuscation, renamed binaries); document bypasses.
- [ ] **F30** Publish a "what I missed" report.

## Phase 8 — SOAR & automation (F31–F50)

- [ ] **F31** ⭐ Approval workflows via Slack, Teams or Telegram buttons.
- [ ] **F32** ⭐ Playbooks as YAML that analysts edit without touching Python.
- [ ] **F33** Visual playbook editor in the UI.
- [ ] **F34** Playbook versioning and testing.
- [ ] **F35** Case management: auto-open tickets with full context.
- [ ] **F36** Integrate TheHive and Cortex.
- [ ] **F37** Integrate MISP for IoC sharing.
- [ ] **F38** Integrate the CIPHER project's feeds live.
- [ ] **F39** Consume GUARDIAN anomaly alerts as an ingest source.
- [ ] **F40** Shuffle or n8n integration as an alternative orchestrator.
- [ ] **F41** Enrichment from OTX, URLhaus, Shodan, GreyNoise and Censys.
- [ ] **F42** Multi-source reputation scoring with weighted consensus.
- [ ] **F43** Automatic user notification for suspicious logins.
- [ ] **F44** MFA step-up or session revocation for Entra ID.
- [ ] **F45** Email quarantine playbook for phishing.
- [ ] **F46** Phishing triage playbook (URL detonation, header analysis).
- [ ] **F47** Automatic sandbox submission for suspicious files.
- [ ] **F48** Memory acquisition before isolation.
- [ ] **F49** Automatic evidence collection (triage package) per incident.
- [ ] **F50** Chain-of-custody hashing for collected evidence.

## Phase 9 — Dashboard & UX (F51–F65)

- [ ] **F51** ⭐ Attack timeline view per incident.
- [ ] **F52** ⭐ Alert triage queue with severity, status and assignee.
- [ ] **F53** Process tree visualization.
- [ ] **F54** Network graph of attacker-to-host relationships.
- [ ] **F55** MTTD/MTTR trend chart over time.
- [ ] **F56** Top-talkers and top-rules widgets.
- [x] **F57** Geo-map of attacker IPs. — **Done earlier** (dd759e8): Leaflet geo-map on the Overview tab plots attacker IP origins (synthetic geo data).
- [ ] **F58** Dark/light mode.
- [ ] **F59** Global search across alerts, hosts and IoCs.
- [ ] **F60** Saved hunts and queries.
- [ ] **F61** Role-based views (analyst, lead, auditor).
- [ ] **F62** Keyboard shortcuts for triage.
- [ ] **F63** Mobile-friendly status view.
- [ ] **F64** Executive summary view.
- [ ] **F65** PDF export for incident reports.

## Phase 10 — Threat hunting (F66–F75)

- [ ] **F66** Hunting workbench with pivot queries.
- [ ] **F67** Hypothesis-driven hunt templates mapped to ATT&CK.
- [ ] **F68** Jupyter notebook set for hunts.
- [ ] **F69** Stack counting and long-tail analysis.
- [ ] **F70** YARA scanning integration.
- [ ] **F71** Velociraptor or osquery integration for live endpoint queries.
- [ ] **F72** Zeek/Suricata network sensor with detections.
- [ ] **F73** DNS tunneling and beaconing detection.
- [ ] **F74** JA3/JA4 TLS fingerprint detections.
- [ ] **F75** Hunt-to-detection workflow: a hunt finding becomes a rule.

## Phase 10b — Reporting & documentation (F76–F85)

- [x] **F76** ⭐ Auto-generate NIST 800-61 incident reports from case data. — **Done earlier** (eb1755d): `soar/report_generator.py` builds NIST SP 800-61 HTML/JSON reports from case data.
- [ ] **F77** Post-incident review templates.
- [ ] **F78** Runbooks for each detection.
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
