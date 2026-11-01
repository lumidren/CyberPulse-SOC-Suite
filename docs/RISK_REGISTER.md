# Ethics and Risk Register

Roadmap E99. What can go wrong when CyberPulse is used, who is harmed, how likely and how
bad it is in a lab deployment, what already reduces it, and what is left. Ratings are the
maintainer's judgement (Low / Medium / High), not measured probabilities. Review this page
whenever automation behaviour changes (see the "Automation behaviour" section of
[CHANGELOG.md](../CHANGELOG.md)).

| ID | Risk | Who is harmed | Likelihood | Impact | Controls in place | Residual risk and owner action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| R1 | **Business outage** from isolating a server or blocking a shared IP | Everyone relying on the service | Medium | High | Approval required by default; protected-asset list; TIER_2/3 always approved; isolation circuit breaker + kill switch; TTLs; rollback ([AUTOMATED_ACTIONS.md](AUTOMATED_ACTIONS.md)) | Medium: an analyst can still approve a bad isolation. Keep the protected-asset list current. |
| R2 | **Wrongful lockout** of a person (account disabled, sessions revoked, mail quarantined) | The employee, their work | Medium | Medium | Identity actions are TIER_3 (always approved); protected accounts; appeals flow ([APPEALS.md](APPEALS.md)); rollback where possible | Medium: revoked sessions cannot be restored. Tell the person; record the appeal outcome. |
| R3 | **Missed detection** of a real attack (rule bypassed, gap, untuned) | The organisation | High | High | Gap report, evasion tests, regression corpus, purple-team reports ([WHAT_I_MISSED.md](WHAT_I_MISSED.md)) | High: rules are tested on synthetic data only and 11 known bypasses are unfixed. Never present lab results as real coverage. |
| R4 | **Alert fatigue** leading analysts to ignore true alerts | Analysts, the organisation | Medium | High | Exceptions with expiry, threshold tuning, quality scores, false-positive catalogue | Medium: real-world noise is unknown until the rules run on real telemetry. |
| R5 | **Over-trust in automation** (approving whatever is proposed) | Everyone affected by actions | Medium | High | Rationale, rule confidence and risk factors shown with every proposal; corroborated reputation only; LLM output (if added) advisory only | Medium: approval fatigue is a human factor; rotate and review approvals. |
| R6 | **Privacy harm**: telemetry and cases name people; exports leave the system | Employees | Medium | Medium | Username masking, retention, data minimisation, pseudonymised external messages, no internal identifiers to third parties ([PRIVACY.md](PRIVACY.md)) | Low-Medium: triage packages and ledgers on disk hold personal data; restrict access. |
| R7 | **Misuse of the simulator or integrations to attack others** | Third parties | Low | High | Telemetry-only simulator, lab-mode flag, lab CIDR/account allowlists, no offensive tooling, Rules of Engagement ([RULES_OF_ENGAGEMENT.md](RULES_OF_ENGAGEMENT.md)) | Low: Atomic/Caldera are outside CyberPulse's control; the RoE assigns responsibility. |
| R8 | **Tip-off to an attacker** (sandbox detonation, public lookups, user notification) | The investigation | Low | Medium | URL detonation opt-in; public sandboxes refused; only public indicators sent to providers; user emails off by default | Low. |
| R9 | **Breaking third-party terms** (rate limits, non-commercial APIs, redistribution) | The deployer, providers | Low | Medium | Client-side quotas, commercial-use gate for VirusTotal, attribution, no redistribution of provider data ([THIRD_PARTY_APIS.md](THIRD_PARTY_APIS.md)) | Low: terms change; re-check before enabling a key. |
| R10 | **Compromise of CyberPulse itself** turning it into an attack tool (responder credentials, approval API) | The whole estate | Low | High | Auth on every endpoint, roles, CSRF, rate limits, HMAC ingest, least-privilege responder identities, command allowlists, tamper-evident action ledger | Medium if live responders are enabled: protect their credentials like domain admin. |
| R11 | **Misleading claims** about effectiveness (portfolio, reports) | Readers, employers, customers | Medium | Medium | Honest-claims tests, "not yet measured" rule, generated reports with caveats | Low. |

## How to use this register

- Before enabling opt-in AUTOMATIC mode, any live responder, or an external integration,
  read R1, R2, R5, R8 and R10 and confirm the controls are configured.
- After an incident where automation caused harm, add or re-rate the risk here in the same
  change that fixes it, and link the appeal.
