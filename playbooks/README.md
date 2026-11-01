# Response Playbooks

Edit these YAML files to change how CyberPulse handles an alert; no Python
needed (roadmap F32). Format and rules: `soar/playbooks.py`.

| File | Handles | Notes |
| :--- | :--- | :--- |
| `credential-theft.yml` | T1003, T1558, T1550 | Always asks for approval |
| `ransomware.yml` | T1486, T1490 | Always asks for approval |
| `brute-force.yml` | T1110 | Leaves the opt-in TIER_1 firewall block to policy |
| `cloud-identity.yml` | T1078, T1548, T1528, T1562.008 | Always asks for approval |
| `deception.yml` | SOC-RULE-046/047/048 | Decoy hits |
| `default.yml` | everything else | Generic triage tasks |

What a playbook can do: choose the containment action to **propose**, set a
minimum risk score below which it only alerts, force analyst approval even in
opt-in automatic mode, switch notifications off, and attach an analyst task
list to the case.

What it cannot do: turn on automatic execution, skip approval, skip the
evidence collected before containment, or name an action the containment
engine does not know. The loader rejects any such field.

Selection: a playbook listing the rule id wins; otherwise the most specific
technique match (exact sub-technique beats parent); otherwise `default.yml`.

Changes are reviewed like code: open a pull request, and the test suite loads
every playbook and checks its routing.

## Versioning and tests (F34)

- Every playbook has a semantic `version`. `playbooks/meta/versions.yml` records it with a
  SHA-256 fingerprint of the behaviour (`match`, `response`, `tasks`; not the description).
  Changing behaviour without bumping the version, updating `meta/versions.yml` and adding a
  `CHANGELOG.md` entry fails the test suite.
- `playbooks/tests/cases.yml` holds behaviour cases: a matched rule plus the policy decision,
  and the expected playbook, action and execution intent. Run them with
  `python -m soar.playbooks --test`; the unit tests run them too.

