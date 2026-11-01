# Rules of Engagement for the CyberPulse Lab

Roadmap E96. These rules apply to anyone running simulations, purple-team exercises,
Atomic Red Team tests or Caldera operations against a CyberPulse lab. Fill in the
bracketed fields for your lab and keep a signed copy with the exercise record.

## 1. Authorisation

- **Lab owner:** [name / team]. Only the owner, or someone they authorise in writing,
  may run exercises.
- **Exercise lead:** [name]. Accountable for following these rules and for stopping.
- Written authorisation names the scope, the window and the people involved. An exercise
  without it does not start.

## 2. Scope

| In scope | Out of scope (never) |
| :--- | :--- |
| Hosts inside the lab CIDRs: `CYBERPULSE_LAB_CIDRS` (default `10.0.0.0/16`; public ranges are refused by the code) | Any address outside the lab CIDRs, production networks, the internet |
| Lab accounts matching `CYBERPULSE_LAB_ACCOUNTS` (default `lab.*`) for credential scenarios | Real user, admin, service or break-glass accounts |
| The lab's own cloud test accounts and tenants | Production cloud accounts or tenants |
| VMs built for the lab (Vagrant/Ansible in `deploy/`), snapshotted before each exercise | Shared or personal machines |

The simulator enforces the CIDR and account allowlists and refuses to run without
`CYBERPULSE_LAB_MODE=true`. Atomic Red Team and Caldera are **not** constrained by
CyberPulse: you must point them only at in-scope lab VMs yourself.

## 3. Permitted and prohibited activity

**Permitted:** CyberPulse's telemetry generators; Atomic Red Team tests and Caldera
abilities run on in-scope lab VMs; detection, triage and containment of the results,
including approving lab containment.

**Prohibited:** real credential theft or exfiltration of real data; destructive actions
outside snapshotted lab VMs; denial of service; disabling security tooling on anything
that is not a lab VM; anything that sends lab telemetry, credentials or attack traffic to
third parties (public sandboxes, public paste sites, unsanctioned cloud storage).

## 4. Timing and rate limits

- Exercise window: [start - end, time zone]. Nothing runs outside it.
- The simulator's own throttle caps runs at `SIM_PER_MIN` (default 60/min) and brute-force
  scenarios at `SIM_BRUTE_FORCE_PER_MIN` (default 6/min). Keep external tools at a
  comparable pace so lab services and responders are not overloaded.

## 5. Automation during exercises

- Run with the default `APPROVAL_REQUIRED` policy unless the exercise is specifically
  about automatic containment; in that case announce it and name who holds the kill switch.
- Responders must target lab VMs only. Live responders (Entra, WinRM, firewall) stay
  disabled unless the exercise needs them and their targets are lab-only.

## 6. Stop conditions

Stop immediately, engage the CyberPulse kill switch and tell the exercise lead if:

- anything outside scope is touched, or might have been;
- a production system, real account or real person is affected;
- a lab service becomes unstable in a way that could spread;
- anyone involved asks to stop.

Restart only after the lead has understood what happened and agreed.

## 7. Communication

- Before: announce the window, scope and contacts to [channel].
- During: post start, pauses and stop to [channel]; decoy tests (honey accounts, canary
  files) are announced so they are closed as tests, not incidents.
- After: post that the exercise is over and the lab is restored.

## 8. Data handling and clean-up

- All exercise data is synthetic or produced on lab VMs; never copy it outside the lab.
- Revert VMs to their snapshots, remove Atomic/Caldera artefacts (`Invoke-AtomicTest -Cleanup`),
  roll back or let expire any containment, and record results with
  `scripts/purple_team_report.py` or `scripts/caldera_compare.py`.

## 9. Sign-off

| Role | Name | Date | Signature |
| :--- | :--- | :--- | :--- |
| Lab owner | | | |
| Exercise lead | | | |
