# Atomic Red Team

Roadmap F21. CyberPulse **does not ship or execute** Atomic Red Team tests. The
project's rules forbid working attack tooling, so the integration has two
separate halves:

1. **Planning, in this repo.** `scripts/atomic_coverage.py` reads your local
   clone of the Atomic Red Team definitions and shows, per technique, how many
   atomic tests exist, which CyberPulse rules cover the technique and whether
   the lab has a telemetry-only emulation. It reads test names, GUIDs,
   platforms and executor type only; it never copies command text.

   ```bash
   git clone https://github.com/redcanaryco/atomic-red-team
   python scripts/atomic_coverage.py --atomics-dir atomic-red-team/atomics --platform windows
   ```

2. **Execution, in your own lab, by you.** Install
   [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam)
   on a disposable Windows VM you own (snapshot first). Run one test at a time
   with `Invoke-AtomicTest <Technique> -TestNumbers <n>`, then
   `-Cleanup`. Ship that VM's Sysmon/Security logs to CyberPulse the way any
   real source arrives (Wazuh/Winlogbeat forwarding to `POST /api/ingest`,
   HMAC-signed; see `scripts/send_signed_event.py`). The alerts that result are
   your real test results; `scripts/purple_team_report.py` (F23) describes how
   to compare them with what you ran.

Never run atomics on a machine you do not own or on a network shared with
others. Many atomics change system configuration; some download tools.

## Telemetry-only emulations

`simulator/atomic_tests/*.yaml` lists the techniques for which the lab emits
the telemetry an atomic test would leave behind, without executing anything.
Each manifest names the generator and the rule expected to fire;
`tests/test_atomic_coverage.py` checks every one of them.

| Technique | Emulation | Expected rule |
| :--- | :--- | :--- |
| T1003.001 | `simulate_t1003_lsass_dump` | SOC-RULE-001 |
| T1003.006 | `simulate_t1003_dcsync` | SOC-RULE-008 |
| T1053.005 | `simulate_t1053_scheduled_task` | SOC-RULE-003 |
| T1059.001 | `simulate_t1059_powershell_execution` | SOC-RULE-004 |
| T1110.001 | `simulate_t1110_brute_force` | SOC-RULE-002 |
| T1486 | `simulate_t1486_ransomware_canary` | SOC-RULE-006 |
| T1558.003 | `simulate_t1558_kerberoasting` | SOC-RULE-007 |
| T1562.001 | `simulate_t1562_defender_tamper` | SOC-RULE-005 |

**Not verified:** no real Atomic Red Team test has been run against this lab
by the author of this document; the emulated events were written by the same
person as the rules.
