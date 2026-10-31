# MITRE Caldera

Roadmap F22, shipped as a **stub**: it has been tested against a hand-written
report fixture only, never against a live Caldera server.

Caldera runs adversary-emulation operations from its own server, against agents
you deploy on your own lab VMs. CyberPulse never starts, schedules or changes an
operation. It only reads a finished operation's report and compares it with the
incidents CyberPulse raised.

```bash
# 1. In Caldera: run an operation against lab agents, then Operations -> Download report
# 2. Export CyberPulse incidents for the same period
curl -s -H "X-API-Key: $CYBERPULSE_API_KEY" "http://127.0.0.1:8080/api/incidents?limit=500" > incidents.json
# 3. Compare
python scripts/caldera_compare.py --report operation_report.json --incidents incidents.json
```

The output lists each executed ability (technique, status, time) as DETECTED (with
rule and latency) or MISSED, plus a summary. Abilities that did not succeed are
shown but not counted as misses. Ability command text is never copied.

To fetch the report directly instead of downloading it, set `CALDERA_URL` and
`CALDERA_API_KEY` (see `.env.example`) and use `--operation <id>`. Only private,
loopback or `*.lab` / `*.local` / `*.internal` / `*.test` addresses are accepted.

Assumptions to check against your Caldera version: steps are read from
`steps -> {agent paw: {steps: [...]}}`, each with `attack.technique_id`, `run`
(ISO timestamp) and `status` (0 = success).
