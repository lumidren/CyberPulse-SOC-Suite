# Recording a Demo (plan for a human)

The roadmap asks for a short GIF at the top of the README (F79). It has to be recorded by a
person on a real screen, so it is not in the repository yet. This page is the plan, so the
recording shows the product honestly.

## Ground rules

- Record the real console against a local server in lab mode; no mock-ups, no edited numbers.
- Keep the **LAB / TEST MODE** banner and the **SIMULATED** badges visible.
- Use only synthetic data: the simulator and the seeded baseline. No real host names, users,
  IPs or company data on screen; check every frame before publishing.
- Do not speed up the pipeline or cut out the approval step; it is the point of the product.

## Setup

```bash
CYBERPULSE_LAB_MODE=true CYBERPULSE_API_KEY=<long random key> python server.py
```

Sign in, choose the light or dark theme, set the browser window to 1280x720.

## GIF for the README (F79): 20-30 seconds, no sound

1. Console overview -> click **T1003.001 LSASS Memory Dump** in the emulation launcher.
2. The incident appears in the log; open it: rule, risk, proposed `ISOLATE_HOST_AND_KILL_PROCESS`
   **pending approval**.
3. Click **Approve Containment**, then **Rollback Containment**, showing both records.
4. End on the triage workspace queue with the case and its attack timeline.

Tools: ScreenToGif (Windows), Kap (macOS) or Peek (Linux). Keep the file under 5 MB
(about 12 fps, 1280 px wide) and save it as `docs/media/demo.gif`, then add it under the README
title with alt text describing what it shows.

## Video walkthrough: alert to closure (F84), 6-8 minutes, narrated

Script (say what is synthetic as you go):

1. **Context (30 s).** "This is a lab with synthetic telemetry; nothing here attacks a real host."
   Show the Rules of Engagement and the lab-mode banner.
2. **Attack (1 min).** Run the ten-stage chain (`CYBERPULSE_LAB_MODE=true python simulator/attack_chain.py`)
   or the launcher; point out that each stage is a log record, not an action.
3. **Triage (2 min).** Triage workspace: pick the top case, assign it, read the attack timeline in
   event time, open the process tree, tick the first playbook tasks.
4. **Decide (1.5 min).** Open the LSASS incident: risk factors, rule confidence, the proposed
   isolation and its tier. Approve as a lead; show that an analyst key cannot.
5. **Hunt (1 min).** Pivot from the host in the hunting workbench; stack processes and point at
   the long tail.
6. **Close (1 min).** Roll back the containment, raise an appeal for a false positive on
   another incident, export the triage package and the PDF report, open the post-incident review,
   close the case.
7. **Limits (30 s).** Show `WHAT_I_MISSED.md`: the bypasses and gaps.

Publish it outside the repository (video host) and link it from the README.
