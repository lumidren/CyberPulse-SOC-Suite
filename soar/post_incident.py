"""
Post-incident review (roadmap F77): a blameless review document pre-filled from a case.

Facts come from the records (timeline, detection delay, responses and who approved them,
appeals, custody); judgements are left as prompts for the people involved. The template
itself is docs/templates/POST_INCIDENT_REVIEW.md, for reviews written by hand.
"""

from soar import views


def _row(*cells):
    return "| " + " | ".join(str(c).replace("|", "/") if c is not None else "" for c in cells) + " |"


def review_markdown(orchestrator, case_id):
    case = orchestrator.case_manager.cases.get(case_id)
    if not case:
        return None
    timeline = views.case_timeline(orchestrator, case_id)
    incidents = [orchestrator.dfir_engine.incidents[i] for i in case["incidents"] if i in orchestrator.dfir_engine.incidents]
    ledger = [e for e in orchestrator.containment_engine.ledger.entries
              if (e.get("what") or {}).get("action_id") in {r["action_id"] for r in case["responses"]}]
    appeals = [a for a in orchestrator.appeals.appeals.values() if a["incident_id"] in case["incidents"]]
    delays = [e["detection_delay_sec"] for e in timeline["entries"] if e["detection_delay_sec"] is not None]
    lines = [
        f"# Post-incident review: {case['title']}",
        "",
        f"Case `{case_id}` · severity {case['severity']} · status {case['status']} · "
        f"{'SIMULATED (lab exercise)' if case.get('simulated') else 'real telemetry'}",
        "",
        "> Blameless review: we look for what in the system made the outcome likely, not for whom to blame.",
        "> Facts below come from CyberPulse records; sections marked *To discuss* are for the review meeting.",
        "",
        "## Summary",
        "",
        f"- Incidents: {len(incidents)}; hosts: {', '.join(case['hosts']) or '-'}; techniques: {', '.join(filter(None, case['techniques'])) or '-'}",
        f"- First activity: {timeline['entries'][0]['at'] if timeline['entries'] else '-'}; "
        f"span: {timeline['span_sec']} s",
        f"- Detection delay: {'from %.3f s to %.3f s' % (min(delays), max(delays)) if delays else 'not measured'}",
        f"- Assignee: {case['assignee'] or 'none'}",
        "- *To discuss:* one-paragraph plain-language summary of what happened and its impact.",
        "",
        "## Timeline (event time)",
        "",
        _row("When", "Tactic", "Technique", "Rule", "Host", "Detected after", "Response"),
        _row(":---", ":---", ":---", ":---", ":---", "---:", ":---"),
    ]
    lines += [_row(e["at"], e["tactic"], e["technique"], e["rule"], e["host"],
                   f"{e['detection_delay_sec']} s" if e["detection_delay_sec"] is not None else "-", e["response"])
              for e in timeline["entries"]]
    lines += ["", "## Response decisions", "", _row("When", "Who", "What", "Why", "Outcome"), _row(":---", ":---", ":---", ":---", ":---")]
    lines += [_row(e["at"][:19], e["actor"], e["event"], e["why"][:120], e["outcome"]) for e in ledger] or ["No containment decisions recorded."]
    lines += ["", "## Appeals", ""]
    lines += [f"- `{a['appeal_id']}` {a['kind']} by {a['raised_by']}: {a['reason']} -> **{a['status']}**"
              + (f" (tuned: {a['tuning_reference']})" if a.get("tuning_reference") else "") for a in appeals] or ["None."]
    lines += ["", "## Case activity", ""]
    lines += [f"- {e['at'][:19]} {e['actor']}: {e['event']}" for e in case["timeline"]]
    lines += ["", "## To discuss", "",
              "- **What went well?** (detections that fired early, decisions that helped)",
              "- **What was hard or slow?** (missing telemetry, unclear alerts, waiting for approval)",
              "- **Where were we lucky?**",
              "- **Was any automated action wrong, late or unnecessary?** Link appeals.",
              "- **Detection gaps:** which steps were not detected? Check `docs/WHAT_I_MISSED.md` and `docs/coverage/GAPS.md`.",
              "",
              "## Actions", "", _row("Action", "Owner", "Due", "Ticket / PR"), _row(":---", ":---", ":---", ":---"),
              _row("", "", "", ""), ""]
    return "\n".join(lines)
