"""
Read-only views for the triage workspace (roadmap F51-F64).

Pure functions over the orchestrator's in-memory incidents and cases, so the server
routes stay thin and every view can be unit-tested without HTTP. Nothing here changes
state. Account names are masked by the server's response masking, as for incidents.
"""

from datetime import datetime, timezone


def _parse(ts):
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _case_incidents(orchestrator, case):
    incidents = orchestrator.dfir_engine.incidents
    return [incidents[i] for i in case["incidents"] if i in incidents]


# ----------------------------------------------------------------- F51 attack timeline
def case_timeline(orchestrator, case_id):
    """Attacker activity for a case in event-time order (when it happened, not when we noticed)."""
    case = orchestrator.case_manager.cases.get(case_id)
    if not case:
        return None
    entries = []
    for inc in _case_incidents(orchestrator, case):
        telemetry = inc.get("telemetry") or {}
        rule = inc.get("rule") or {}
        happened = _parse(telemetry.get("timestamp")) or _parse(inc.get("created_at"))
        detected = _parse(inc.get("created_at"))
        action = inc.get("containment_action") or {}
        entries.append({
            "at": happened.isoformat() if happened else None,
            "detected_at": detected.isoformat() if detected else None,
            "detection_delay_sec": round((detected - happened).total_seconds(), 3) if happened and detected else None,
            "incident_id": inc.get("incident_id"),
            "tactic": telemetry.get("tactic") or "Unknown",
            "technique": rule.get("mitre_id") or telemetry.get("technique_id"),
            "rule": f"{rule.get('rule_id')} {rule.get('rule_name')}",
            "host": telemetry.get("computer_name"),
            "user": telemetry.get("user"),
            "source_ip": telemetry.get("source_ip"),
            "response": f"{action.get('action_type')} ({action.get('status')})",
            "simulated": bool(inc.get("simulated")),
        })
    entries.sort(key=lambda e: e["at"] or "")
    return {"case_id": case_id, "title": case["title"], "entries": entries,
            "span_sec": round((_parse(entries[-1]["at"]) - _parse(entries[0]["at"])).total_seconds(), 3)
            if len(entries) > 1 and entries[0]["at"] and entries[-1]["at"] else 0}
