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


# ----------------------------------------------------------------- F52 triage queue
STATUS_ORDER = {"New": 0, "Investigating": 1, "Resolved": 2, "Closed": 3}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def triage_queue(orchestrator, include_closed=False, assignee=None):
    """Open work first: status (New, Investigating), then severity, then risk, then oldest update."""
    cases = [c for c in orchestrator.case_manager.cases.values()
             if (include_closed or c["status"] != "Closed") and (assignee is None or c["assignee"] == assignee)]
    cases.sort(key=lambda c: (STATUS_ORDER.get(c["status"], 9), SEVERITY_ORDER.get(c["severity"], 9),
                              -(c.get("max_risk_score") or 0), c["updated_at"]))
    return [{
        "case_id": c["case_id"], "title": c["title"], "severity": c["severity"], "status": c["status"],
        "assignee": c["assignee"], "incidents": len(c["incidents"]), "max_risk_score": c.get("max_risk_score"),
        "pending_responses": sum(1 for r in c["responses"] if r.get("status") == "PENDING_ANALYST_APPROVAL"),
        "open_tasks": sum(1 for t in c["tasks"] if t["status"] == "Open"), "updated_at": c["updated_at"],
        "simulated": c.get("simulated", False),
    } for c in cases]


# ----------------------------------------------------------------- F53 process tree
def _image(path):
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1] if path else None


def _build_node(nodes, children, name, kind, seen):
    node = dict(nodes[name], relation=kind, children=[])
    if name in seen:  # cycles cannot happen in real lineage, but names repeat across incidents
        return node
    node["children"] = [_build_node(nodes, children, c, k, seen | {name}) for c, k in children.get(name, [])]
    return node


def process_tree(orchestrator, case_id):
    """Parent -> child process forest per host, built from the case's process telemetry.

    Each node is an executable seen in the case (by name, per host); alerted processes carry
    the rule that fired. Sysmon 10 (process access) adds an 'accessed' edge, e.g. -> lsass.exe."""
    case = orchestrator.case_manager.cases.get(case_id)
    if not case:
        return None
    hosts = {}
    for inc in _case_incidents(orchestrator, case):
        telemetry = inc.get("telemetry") or {}
        details = telemetry.get("details") or {}
        host = telemetry.get("computer_name") or "unknown"
        nodes, edges = hosts.setdefault(host, ({}, set()))
        rule = (inc.get("rule") or {}).get("rule_id")
        child = _image(details.get("Image")) or _image(details.get("SourceImage"))
        parent = _image(details.get("ParentImage"))
        target = _image(details.get("TargetImage"))
        for name in filter(None, (child, parent, target)):
            nodes.setdefault(name, {"name": name, "alerts": [], "command_line": None})
        if child:
            nodes[child]["alerts"].append(rule)
            nodes[child]["command_line"] = nodes[child]["command_line"] or details.get("CommandLine")
        if parent and child:
            edges.add((parent, child, "spawned"))
        if child and target:
            edges.add((child, target, "accessed"))
    forest = []
    for host, (nodes, edges) in sorted(hosts.items()):
        children = {}
        for parent, child, kind in sorted(edges):
            children.setdefault(parent, []).append((child, kind))
        has_parent = {c for _, c, k in edges if k == "spawned"}

        roots = [n for n in sorted(nodes) if n not in has_parent and (children.get(n) or nodes[n]["alerts"])]
        forest.append({"host": host, "roots": [_build_node(nodes, children, r, "root", frozenset()) for r in roots]})
    return {"case_id": case_id, "hosts": forest}


# ----------------------------------------------------------------- F54 network graph
def _ip_kind(ip):
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return "unknown"
    from soar.notifications import _DOC_NETS
    # RFC 5737 ranges are the lab's stand-ins for internet attackers; Python counts them as private
    if any(addr in net for net in _DOC_NETS):
        return "external"
    if addr.is_private or addr.is_loopback:
        return "internal"
    return "external"


def network_graph(orchestrator, limit=200):
    """Source IP -> host relationships across all incidents: who touched what, how often, with which techniques."""
    edges = {}
    for inc in list(orchestrator.dfir_engine.incident_list)[-limit:]:
        telemetry = inc.get("telemetry") or {}
        src, host = telemetry.get("source_ip"), telemetry.get("computer_name")
        if not src or not host:
            continue
        edge = edges.setdefault((src, host), {"source": src, "target": host, "count": 0, "techniques": set(),
                                              "last_seen": None, "simulated": True})
        edge["count"] += 1
        edge["techniques"].add((inc.get("rule") or {}).get("mitre_id"))
        edge["last_seen"] = max(filter(None, [edge["last_seen"], inc.get("created_at")]))
        edge["simulated"] = edge["simulated"] and bool(inc.get("simulated"))
    nodes = {}
    for src, host in edges:
        nodes.setdefault(src, {"id": src, "type": "source", "kind": _ip_kind(src), "degree": 0})["degree"] += 1
        nodes.setdefault(host, {"id": host, "type": "host", "kind": "host", "degree": 0})["degree"] += 1
    return {"nodes": sorted(nodes.values(), key=lambda n: (n["type"], -n["degree"], n["id"])),
            "edges": [dict(e, techniques=sorted(filter(None, e["techniques"]))) for e in edges.values()]}


# ----------------------------------------------------------------- F55 MTTD / MTTR trend
def _mean(values):
    return round(sum(values) / len(values), 3) if values else None


def mttd_mttr_trend(orchestrator):
    """Per-day mean time to detect (event time -> incident) and to resolve (case opened -> Resolved/Closed).

    Only measured values are reported; a day without data has None ("not yet measured")."""
    detect, resolve = {}, {}
    for inc in orchestrator.dfir_engine.incident_list:
        happened = _parse((inc.get("telemetry") or {}).get("timestamp"))
        detected = _parse(inc.get("created_at"))
        if happened and detected and detected >= happened:
            detect.setdefault(detected.date().isoformat(), []).append((detected - happened).total_seconds())
    for case in orchestrator.case_manager.cases.values():
        opened = _parse(case["created_at"])
        done = next((_parse(e["at"]) for e in case["timeline"]
                     if e["event"].startswith("status ") and (e["event"].endswith("-> Resolved") or e["event"].endswith("-> Closed"))), None)
        if opened and done:
            resolve.setdefault(done.date().isoformat(), []).append((done - opened).total_seconds())
    days = sorted(set(detect) | set(resolve))
    return {
        "basis": "Measured from incident and case timestamps in this process; lab events are synthetic.",
        "points": [{"day": d, "mttd_sec": _mean(detect.get(d, [])), "mttr_sec": _mean(resolve.get(d, [])),
                    "incidents": len(detect.get(d, [])), "resolved_cases": len(resolve.get(d, []))} for d in days],
    }


# ----------------------------------------------------------------- F56 top talkers / top rules
def top_stats(orchestrator, n=5):
    """Most frequent source IPs, hosts, users and rules across all incidents."""
    from collections import Counter
    counters = {k: Counter() for k in ("source_ips", "hosts", "users", "rules")}
    for inc in orchestrator.dfir_engine.incident_list:
        telemetry = inc.get("telemetry") or {}
        rule = inc.get("rule") or {}
        for key, value in (("source_ips", telemetry.get("source_ip")), ("hosts", telemetry.get("computer_name")),
                           ("users", telemetry.get("user")),
                           ("rules", f"{rule.get('rule_id')} {rule.get('rule_name')}" if rule.get("rule_id") else None)):
            if value:
                counters[key][value] += 1
    return {"incidents": len(orchestrator.dfir_engine.incident_list),
            **{k: [{"value": v, "count": c} for v, c in counter.most_common(n)] for k, counter in counters.items()}}


# ----------------------------------------------------------------- F59 global search
SEARCH_FIELDS = {
    "incident": lambda i: i.get("incident_id"),
    "rule": lambda i: f"{(i.get('rule') or {}).get('rule_id')} {(i.get('rule') or {}).get('rule_name')}",
    "technique": lambda i: (i.get("rule") or {}).get("mitre_id"),
    "host": lambda i: (i.get("telemetry") or {}).get("computer_name"),
    "source_ip": lambda i: (i.get("telemetry") or {}).get("source_ip"),
    "user": lambda i: (i.get("telemetry") or {}).get("user"),
    "ioc": lambda i: " ".join(str(o.get("value")) for o in i.get("observables") or []),
    "command_line": lambda i: ((i.get("telemetry") or {}).get("details") or {}).get("CommandLine"),
}


def search(orchestrator, query, limit=50):
    """Case-insensitive substring search across incidents and cases; each hit names the field that matched."""
    q = str(query or "").strip().lower()
    if len(q) < 2:
        return {"query": query, "error": "type at least 2 characters", "results": []}
    results = []
    for inc in reversed(orchestrator.dfir_engine.incident_list):
        fields = [name for name, get in SEARCH_FIELDS.items() if q in str(get(inc) or "").lower()]
        if fields:
            case = orchestrator.case_manager.find_by_incident(inc["incident_id"])
            results.append({"type": "incident", "id": inc["incident_id"], "case_id": case["case_id"] if case else None,
                            "title": (inc.get("rule") or {}).get("rule_name"),
                            "host": (inc.get("telemetry") or {}).get("computer_name"), "matched": fields})
    for case in orchestrator.case_manager.cases.values():
        if q in case["case_id"].lower() or q in case["title"].lower():
            results.append({"type": "case", "id": case["case_id"], "case_id": case["case_id"], "title": case["title"],
                            "host": ", ".join(case["hosts"]), "matched": ["case"]})
    return {"query": query, "total": len(results), "results": results[:limit], "truncated": len(results) > limit}


# ----------------------------------------------------------------- F63 mobile status
def status_summary(orchestrator):
    """The few numbers an on-call phone needs: is automation halted, what waits on me, what is open."""
    safety = orchestrator.containment_engine.safety.status()
    queue = triage_queue(orchestrator)
    by_severity = {}
    for case in queue:
        by_severity[case["severity"]] = by_severity.get(case["severity"], 0) + 1
    recent = list(orchestrator.dfir_engine.incident_list)[-5:]
    return {
        "kill_switch_engaged": bool(safety["kill_switch"].get("engaged")),
        "pending_approvals": len(orchestrator.containment_engine.pending_approvals()),
        "open_cases": len(queue),
        "unassigned_cases": sum(1 for c in queue if not c["assignee"]),
        "open_by_severity": by_severity,
        "policy_mode": orchestrator.risk_engine.policy_mode,
        "recent": [{"incident_id": i.get("incident_id"), "rule": (i.get("rule") or {}).get("rule_name"),
                    "severity": (i.get("rule") or {}).get("severity"), "at": i.get("created_at"),
                    "simulated": bool(i.get("simulated"))} for i in reversed(recent)],
    }


# ----------------------------------------------------------------- F64 executive summary
def executive_summary(orchestrator):
    """Plain-language posture summary for non-specialists, computed only from recorded data."""
    from collections import Counter
    incidents = list(orchestrator.dfir_engine.incident_list)
    real = [i for i in incidents if not i.get("simulated")]
    severity = Counter((i.get("rule") or {}).get("severity") for i in incidents)
    tactics = Counter((i.get("telemetry") or {}).get("tactic") or "Unknown" for i in incidents)
    statuses = Counter((i.get("containment_action") or {}).get("status") for i in incidents)
    cases = list(orchestrator.case_manager.cases.values())
    trend = mttd_mttr_trend(orchestrator)["points"]
    mttd = [p["mttd_sec"] for p in trend if p["mttd_sec"] is not None]
    mttr = [p["mttr_sec"] for p in trend if p["mttr_sec"] is not None]
    headline = (f"{len(incidents)} incidents ({len(real)} from real telemetry, {len(incidents) - len(real)} simulated), "
                f"{sum(1 for c in cases if c['status'] not in ('Resolved', 'Closed'))} cases open.")
    return {
        "headline": headline,
        "incidents": {"total": len(incidents), "real": len(real), "simulated": len(incidents) - len(real),
                      "by_severity": {k: v for k, v in severity.items() if k}},
        "response": {"contained": statuses.get("SUCCESS", 0), "awaiting_approval": statuses.get("PENDING_ANALYST_APPROVAL", 0),
                     "rejected": statuses.get("REJECTED_BY_ANALYST", 0),
                     "alert_only": sum(v for k, v in statuses.items() if k == "FLAGGED_FOR_MANUAL_REVIEW"),
                     "halted_by_kill_switch": statuses.get("HALTED_BY_KILL_SWITCH", 0)},
        "cases": {"total": len(cases), "open": sum(1 for c in cases if c["status"] in ("New", "Investigating")),
                  "resolved": sum(1 for c in cases if c["status"] in ("Resolved", "Closed")),
                  "unassigned": sum(1 for c in cases if not c["assignee"] and c["status"] != "Closed")},
        "speed": {"mean_time_to_detect_sec": round(sum(mttd) / len(mttd), 3) if mttd else None,
                  "mean_time_to_resolve_sec": round(sum(mttr) / len(mttr), 3) if mttr else None},
        "top_tactics": [{"tactic": t, "count": c} for t, c in tactics.most_common(5)],
        "caveats": [
            "Simulated incidents come from the lab's attack simulator and say nothing about real threats.",
            "Times are measured inside this lab; real detection time also includes log shipping and SIEM delay.",
            "A value shown as 'not yet measured' has no recorded data behind it.",
        ],
    }


# ----------------------------------------------------------------- F66 pivot queries
def pivot(orchestrator, field, value, limit=200):
    """Every stored event where `field` equals `value`, and what else those events touch."""
    from collections import Counter

    from soar.event_store import PIVOT_FIELDS, field_value
    if field not in PIVOT_FIELDS:
        return {"error": f"field must be one of {sorted(PIVOT_FIELDS)}"}
    needle = str(value or "").strip().lower()
    if not needle:
        return {"error": "value is required"}
    hits = [e for e in orchestrator.event_store.snapshot() if str(field_value(e, field) or "").lower() == needle]
    related = {}
    for other in PIVOT_FIELDS:
        if other == field:
            continue
        counts = Counter(str(field_value(e, other)) for e in hits if field_value(e, other) not in (None, ""))
        if counts:
            related[other] = [{"value": v, "count": c} for v, c in counts.most_common(10)]
    times = sorted(e["_seen_at"] for e in hits)
    return {
        "field": field, "value": value, "events": len(hits),
        "alerted": sum(1 for e in hits if e.get("_rule")),
        "first_seen": times[0] if times else None, "last_seen": times[-1] if times else None,
        "related": related,
        "sample": [{"seen_at": e["_seen_at"], "rule": e.get("_rule"), "host": e.get("computer_name"),
                    "user": e.get("user"), "source_ip": e.get("source_ip"), "event_id": e.get("event_id"),
                    "process": field_value(e, "process"), "command_line": field_value(e, "command_line")}
                   for e in hits[-limit:]][::-1][:50],
    }


# ----------------------------------------------------------------- F69 stack counting / long tail
def stack(orchestrator, field, where_field=None, where_value=None, tail_share=0.01):
    """Count every value of `field` across stored events (optionally filtered), rarest first.

    Values seen in at most max(1, tail_share x total) events are flagged as the long tail:
    on a stable estate, attacker tooling tends to live there."""
    from collections import Counter

    from soar.event_store import PIVOT_FIELDS, field_value
    for f in filter(None, (field, where_field)):
        if f not in PIVOT_FIELDS:
            return {"error": f"field must be one of {sorted(PIVOT_FIELDS)}"}
    events = orchestrator.event_store.snapshot()
    if where_field:
        needle = str(where_value or "").lower()
        events = [e for e in events if str(field_value(e, where_field) or "").lower() == needle]
    values = [str(field_value(e, field)) for e in events if field_value(e, field) not in (None, "")]
    counts = Counter(values)
    total = len(values)
    tail_limit = max(1, int(total * tail_share))
    alerted = Counter(str(field_value(e, field)) for e in events if e.get("_rule") and field_value(e, field) not in (None, ""))
    rows = [{"value": v, "count": c, "share": round(c / total, 4) if total else 0, "tail": c <= tail_limit,
             "alerted": alerted.get(v, 0)} for v, c in sorted(counts.items(), key=lambda kv: (kv[1], kv[0]))]
    return {"field": field, "where": {where_field: where_value} if where_field else None, "events": len(events),
            "with_value": total, "distinct": len(counts), "tail_limit": tail_limit,
            "tail": sum(1 for r in rows if r["tail"]), "rows": rows[:500]}
