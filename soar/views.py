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
