"""
Case management (roadmap F35): every incident is filed into a case automatically,
with the context an analyst needs to work it.

Incidents for the same host (or, without a host, the same source IP) within
GROUPING_WINDOW of the case's last activity join that case instead of opening a
new one, so one intrusion is one ticket. A case carries:

  * the incidents, rules, techniques, hosts and the highest severity and risk;
  * every proposed or executed response and its status;
  * the playbook task list (merged, de-duplicated across incidents);
  * a timeline of what happened to the case and who did it.

Status flow: New -> Investigating -> Resolved -> Closed (Closed is final). Status,
assignee and notes are changed through ``update`` and recorded with the actor.
Cases live in memory alongside incidents and are purged with them (retention).
"""

import threading
from datetime import datetime, timedelta, timezone

from soar.resilient_containment import next_id

GROUPING_WINDOW = timedelta(hours=2)
STATUSES = ["New", "Investigating", "Resolved", "Closed"]
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
MAX_NOTE_LEN = 2000


def _now():
    return datetime.now(timezone.utc)


def _parse(ts):
    parsed = datetime.fromisoformat(str(ts))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class CaseManager:
    def __init__(self, clock=_now):
        self.clock = clock
        self.cases = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ filing
    def _grouping_key(self, incident):
        telemetry = incident.get("telemetry") or {}
        if telemetry.get("computer_name"):
            return ("host", str(telemetry["computer_name"]).lower())
        if telemetry.get("source_ip"):
            return ("source_ip", str(telemetry["source_ip"]))
        return ("incident", incident["incident_id"])

    def _open_case_for(self, key, now):
        for case in self.cases.values():
            if (case["grouping_key"] == list(key) and case["status"] != "Closed"
                    and now - _parse(case["updated_at"]) <= GROUPING_WINDOW):
                return case
        return None

    def attach(self, incident):
        """File an incident into an open case for the same host/IP, or open a new one. Returns the case."""
        now = self.clock()
        key = self._grouping_key(incident)
        rule = incident.get("rule") or {}
        action = incident.get("containment_action") or {}
        telemetry = incident.get("telemetry") or {}
        with self._lock:
            case = self._open_case_for(key, now)
            if case is None:
                case_id = next_id("CASE")
                case = {
                    "case_id": case_id, "title": f"{rule.get('rule_name', 'Alert')} on {key[1]}",
                    "status": "New", "assignee": None, "severity": rule.get("severity", "MEDIUM"),
                    "grouping_key": list(key), "created_at": now.isoformat(), "updated_at": now.isoformat(),
                    "incidents": [], "rules": [], "techniques": [], "hosts": [], "source_ips": [],
                    "max_risk_score": 0, "responses": [], "tasks": [], "simulated": True,
                    "timeline": [{"at": now.isoformat(), "actor": "system", "event": "Case opened automatically"}],
                }
                self.cases[case_id] = case
            case["incidents"].append(incident["incident_id"])
            for field, value in (("rules", rule.get("rule_id")), ("techniques", rule.get("mitre_id")),
                                 ("hosts", telemetry.get("computer_name")), ("source_ips", telemetry.get("source_ip"))):
                if value and value not in case[field]:
                    case[field].append(value)
            if SEVERITY_RANK.get(rule.get("severity"), 0) > SEVERITY_RANK.get(case["severity"], 0):
                case["severity"] = rule.get("severity")
            risk = (incident.get("risk_assessment") or {}).get("final_score", 0) or 0
            case["max_risk_score"] = max(case["max_risk_score"], risk)
            if action.get("action_id"):
                case["responses"].append({"action_id": action["action_id"], "action_type": action.get("action_type"),
                                          "status": action.get("status"), "incident_id": incident["incident_id"]})
            known = {t["title"] for t in case["tasks"]}
            for task in (incident.get("playbook") or {}).get("tasks", []):
                if task["title"] not in known:
                    case["tasks"].append({"title": task["title"], "status": "Open"})
            # A case is only "simulated" while every incident in it is
            case["simulated"] = case["simulated"] and bool(incident.get("simulated"))
            case["timeline"].append({"at": now.isoformat(), "actor": "system",
                                     "event": f"Incident {incident['incident_id']} added ({rule.get('rule_id')})"})
            case["updated_at"] = now.isoformat()
            return case

    # ------------------------------------------------------------------ analyst actions
    def update(self, case_id, actor, status=None, assignee=None, note=None, task=None, task_status=None):
        """Change status/assignee, add a note or close a task. Returns {"status": "SUCCESS"|"ERROR", ...}."""
        if not actor:
            return {"status": "ERROR", "message": "an actor is required"}
        with self._lock:
            case = self.cases.get(case_id)
            if not case:
                return {"status": "ERROR", "message": f"case {case_id} not found"}
            if case["status"] == "Closed":
                return {"status": "ERROR", "message": "case is closed"}
            now = self.clock().isoformat()
            changes = []
            if status is not None:
                if status not in STATUSES:
                    return {"status": "ERROR", "message": f"status must be one of {STATUSES}"}
                if STATUSES.index(status) < STATUSES.index(case["status"]) and status != "Investigating":
                    return {"status": "ERROR", "message": f"cannot move from {case['status']} back to {status}"}
                changes.append(f"status {case['status']} -> {status}")
                case["status"] = status
            if assignee is not None:
                changes.append(f"assigned to {assignee or 'nobody'}")
                case["assignee"] = assignee or None
            if task is not None:
                match = next((t for t in case["tasks"] if t["title"] == task), None)
                if not match or task_status not in ("Open", "Done"):
                    return {"status": "ERROR", "message": "unknown task or task_status (Open/Done)"}
                match["status"] = task_status
                changes.append(f"task '{task}' -> {task_status}")
            if note:
                changes.append(f"note: {str(note)[:MAX_NOTE_LEN]}")
            if not changes:
                return {"status": "ERROR", "message": "nothing to change"}
            for change in changes:
                case["timeline"].append({"at": now, "actor": actor, "event": change})
            case["updated_at"] = now
            return {"status": "SUCCESS", "case": case}

    def list(self, status=None):
        cases = sorted(self.cases.values(), key=lambda c: c["updated_at"], reverse=True)
        return [c for c in cases if status is None or c["status"] == status]

    def find_by_incident(self, incident_id):
        return next((c for c in self.cases.values() if incident_id in c["incidents"]), None)

    def purge_missing(self, live_incident_ids):
        """Drop cases none of whose incidents still exist (called after incident retention)."""
        with self._lock:
            stale = [cid for cid, c in self.cases.items() if not set(c["incidents"]) & set(live_incident_ids)]
            for cid in stale:
                del self.cases[cid]
            return len(stale)
