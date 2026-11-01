"""
Appeals: analysts say an automated decision was wrong, and the rule gets tuned (roadmap E98).

  1. Any analyst opens an appeal on an incident: false positive, wrong action, wrong
     target, or too slow/too late. Opening an appeal does not undo anything by itself;
     rolling back is a separate, deliberate step.
  2. A lead accepts or rejects it with a reason.
  3. An accepted false-positive appeal comes with a **draft** exception for
     rules/exceptions.yml built from the incident's own fields. It is a suggestion to
     review and commit, never applied automatically, and it cannot hide the rule's
     attack samples (the test suite enforces that once it is committed).
  4. When the fix lands (exception, rule change, playbook change), the appeal is marked
     tuned with a reference to it (commit, exception id, PR), closing the loop.

Every step is written to the action ledger. Open/accepted appeal counts per rule show
which rules analysts distrust most.
"""

import threading
from collections import Counter
from datetime import date, datetime, timedelta, timezone

from soar.resilient_containment import next_id

KINDS = {"false_positive", "wrong_action", "wrong_target", "too_late"}
STATUSES = ("Open", "Accepted", "Rejected", "Tuned")
STABLE_FIELDS = ("ParentImage", "Image", "TaskName", "ServiceName", "TargetFilename", "SourceImage",
                 "SenderFromAddress", "eventName", "roleArn")


def draft_exception(incident, appeal_id, owner):
    """Suggested rules/exceptions.yml entry built from stable fields of the event (to be reviewed)."""
    details = ((incident.get("telemetry") or {}).get("details") or {})
    match = {f: details[f] for f in STABLE_FIELDS if details.get(f)}
    today = date.today()
    return {
        "id": "EXC-XXXX",
        "rule": (incident.get("rule") or {}).get("rule_id"),
        "reason": f"From appeal {appeal_id}: <say why this pattern is benign and who confirmed it>",
        "owner": owner,
        "created": today.isoformat(),
        "expires": (today + timedelta(days=90)).isoformat(),
        "match": match or {"<field>": "<value>"},
        "review_note": "Draft only. Narrow 'match' to fields an attacker cannot easily copy, then commit it with tests.",
    }


class AppealStore:
    def __init__(self, ledger=None):
        self.appeals = {}
        self.ledger = ledger
        self._lock = threading.Lock()

    def _log(self, actor, event, appeal, why=""):
        if self.ledger is not None:
            self.ledger.record(actor=actor, event=f"appeal.{event}", why=why, outcome=appeal["status"],
                               what={"appeal_id": appeal["appeal_id"], "incident_id": appeal["incident_id"],
                                     "rule_id": appeal["rule_id"], "action_id": appeal["action_id"]})

    def open(self, incident, raised_by, kind, reason):
        if not raised_by:
            return {"status": "ERROR", "message": "an analyst name is required"}
        if kind not in KINDS:
            return {"status": "ERROR", "message": f"kind must be one of {sorted(KINDS)}"}
        if not str(reason or "").strip():
            return {"status": "ERROR", "message": "say why the decision was wrong"}
        now = datetime.now(timezone.utc).isoformat()
        appeal = {"appeal_id": next_id("APL"), "incident_id": incident.get("incident_id"),
                  "rule_id": (incident.get("rule") or {}).get("rule_id"),
                  "action_id": (incident.get("containment_action") or {}).get("action_id"),
                  "action_type": (incident.get("containment_action") or {}).get("action_type"),
                  "kind": kind, "reason": str(reason)[:2000], "raised_by": raised_by, "status": "Open",
                  "created_at": now, "decision": None, "tuning_reference": None, "draft_exception": None,
                  "timeline": [{"at": now, "actor": raised_by, "event": f"opened ({kind})"}]}
        with self._lock:
            self.appeals[appeal["appeal_id"]] = appeal
        self._log(raised_by, "open", appeal, reason)
        return {"status": "SUCCESS", "appeal": appeal}

    def decide(self, appeal_id, lead, accept, reason, incident=None):
        with self._lock:
            appeal = self.appeals.get(appeal_id)
            if not appeal:
                return {"status": "ERROR", "message": "appeal not found"}
            if appeal["status"] != "Open":
                return {"status": "ERROR", "message": f"appeal is {appeal['status']}"}
            if not lead or not str(reason or "").strip():
                return {"status": "ERROR", "message": "a lead and a reason are required"}
            appeal["status"] = "Accepted" if accept else "Rejected"
            appeal["decision"] = {"by": lead, "reason": str(reason)[:2000], "at": datetime.now(timezone.utc).isoformat()}
            if accept and appeal["kind"] == "false_positive" and incident is not None:
                appeal["draft_exception"] = draft_exception(incident, appeal_id, lead)
            appeal["timeline"].append({"at": appeal["decision"]["at"], "actor": lead, "event": appeal["status"].lower()})
        self._log(lead, "decide", appeal, reason)
        return {"status": "SUCCESS", "appeal": appeal}

    def mark_tuned(self, appeal_id, actor, reference):
        with self._lock:
            appeal = self.appeals.get(appeal_id)
            if not appeal or appeal["status"] != "Accepted":
                return {"status": "ERROR", "message": "only an accepted appeal can be marked tuned"}
            if not actor or not str(reference or "").strip():
                return {"status": "ERROR", "message": "an actor and a reference (commit, exception id, PR) are required"}
            appeal["status"] = "Tuned"
            appeal["tuning_reference"] = str(reference)[:200]
            appeal["timeline"].append({"at": datetime.now(timezone.utc).isoformat(), "actor": actor,
                                       "event": f"tuned: {appeal['tuning_reference']}"})
        self._log(actor, "tuned", appeal, reference)
        return {"status": "SUCCESS", "appeal": appeal}

    def per_rule(self):
        """{rule_id: {"open": n, "accepted": n, "rejected": n, "tuned": n}}"""
        counts = {}
        for appeal in self.appeals.values():
            counts.setdefault(appeal["rule_id"], Counter())[appeal["status"].lower()] += 1
        return {rule: dict(c) for rule, c in sorted(counts.items(), key=lambda kv: str(kv[0]))}
