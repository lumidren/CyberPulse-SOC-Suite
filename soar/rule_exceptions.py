"""
Per-rule exceptions (allowlist) for the Sigma rules (roadmap F15).

Exceptions live in rules/exceptions.yml, reviewed like code. Each one names a SOC
rule, a reason, an owner and an expiry date, and a ``match`` block in Sigma
selection syntax that must match *all* of its fields. A rule match covered by an
active exception is suppressed: it does not alert, but it is counted per
exception so suppression stays visible (``/api/exceptions``, validation report).

Guard rails, enforced at load time:
  * ``expires`` is required and at most MAX_LIFETIME_DAYS after ``created``;
    expired exceptions stop suppressing, so tuning debt cannot pile up silently.
  * ``match`` needs at least one field condition, and a bare ``*`` value is
    rejected, so an exception can never switch a whole rule off.
"""

import os
import threading
from collections import Counter
from datetime import date, datetime, timezone

import yaml

from soar.sigma_engine import ROOT, SigmaRuleError, _match_selection

DEFAULT_EXCEPTIONS = os.path.join(ROOT, "rules", "exceptions.yml")
MAX_LIFETIME_DAYS = 180
REQUIRED = ("id", "rule", "reason", "owner", "created", "expires", "match")


def _as_date(value, field, exc_id):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as e:
        raise SigmaRuleError(f"exception {exc_id}: {field} must be YYYY-MM-DD") from e


class RuleException:
    def __init__(self, doc):
        missing = [k for k in REQUIRED if not doc.get(k)]
        exc_id = doc.get("id", "?")
        if missing:
            raise SigmaRuleError(f"exception {exc_id}: missing {missing}")
        self.id = str(doc["id"])
        self.rule = str(doc["rule"])
        self.reason = str(doc["reason"])
        self.owner = str(doc["owner"])
        self.ticket = doc.get("ticket")
        self.created = _as_date(doc["created"], "created", exc_id)
        self.expires = _as_date(doc["expires"], "expires", exc_id)
        if self.expires <= self.created:
            raise SigmaRuleError(f"exception {exc_id}: expires must be after created")
        if (self.expires - self.created).days > MAX_LIFETIME_DAYS:
            raise SigmaRuleError(f"exception {exc_id}: lifetime over {MAX_LIFETIME_DAYS} days; re-review instead")
        match = doc["match"]
        if not isinstance(match, dict) or not match:
            raise SigmaRuleError(f"exception {exc_id}: match needs at least one field condition")
        for spec, value in match.items():
            values = value if isinstance(value, list) else [value]
            if any(str(v).strip("*") == "" for v in values):
                raise SigmaRuleError(f"exception {exc_id}: wildcard-only value for {spec} would disable the rule")
        self.match = match

    def active(self, today):
        return today <= self.expires

    def covers(self, event):
        return _match_selection(event, self.match)

    def as_dict(self, today, suppressed=0):
        return {"id": self.id, "rule": self.rule, "reason": self.reason, "owner": self.owner, "ticket": self.ticket,
                "created": self.created.isoformat(), "expires": self.expires.isoformat(),
                "status": "active" if self.active(today) else "expired", "suppressed": suppressed, "match": self.match}


class ExceptionRegistry:
    def __init__(self, path=DEFAULT_EXCEPTIONS, clock=None):
        self.path = path
        self.clock = clock or (lambda: datetime.now(timezone.utc).date())
        self.exceptions = []
        self.suppressed = Counter()
        self._lock = threading.Lock()
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                docs = (yaml.safe_load(fh) or {}).get("exceptions") or []
            self.exceptions = [RuleException(d) for d in docs]
        ids = [e.id for e in self.exceptions]
        if len(ids) != len(set(ids)):
            raise SigmaRuleError("duplicate exception ids in " + str(path))

    def suppressing(self, rule_id, event):
        """The active exception covering this (rule, event), or None. Counts the suppression."""
        today = self.clock()
        for exc in self.exceptions:
            if exc.rule == rule_id and exc.active(today) and exc.covers(event):
                with self._lock:
                    self.suppressed[exc.id] += 1
                return exc
        return None

    def status(self):
        today = self.clock()
        return {"exceptions": [e.as_dict(today, self.suppressed.get(e.id, 0)) for e in self.exceptions],
                "max_lifetime_days": MAX_LIFETIME_DAYS}
