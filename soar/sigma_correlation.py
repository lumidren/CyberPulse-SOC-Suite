"""
Sigma correlation rules (roadmap F12): detections over several events.

Rules live in rules/sigma/correlations/*.yml as multi-document YAML: one or more
*base* rules (ordinary Sigma rules with a ``name``) followed by a correlation
document, as in the Sigma v2 correlation specification:

    title: ...
    name: failed_network_logon        # base rule
    logsource: ...
    detection: ...
    ---
    title: ...
    id: ...
    correlation:
        type: event_count             # event_count | value_count | temporal
        rules: [failed_network_logon]
        group-by: [IpAddress, TargetUserName]
        timespan: 5m
        condition: {gte: 10}          # value_count adds field: <name>

Supported subset: ``event_count``, ``value_count`` and ``temporal`` (all listed
rules seen, in any order, within the timespan), condition operators
gt/gte/lt/lte/eq, timespans in s/m/h/d. Base rules referenced by a correlation
do not alert on their own (the spec's ``generate: false`` default).

State is in memory and per process. Event time comes from the event's
``timestamp`` (ISO 8601) so replays of historical data correlate correctly;
events without one use the wall clock. After a correlation fires, the state for
that group is cleared so one burst produces one alert, not one per event.
"""

import os
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone

import yaml

from soar.rule_versioning import detection_fingerprint
from soar.sigma_engine import (
    DEFAULT_MAPPING,
    DEFAULT_RULES_DIR,
    LEVEL_TO_SEVERITY,
    ROOT,
    SigmaRule,
    SigmaRuleError,
    _event_value,
)

DEFAULT_CORRELATIONS_DIR = os.path.join(DEFAULT_RULES_DIR, "correlations")
TIMESPAN_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
CONDITION_OPS = {
    "gt": lambda a, b: a > b, "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b, "lte": lambda a, b: a <= b, "eq": lambda a, b: a == b,
}
CORRELATION_TYPES = {"event_count", "value_count", "temporal"}


def parse_timespan(value):
    text = str(value).strip().lower()
    if not text or text[-1] not in TIMESPAN_UNITS or not text[:-1].isdigit():
        raise SigmaRuleError(f"unsupported timespan {value!r} (use e.g. 30s, 5m, 1h, 1d)")
    return int(text[:-1]) * TIMESPAN_UNITS[text[-1]]


def event_time(event):
    ts = event.get("timestamp")
    if ts:
        try:
            parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            pass
    return datetime.now(timezone.utc).timestamp()


class CorrelationRule:
    def __init__(self, path, doc, base_rules, soar):
        self.file = os.path.relpath(path, ROOT).replace("\\", "/")
        self.doc = doc
        self.id = doc.get("id")
        self.title = doc.get("title")
        self.level = str(doc.get("level", "high")).lower()
        self.tags = doc.get("tags", []) or []
        self.soar = soar or {}
        spec = doc["correlation"]
        self.type = spec.get("type")
        if self.type not in CORRELATION_TYPES:
            raise SigmaRuleError(f"{self.file}: unsupported correlation type {self.type!r}")
        names = spec.get("rules") or []
        missing = [n for n in names if n not in base_rules]
        if not names or missing:
            raise SigmaRuleError(f"{self.file}: unknown base rules {missing or names}")
        self.rule_names = list(names)
        self.base_rules = [base_rules[n] for n in names]
        self.group_by = list(spec.get("group-by") or [])
        self.timespan = parse_timespan(spec.get("timespan", "5m"))
        condition = dict(spec.get("condition") or {})
        self.value_field = condition.pop("field", None)
        if self.type == "value_count" and not self.value_field:
            raise SigmaRuleError(f"{self.file}: value_count needs condition.field")
        ops = [(op, value) for op, value in condition.items() if op in CONDITION_OPS]
        if self.type != "temporal" and len(ops) != 1:
            raise SigmaRuleError(f"{self.file}: condition needs exactly one of {sorted(CONDITION_OPS)}")
        self.op, self.threshold = ops[0] if ops else ("gte", len(names))
        self._state = defaultdict(deque)

    @property
    def technique_ids(self):
        return [t.split(".", 1)[1].upper() for t in self.tags if t.lower().startswith("attack.t")]

    def _group_key(self, event):
        return tuple(str(_event_value(event, f)[0]) for f in self.group_by)

    def observe(self, event, hit_names):
        """Feed one event (already matched to base rules `hit_names`). Returns True when the correlation fires."""
        relevant = [n for n in self.rule_names if n in hit_names]
        if not relevant:
            return False
        now = event_time(event)
        window = self._state[self._group_key(event)]
        value = _event_value(event, self.value_field)[0] if self.value_field else None
        for name in relevant:
            window.append((now, name, value))
        while window and window[0][0] < now - self.timespan:
            window.popleft()
        if self.type == "event_count":
            measured = len(window)
        elif self.type == "value_count":
            measured = len({str(v) for _, _, v in window if v is not None})
        else:
            measured = len({name for _, name, _ in window})
        fired = CONDITION_OPS[self.op](measured, self.threshold)
        if fired:
            window.clear()
        return fired

    def as_matched_rule(self):
        techniques = self.technique_ids
        return {
            "rule_id": self.soar.get("soc_rule_id", self.id),
            "rule_name": self.soar.get("name", self.title),
            "severity": self.soar.get("severity") or LEVEL_TO_SEVERITY.get(self.level, "HIGH"),
            "mitre_id": self.soar.get("mitre_id") or (techniques[0] if techniques else "Unknown"),
            "action_recommended": self.soar.get("action_recommended", "ENRICH_AND_ALERT_ANALYST"),
            "sigma_id": self.id,
            "sigma_file": self.file,
            "correlation": {"type": self.type, "rules": self.rule_names, "group_by": self.group_by,
                            "timespan_seconds": self.timespan},
        }


def correlation_fingerprint(rule):
    """Version fingerprint over the correlation and its base rules, so editing either needs a bump."""
    return detection_fingerprint({
        "logsource": [b.logsource for b in rule.base_rules],
        "detection": {"correlation": rule.doc.get("correlation"), "base": [b.doc.get("detection") for b in rule.base_rules]},
    })


class CorrelationEngine:
    def __init__(self, rules_dir=DEFAULT_CORRELATIONS_DIR, mapping_path=DEFAULT_MAPPING):
        mapping = {}
        if mapping_path and os.path.exists(mapping_path):
            with open(mapping_path, encoding="utf-8") as fh:
                mapping = (yaml.safe_load(fh) or {}).get("rules", {})
        self.base_rules = {}
        self.rules = []
        self._lock = threading.Lock()
        if not os.path.isdir(rules_dir):
            return
        for name in sorted(os.listdir(rules_dir)):
            if not name.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(rules_dir, name)
            with open(path, encoding="utf-8") as fh:
                docs = [d for d in yaml.safe_load_all(fh) if isinstance(d, dict)]
            local = {}
            for doc in docs:
                if "detection" in doc:
                    if not doc.get("name"):
                        raise SigmaRuleError(f"{name}: base rule needs a name")
                    local[doc["name"]] = SigmaRule(path, doc, None)
            self.base_rules.update(local)
            for doc in docs:
                if "correlation" in doc:
                    self.rules.append(CorrelationRule(path, doc, local, mapping.get(doc.get("id"))))

    def observe(self, event):
        """Update every correlation with this event; return the matched_rule dicts that fired."""
        hit_names = {n for n, r in self.base_rules.items() if r.matches(event)}
        if not hit_names:
            return []
        with self._lock:
            return [r.as_matched_rule() for r in self.rules if r.observe(event, hit_names)]

    def reset(self):
        with self._lock:
            for rule in self.rules:
                rule._state.clear()
