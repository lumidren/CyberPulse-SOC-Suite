"""
Bounded store of recent events for hunting (roadmap F66, F69).

Detection only keeps events that matched a rule; hunting needs the rest too. Every event
the pipeline evaluates is kept here (already redacted), up to ``HUNT_EVENT_BUFFER``
events (default 20000, oldest dropped first), and purged by the same retention period as
incidents. It is in memory only: a SIEM is the place for long-term search.
"""

import os
import threading
from collections import deque
from datetime import datetime, timezone

from soar.redaction import redact_deep

# Fields that can be pivoted on, mapped to where they live in an event
PIVOT_FIELDS = {
    "host": ("computer_name",), "source_ip": ("source_ip",), "user": ("user",),
    "process": ("details.Image", "details.SourceImage"), "parent_process": ("details.ParentImage",),
    "command_line": ("details.CommandLine",), "hash": ("details.FileHash_SHA256", "details.Hashes"),
    "technique": ("technique_id",), "event_id": ("event_id",), "source": ("event_source",),
    "target_user": ("details.TargetUserName",), "destination": ("details.DestinationIp", "details.query"),
}


def field_value(event, field):
    for path in PIVOT_FIELDS.get(field, ()):
        value = event
        for part in path.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value not in (None, ""):
            return value
    return None


class EventStore:
    def __init__(self, maxlen=None):
        self.maxlen = maxlen or int(os.environ.get("HUNT_EVENT_BUFFER", "20000"))
        self.events = deque(maxlen=self.maxlen)
        self._lock = threading.Lock()

    def add(self, event, matched_rule=None):
        stored = redact_deep(dict(event))
        stored["_seen_at"] = datetime.now(timezone.utc).isoformat()
        stored["_rule"] = (matched_rule or {}).get("rule_id")
        with self._lock:
            self.events.append(stored)

    def snapshot(self):
        with self._lock:
            return list(self.events)

    def purge_older_than(self, cutoff):
        with self._lock:
            keep = [e for e in self.events if datetime.fromisoformat(e["_seen_at"]) >= cutoff]
            removed = len(self.events) - len(keep)
            self.events = deque(keep, maxlen=self.maxlen)
            return removed
