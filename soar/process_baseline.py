"""
Behavioural baseline of parent -> child process pairs (roadmap F13).

Learns how often each (parent image, child image) pair appears in process-creation
telemetry (Sysmon Event 1 / Security 4688) and flags pairs that are rare or never
seen. This is an anomaly signal for triage and hunting, not a detection: a rare
pair raises a LOW-severity hint and never drives containment on its own.

Only executable basenames are stored (``winword.exe -> powershell.exe``); no
hostnames, usernames or command lines, so a saved baseline holds no personal data.
"""

import json
import ntpath
import threading
from collections import Counter

PROCESS_EVENT_IDS = {1, 4688}


def _basename(path):
    return ntpath.basename(str(path)).lower() if path else None


def process_pair(event):
    """(parent, child) basenames for a process-creation event, else None."""
    try:
        if int(event.get("event_id")) not in PROCESS_EVENT_IDS:
            return None
    except (TypeError, ValueError):
        return None
    details = event.get("details") or {}
    child = _basename(details.get("Image") or details.get("NewProcessName"))
    parent = _basename(details.get("ParentImage") or details.get("ParentProcessName"))
    if not child or not parent:
        return None
    return parent, child


class ProcessPairBaseline:
    """Counts of parent -> child pairs; `score` says whether a new event's pair is rare."""

    def __init__(self, min_training_events=50, rare_threshold=1):
        self.min_training_events = min_training_events
        self.rare_threshold = rare_threshold  # pairs seen this many times or fewer are rare
        self.counts = Counter()
        self._lock = threading.Lock()

    @property
    def total(self):
        return sum(self.counts.values())

    def learn(self, event):
        pair = process_pair(event)
        if pair:
            with self._lock:
                self.counts[pair] += 1
        return pair

    def learn_many(self, events):
        for event in events:
            self.learn(event)
        return self

    def score(self, event):
        pair = process_pair(event)
        if pair is None:
            return {"verdict": "NOT_APPLICABLE"}
        seen = self.counts.get(pair, 0)
        result = {"pair": f"{pair[0]} -> {pair[1]}", "seen": seen, "baseline_events": self.total}
        if self.total < self.min_training_events:
            result["verdict"] = "INSUFFICIENT_BASELINE"
        elif seen <= self.rare_threshold:
            result["verdict"] = "NEVER_SEEN" if seen == 0 else "RARE"
        else:
            result["verdict"] = "COMMON"
        return result

    def rare_pairs(self):
        return sorted((f"{p} -> {c}", n) for (p, c), n in self.counts.items() if n <= self.rare_threshold)

    def to_json(self):
        return json.dumps({"min_training_events": self.min_training_events, "rare_threshold": self.rare_threshold,
                           "pairs": [[p, c, n] for (p, c), n in sorted(self.counts.items())]}, indent=2)

    @classmethod
    def from_json(cls, text):
        data = json.loads(text)
        baseline = cls(data.get("min_training_events", 50), data.get("rare_threshold", 1))
        for parent, child, n in data.get("pairs", []):
            baseline.counts[(str(parent).lower(), str(child).lower())] = int(n)
        return baseline
