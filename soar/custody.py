"""
Chain of custody for collected evidence (roadmap F50).

Every time evidence is collected or leaves the system (a triage package download), an
entry is appended to the incident's custody log: who, when, what, and the SHA-256 of the
artifact. Entries are hash-chained: each stores the previous entry's hash and its own
hash over its content, so editing, deleting or reordering any entry breaks ``verify``.

Hashes are computed over canonical JSON (sorted keys) for structured evidence and over
the exact bytes for files (the triage zip). The log is in memory with the incident and
is included in the triage package; it is evidence of handling inside this process, not a
substitute for write-once storage.
"""

import hashlib
import json
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


def sha256_of(obj):
    data = obj if isinstance(obj, (bytes, bytearray)) else json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _entry_hash(entry):
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


class CustodyLedger:
    def __init__(self, clock=lambda: datetime.now(timezone.utc).isoformat()):
        self.logs = {}
        self.clock = clock
        self._lock = threading.Lock()

    def record(self, incident_id, action, artifact, digest, actor):
        with self._lock:
            log = self.logs.setdefault(incident_id, [])
            entry = {"seq": len(log) + 1, "at": self.clock(), "actor": actor, "action": action,
                     "artifact": artifact, "sha256": digest, "prev_hash": log[-1]["entry_hash"] if log else GENESIS}
            entry["entry_hash"] = _entry_hash(entry)
            log.append(entry)
            return entry

    def verify(self, incident_id):
        """{"intact": bool, "entries": n, "problems": [...]}"""
        log = self.logs.get(incident_id, [])
        problems, prev = [], GENESIS
        for i, entry in enumerate(log, 1):
            if entry.get("seq") != i:
                problems.append(f"entry {i}: sequence is {entry.get('seq')}")
            if entry.get("prev_hash") != prev:
                problems.append(f"entry {i}: does not link to the previous entry")
            if _entry_hash(entry) != entry.get("entry_hash"):
                problems.append(f"entry {i}: content changed after it was recorded")
            prev = entry.get("entry_hash")
        return {"intact": not problems, "entries": len(log), "problems": problems}

    def verify_artifact(self, incident_id, artifact, obj):
        """True if `obj` still hashes to the latest recorded hash of `artifact`."""
        recorded = [e for e in self.logs.get(incident_id, []) if e["artifact"] == artifact]
        return bool(recorded) and recorded[-1]["sha256"] == sha256_of(obj)

    def purge(self, live_incident_ids):
        with self._lock:
            for inc_id in [i for i in self.logs if i not in live_incident_ids]:
                del self.logs[inc_id]
