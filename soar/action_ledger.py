"""
Tamper-evident ledger of every automated action (roadmap E97).

Each containment decision and change is appended as one entry: **who** (actor),
**what** (event, action id and type, target), **why** (policy rationale or analyst
reason), **when** (UTC), and the outcome. Entries are hash-chained: every entry stores
the previous entry's hash and a SHA-256 over its own content, so editing, deleting or
reordering any entry is detected by ``verify``.

Set ``ACTION_LEDGER_FILE`` to also append each entry as a JSON line to that file; on
start the file is re-read, verified, and the chain continues from its last entry. For
stronger guarantees ship the file to write-once storage (S3 Object Lock, WORM share):
a hash chain shows tampering, it cannot prevent someone deleting the whole file.

    python -m soar.action_ledger --verify /var/log/cyberpulse/actions.jsonl
"""

import hashlib
import json
import os
import sys
import threading
from datetime import datetime, timezone

GENESIS = "0" * 64


def _hash(entry):
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def verify(entries):
    """{"intact": bool, "entries": n, "problems": [...]}"""
    problems, prev = [], GENESIS
    for i, entry in enumerate(entries, 1):
        if entry.get("seq") != i:
            problems.append(f"entry {i}: sequence is {entry.get('seq')}")
        if entry.get("prev_hash") != prev:
            problems.append(f"entry {i}: does not link to the previous entry")
        if _hash(entry) != entry.get("entry_hash"):
            problems.append(f"entry {i}: content changed after it was recorded")
        prev = entry.get("entry_hash")
    return {"intact": not problems, "entries": len(entries), "problems": problems}


class ActionLedger:
    def __init__(self, path=None, clock=lambda: datetime.now(timezone.utc).isoformat()):
        self.path = path if path is not None else os.environ.get("ACTION_LEDGER_FILE", "")
        self.clock = clock
        self.entries = []
        self.load_problems = []
        self._lock = threading.Lock()
        if self.path and os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as fh:
                self.entries = [json.loads(line) for line in fh if line.strip()]
            self.load_problems = verify(self.entries)["problems"]

    def record(self, actor, event, what, why="", outcome=None):
        with self._lock:
            entry = {"seq": len(self.entries) + 1, "at": self.clock(), "actor": str(actor or "unknown"),
                     "event": event, "what": what, "why": str(why or "")[:1000], "outcome": outcome,
                     "prev_hash": self.entries[-1]["entry_hash"] if self.entries else GENESIS}
            entry["entry_hash"] = _hash(entry)
            self.entries.append(entry)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
            return entry

    def verify(self):
        result = verify(self.entries)
        if self.load_problems:
            result["problems"] = self.load_problems + result["problems"]
            result["intact"] = False
        return result


def action_summary(record):
    """The 'what' of a containment action record."""
    return {k: record.get(k) for k in ("action_id", "action_type", "target_host", "target_ip", "target_user", "execution_intent")}


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--verify":
        sys.exit("usage: python -m soar.action_ledger --verify <ledger.jsonl>")
    with open(sys.argv[2], encoding="utf-8") as fh:
        result = verify([json.loads(line) for line in fh if line.strip()])
    print(json.dumps(result, indent=2))
    sys.exit(0 if result["intact"] else 1)
