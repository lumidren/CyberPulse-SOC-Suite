"""
Saved hunts and queries (roadmap F60).

A hunt is a named global-search query (soar/views.py ``search``) that the team can
re-run. Hunts are shared across analysts, so they live on the server, not in a browser.
They are kept in memory and, if ``HUNTS_FILE`` is set, in that JSON file (written
atomically) so they survive restarts. Queries hold search terms, which may name hosts or
IPs, so keep that file with the rest of the SOC's data, not in the repository.
"""

import json
import os
import re
import threading
from datetime import datetime, timezone

from soar.resilient_containment import next_id

MAX_HUNTS = 500
NAME_RE = re.compile(r"^[\w .:/()-]{1,80}$")


class HuntStore:
    def __init__(self, path=None):
        self.path = path if path is not None else os.environ.get("HUNTS_FILE", "")
        self.hunts = {}
        self._lock = threading.Lock()
        if self.path and os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as fh:
                self.hunts = {h["id"]: h for h in json.load(fh)}

    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(sorted(self.hunts.values(), key=lambda h: h["created_at"]), fh, indent=2)
        os.replace(tmp, self.path)

    def add(self, name, query, owner, description=""):
        name, query, owner = str(name or "").strip(), str(query or "").strip(), str(owner or "").strip()
        if not NAME_RE.match(name):
            return {"status": "ERROR", "message": "name: 1-80 letters, digits, spaces or . : / ( ) -"}
        if not 2 <= len(query) <= 200:
            return {"status": "ERROR", "message": "query must be 2-200 characters"}
        if not owner:
            return {"status": "ERROR", "message": "an owner (analyst name) is required"}
        with self._lock:
            if len(self.hunts) >= MAX_HUNTS:
                return {"status": "ERROR", "message": f"at most {MAX_HUNTS} saved hunts"}
            if any(h["name"].lower() == name.lower() for h in self.hunts.values()):
                return {"status": "ERROR", "message": "a hunt with that name exists"}
            hunt = {"id": next_id("HUNT"), "name": name, "query": query, "description": str(description)[:500],
                    "owner": owner[:64], "created_at": datetime.now(timezone.utc).isoformat(), "runs": 0}
            self.hunts[hunt["id"]] = hunt
            self._save()
        return {"status": "SUCCESS", "hunt": hunt}

    def delete(self, hunt_id, actor):
        with self._lock:
            if hunt_id not in self.hunts:
                return {"status": "ERROR", "message": "hunt not found"}
            if not actor:
                return {"status": "ERROR", "message": "an actor is required"}
            del self.hunts[hunt_id]
            self._save()
        return {"status": "SUCCESS"}

    def mark_run(self, hunt_id):
        with self._lock:
            hunt = self.hunts.get(hunt_id)
            if hunt:
                hunt["runs"] += 1
                hunt["last_run_at"] = datetime.now(timezone.utc).isoformat()
                self._save()
            return hunt

    def list(self):
        return sorted(self.hunts.values(), key=lambda h: h["name"].lower())
