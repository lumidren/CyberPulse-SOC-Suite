"""
Automation Safety Controls for the CyberPulse SOC Lab

Guards enforced by the containment engine itself (the single choke point every
action passes through), so no policy mode or approval can bypass them.
"""

import os
import threading
from datetime import datetime, timezone


def _env_flag(name, default="false"):
    return os.environ.get(name, default).strip().lower() == "true"


class AutomationSafety:
    """Process-wide safety state shared by the policy and containment engines."""

    def __init__(self):
        self._lock = threading.Lock()
        self.kill_switch = {
            "engaged": _env_flag("CYBERPULSE_KILL_SWITCH"),
            "actor": "environment" if _env_flag("CYBERPULSE_KILL_SWITCH") else None,
            "reason": "CYBERPULSE_KILL_SWITCH=true at startup" if _env_flag("CYBERPULSE_KILL_SWITCH") else None,
            "changed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------ kill switch
    def engage_kill_switch(self, actor, reason=""):
        """Halt all automated and approved containment until released."""
        with self._lock:
            self.kill_switch = {
                "engaged": True,
                "actor": actor,
                "reason": reason,
                "changed_at": datetime.now(timezone.utc).isoformat(),
            }
            return dict(self.kill_switch)

    def release_kill_switch(self, actor, reason=""):
        with self._lock:
            self.kill_switch = {
                "engaged": False,
                "actor": actor,
                "reason": reason,
                "changed_at": datetime.now(timezone.utc).isoformat(),
            }
            return dict(self.kill_switch)

    def is_halted(self):
        return self.kill_switch["engaged"]

    def status(self):
        return {"kill_switch": dict(self.kill_switch)}
