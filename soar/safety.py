"""
Automation Safety Controls for the CyberPulse SOC Lab

Guards enforced by the containment engine itself (the single choke point every
action passes through), so no policy mode or approval can bypass them.
"""

import os
import threading
import time
from collections import deque
from datetime import datetime, timezone


def _env_flag(name, default="false"):
    return os.environ.get(name, default).strip().lower() == "true"


class AutomationSafety:
    """Process-wide safety state shared by the policy and containment engines."""

    def __init__(self, clock=time.time):
        self._lock = threading.Lock()
        self.clock = clock  # injectable for tests

        # Rate limit: max containment executions in any rolling hour
        self.max_actions_per_hour = int(os.environ.get("CONTAINMENT_MAX_ACTIONS_PER_HOUR", "20"))
        self._executions = deque()  # (timestamp, action_type, target)
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

    # ------------------------------------------------------------------ rate limit
    def _prune(self, window, horizon_sec):
        cutoff = self.clock() - horizon_sec
        while window and window[0][0] < cutoff:
            window.popleft()

    def executions_last_hour(self):
        with self._lock:
            self._prune(self._executions, 3600)
            return len(self._executions)

    def rate_limit_exceeded(self):
        """True once the rolling-hour execution budget is spent."""
        return self.executions_last_hour() >= self.max_actions_per_hour

    def record_execution(self, action_record):
        """Count an executed (not staged, not simulated) containment action."""
        with self._lock:
            self._executions.append((self.clock(), action_record["action_type"],
                                     action_record.get("target_host") or action_record.get("target_ip")))

    def status(self):
        return {
            "kill_switch": dict(self.kill_switch),
            "rate_limit": {
                "max_actions_per_hour": self.max_actions_per_hour,
                "executions_last_hour": self.executions_last_hour(),
            },
        }
