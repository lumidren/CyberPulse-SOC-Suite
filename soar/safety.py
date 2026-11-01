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
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple


# Actions that cut a host off the network
ISOLATION_ACTIONS = {"ISOLATE_HOST_AND_KILL_PROCESS", "REVERT_DEFENDER_POLICY_AND_ISOLATE"}


def _env_flag(name: str, default: str = "false") -> bool:
    return os.environ.get(name, default).strip().lower() == "true"


class AutomationSafety:
    """Process-wide safety state shared by the policy and containment engines."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._lock = threading.Lock()
        self.clock = clock  # injectable for tests

        # Rate limit: max containment executions in any rolling hour
        self.max_actions_per_hour = int(os.environ.get("CONTAINMENT_MAX_ACTIONS_PER_HOUR", "20"))
        self._executions: Deque[Tuple[float, str, Any]] = deque()  # (timestamp, action_type, target)

        # Isolation circuit breaker: N distinct hosts isolated within M minutes trips
        # the kill switch and pages a human (mass isolation usually means a bad rule).
        self.breaker_max_hosts = int(os.environ.get("ISOLATION_BREAKER_MAX_HOSTS", "3"))
        self.breaker_window_sec = int(os.environ.get("ISOLATION_BREAKER_WINDOW_MIN", "10")) * 60
        self._isolations: Deque[Tuple[float, Optional[str]]] = deque()  # (timestamp, host)
        self.breaker_trips: List[Dict[str, Any]] = []
        self.pager: Optional[Callable[[str], Any]] = None  # callable(message) set by the orchestrator to reach a human

        # TTLs: isolation and perimeter blocks expire (and are rolled back) unless renewed
        self.ttl_minutes = {
            "ISOLATE_HOST_AND_KILL_PROCESS": int(os.environ.get("ISOLATION_TTL_MIN", "240")),
            "REVERT_DEFENDER_POLICY_AND_ISOLATE": int(os.environ.get("ISOLATION_TTL_MIN", "240")),
            "BLOCK_SOURCE_IP_FIREWALL": int(os.environ.get("IP_BLOCK_TTL_MIN", "1440")),
        }
        self.kill_switch = {
            "engaged": _env_flag("CYBERPULSE_KILL_SWITCH"),
            "actor": "environment" if _env_flag("CYBERPULSE_KILL_SWITCH") else None,
            "reason": "CYBERPULSE_KILL_SWITCH=true at startup" if _env_flag("CYBERPULSE_KILL_SWITCH") else None,
            "changed_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------ kill switch
    def engage_kill_switch(self, actor: str, reason: str = "") -> Dict[str, Any]:
        """Halt all automated and approved containment until released."""
        with self._lock:
            self.kill_switch = {
                "engaged": True,
                "actor": actor,
                "reason": reason,
                "changed_at": datetime.now(timezone.utc).isoformat(),
            }
            return dict(self.kill_switch)

    def release_kill_switch(self, actor: str, reason: str = "") -> Dict[str, Any]:
        with self._lock:
            self.kill_switch = {
                "engaged": False,
                "actor": actor,
                "reason": reason,
                "changed_at": datetime.now(timezone.utc).isoformat(),
            }
            return dict(self.kill_switch)

    def is_halted(self) -> bool:
        return bool(self.kill_switch["engaged"])

    # ------------------------------------------------------------------ rate limit
    def _prune(self, window: Any, horizon_sec: float) -> None:
        cutoff = self.clock() - horizon_sec
        while window and window[0][0] < cutoff:
            window.popleft()

    def executions_last_hour(self) -> int:
        with self._lock:
            self._prune(self._executions, 3600)
            return len(self._executions)

    def rate_limit_exceeded(self) -> bool:
        """True once the rolling-hour execution budget is spent."""
        return self.executions_last_hour() >= self.max_actions_per_hour

    def record_execution(self, action_record: Dict[str, Any]) -> None:
        """Count an executed (not staged, not simulated) containment action."""
        with self._lock:
            self._executions.append((self.clock(), action_record["action_type"],
                                     action_record.get("target_host") or action_record.get("target_ip")))
        if action_record["action_type"] in ISOLATION_ACTIONS:
            self._record_isolation(action_record.get("target_host"))

    def _record_isolation(self, host: Optional[str]) -> None:
        with self._lock:
            self._isolations.append((self.clock(), host))
            self._prune(self._isolations, self.breaker_window_sec)
            hosts = {h for _, h in self._isolations}
            tripped = len(hosts) >= self.breaker_max_hosts and not self.kill_switch["engaged"]
        if tripped:
            self._trip_breaker(sorted(hosts))

    def _trip_breaker(self, hosts: List[Any]) -> None:
        minutes = self.breaker_window_sec // 60
        reason = (f"Isolation circuit breaker: {len(hosts)} hosts isolated within {minutes} min "
                  f"({', '.join(hosts)}). Automation halted pending human review.")
        self.engage_kill_switch("isolation-circuit-breaker", reason)
        trip = {"tripped_at": datetime.now(timezone.utc).isoformat(), "hosts": hosts, "reason": reason, "paged": False}
        if self.pager:
            try:
                # The page goes to an external chat service: host names stay in the local record only
                self.pager(f"Isolation circuit breaker: {len(hosts)} hosts isolated within {minutes} min. "
                           "Automation halted pending human review; host list at GET /api/safety.")
                trip["paged"] = True
            except Exception as exc:  # paging must never crash containment
                trip["page_error"] = str(exc)
        self.breaker_trips.append(trip)

    def ttl_for(self, action_type: str) -> Optional[int]:
        """TTL in minutes for an action type, or None if it does not expire."""
        return self.ttl_minutes.get(action_type)

    def status(self) -> Dict[str, Any]:
        return {
            "ttl_minutes": dict(self.ttl_minutes),
            "kill_switch": dict(self.kill_switch),
            "rate_limit": {
                "max_actions_per_hour": self.max_actions_per_hour,
                "executions_last_hour": self.executions_last_hour(),
            },
            "isolation_circuit_breaker": {
                "max_hosts": self.breaker_max_hosts,
                "window_minutes": self.breaker_window_sec // 60,
                "trips": list(self.breaker_trips),
            },
        }
