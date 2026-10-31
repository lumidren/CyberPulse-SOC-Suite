"""
MITRE Caldera operation import (roadmap F22) - stub, off by default.

Caldera runs adversary-emulation operations from its own server in your lab;
CyberPulse never starts operations or sends Caldera anything but a read request.
This module turns a finished operation's report into "what ran" and compares it
with the incidents CyberPulse raised, so you can see what fired and what missed.

Two ways to get a report:
  * Export it from the Caldera UI (Operations -> Download report) and pass the
    JSON file to scripts/caldera_compare.py. Works without any configuration.
  * Set CALDERA_URL and CALDERA_API_KEY to let ``fetch_report`` read it from
    ``GET {CALDERA_URL}/api/v2/operations/{id}/report``. Only http(s) URLs on a
    private/loopback address are accepted: Caldera is a lab server, not an
    external API.

The report layout parsed here (``steps -> {paw: {steps: [...]}}`` with an
``attack`` block per step) follows Caldera 4.x/5.x exports. It has been tested
on a hand-written fixture only, not on a live Caldera server; check it against
your version. Ability command text is never copied into results.
"""

import ipaddress
import json
import os
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

DEFAULT_WINDOW_SEC = 300


class CalderaNotConfigured(RuntimeError):
    pass


def _ts(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def parse_operation_report(report):
    """[{"technique", "tactic", "ability", "host", "ran_at", "status"}] for every executed step."""
    executed = []
    for paw, host in (report.get("steps") or {}).items():
        for step in (host or {}).get("steps") or []:
            attack = step.get("attack") or {}
            if not attack.get("technique_id"):
                continue
            executed.append({
                "technique": str(attack["technique_id"]).upper(),
                "tactic": attack.get("tactic"),
                "ability": step.get("name") or step.get("ability_id"),
                "host": paw,
                "ran_at": step.get("run") or step.get("finish"),
                # Caldera: 0 = success; anything else means the ability did not complete
                "status": "success" if step.get("status") == 0 else f"status {step.get('status')}",
            })
    return sorted(executed, key=lambda s: (_ts(s["ran_at"]) or 0, s["technique"]))


def _same_technique(a, b):
    return a == b or a.split(".")[0] == b or b.split(".")[0] == a


def compare(executed, incidents, window_sec=DEFAULT_WINDOW_SEC):
    """Pair each executed step with an incident for the same technique raised within the window after it."""
    results = []
    for step in executed:
        start = _ts(step["ran_at"])
        hit = None
        for inc in incidents:
            rule = inc.get("rule") or {}
            created = _ts(inc.get("created_at"))
            if not _same_technique(str(rule.get("mitre_id", "")).upper(), step["technique"]):
                continue
            if start is not None and created is not None and not (start <= created <= start + window_sec):
                continue
            hit = inc
            break
        results.append({**step, "detected": bool(hit),
                        "rule_id": (hit or {}).get("rule", {}).get("rule_id"),
                        "incident_id": (hit or {}).get("incident_id"),
                        "latency_sec": round(_ts(hit["created_at"]) - start, 3) if hit and start and _ts(hit.get("created_at")) else None})
    return results


def summarise(results):
    ran = [r for r in results if r["status"] == "success"]
    return {"steps": len(results), "succeeded": len(ran), "detected": sum(1 for r in ran if r["detected"]),
            "missed": sorted({r["technique"] for r in ran if not r["detected"]})}


def _allowed_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if parsed.hostname == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return parsed.hostname.endswith((".lab", ".local", ".internal", ".test"))
    return addr.is_private or addr.is_loopback


def fetch_report(operation_id, url=None, api_key=None, timeout=15):
    url = (url or os.environ.get("CALDERA_URL", "")).rstrip("/")
    api_key = api_key or os.environ.get("CALDERA_API_KEY")
    if not url or not api_key:
        raise CalderaNotConfigured("set CALDERA_URL and CALDERA_API_KEY, or export the report from the Caldera UI")
    if not _allowed_url(url):
        raise CalderaNotConfigured(f"CALDERA_URL must be a lab address (private, loopback or *.lab/.local): {url}")
    req = urllib.request.Request(f"{url}/api/v2/operations/{operation_id}/report", headers={"KEY": api_key})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - scheme checked above
        return json.loads(resp.read().decode("utf-8"))
