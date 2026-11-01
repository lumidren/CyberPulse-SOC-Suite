"""
TheHive 5 and Cortex integration (roadmap F36) - off by default.

TheHive: when ``THEHIVE_ENABLED=true`` with ``THEHIVE_URL`` and ``THEHIVE_API_KEY``,
each new incident is sent as a TheHive *alert* (``POST /api/v1/alert``) whose
``sourceRef`` is the CyberPulse case id, so analysts can merge alerts of one case.
TheHive is your own case-management server, so the URL must be a lab address
(private, loopback or *.lab/.local/.internal/.test); anything else is refused.

Observables are marked with PAP so Cortex analyzers that call outside services are
not run on internal identifiers: public IPs and file hashes get PAP:AMBER (2), host
names, accounts and internal IPs get PAP:RED (3) and the ``internal`` tag.

Cortex: ``CortexClient.run_analyzer`` (``CORTEX_URL``/``CORTEX_API_KEY``, also
lab-address only) runs an analyzer on a public IP or file hash; any other value is
refused before a request is made, as with the built-in enrichment client.

Status: payloads follow the TheHive 5 / Cortex 3 REST APIs as documented; tested
against a stubbed HTTP layer only, never against a running TheHive or Cortex.
"""

import ipaddress
import json
import os
import urllib.request
from urllib.parse import urlparse

from soar.enrichment import classify_indicator

SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PAP_AMBER, PAP_RED = 2, 3
OBSERVABLE_TYPES = {"ip-src": "ip", "ip-dst": "ip", "file-sha256": "hash", "hostname": "hostname",
                    "user-account": "other", "process-path": "filename"}


class IntegrationNotConfigured(RuntimeError):
    pass


def lab_url(url):
    parsed = urlparse(url or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False
    if parsed.hostname == "localhost" or parsed.hostname.endswith((".lab", ".local", ".internal", ".test")):
        return True
    try:
        addr = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback


def _post(url, api_key, payload, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - lab_url() checked the scheme
        return json.loads(resp.read().decode("utf-8") or "{}")


def observable(entry):
    """CyberPulse observable -> TheHive observable with a PAP that keeps internal values local."""
    value = str(entry.get("value"))
    shareable = classify_indicator(value) is not None
    obs = {"dataType": OBSERVABLE_TYPES.get(entry.get("type"), "other"), "data": value,
           "ioc": bool(entry.get("ioc")) and shareable, "pap": PAP_AMBER if shareable else PAP_RED,
           "tags": [] if shareable else ["internal"]}
    return obs


def alert_payload(incident, case_id):
    rule = incident.get("rule") or {}
    tasks = [t["title"] for t in (incident.get("playbook") or {}).get("tasks", [])]
    description = "\n".join([
        f"Rule: {rule.get('rule_id')} {rule.get('rule_name')}",
        f"ATT&CK: {rule.get('mitre_id')}",
        f"Risk: {(incident.get('risk_assessment') or {}).get('final_score')}",
        f"Response: {(incident.get('containment_action') or {}).get('action_type')} "
        f"({(incident.get('containment_action') or {}).get('status')})",
        f"CyberPulse incident {incident.get('incident_id')}, case {case_id}",
        "Simulated lab event." if incident.get("simulated") else "",
        *(["", "Playbook tasks:"] + [f"- {t}" for t in tasks] if tasks else []),
    ]).strip()
    return {
        "type": "cyberpulse", "source": "CyberPulse SOC", "sourceRef": case_id,
        "title": f"[CyberPulse] {rule.get('rule_name')}", "description": description,
        "severity": SEVERITY.get(rule.get("severity"), 2), "tlp": 2, "pap": 2,
        "tags": [f"rule:{rule.get('rule_id')}", f"attack:{rule.get('mitre_id')}"]
                + (["simulated"] if incident.get("simulated") else []),
        "observables": [observable(o) for o in incident.get("observables") or []],
    }


class TheHiveClient:
    def __init__(self, url=None, api_key=None, enabled=None, post=_post):
        self.url = (url if url is not None else os.environ.get("THEHIVE_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("THEHIVE_API_KEY", "")
        flag = enabled if enabled is not None else os.environ.get("THEHIVE_ENABLED", "false").lower() == "true"
        self.enabled = bool(flag and self.url and self.api_key)
        self._post = post

    def send(self, incident, case_id):
        """Create a TheHive alert for the incident. Never raises; returns a status dict for the incident."""
        if not self.enabled:
            return {"status": "DISABLED", "message": "THEHIVE_ENABLED is not true (local case record only)"}
        if not lab_url(self.url):
            return {"status": "REFUSED", "message": "THEHIVE_URL must be a lab address"}
        try:
            created = self._post(f"{self.url}/api/v1/alert", self.api_key, alert_payload(incident, case_id))
            return {"status": "SENT", "thehive_alert_id": created.get("_id") or created.get("id")}
        except Exception as exc:  # case management must never break the pipeline
            return {"status": "ERROR", "message": f"{type(exc).__name__}: {exc}"}


class CortexClient:
    def __init__(self, url=None, api_key=None, post=_post):
        self.url = (url if url is not None else os.environ.get("CORTEX_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("CORTEX_API_KEY", "")
        self._post = post

    def run_analyzer(self, analyzer_id, value):
        kind = classify_indicator(value)
        if kind is None:
            return {"status": "REFUSED", "message": "only public IPs and file hashes may be analysed"}
        if not (self.url and self.api_key):
            raise IntegrationNotConfigured("set CORTEX_URL and CORTEX_API_KEY")
        if not lab_url(self.url):
            return {"status": "REFUSED", "message": "CORTEX_URL must be a lab address"}
        job = self._post(f"{self.url}/api/analyzer/{analyzer_id}/run", self.api_key,
                         {"data": str(value), "dataType": kind, "tlp": 2, "pap": PAP_AMBER})
        return {"status": "SUBMITTED", "job_id": job.get("id")}
