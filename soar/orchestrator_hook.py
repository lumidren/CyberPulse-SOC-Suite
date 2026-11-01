"""
Hand incidents to an external SOAR such as Shuffle or n8n (roadmap F40) - off by default.

Set ``ORCHESTRATOR_WEBHOOK_URL`` (the Shuffle/n8n webhook trigger) and
``ORCHESTRATOR_WEBHOOK_SECRET``. Every incident is POSTed as JSON, signed with the same
HMAC scheme as CyberPulse's own ingest (``X-CyberPulse-Timestamp`` and
``X-CyberPulse-Signature: sha256=...`` over ``timestamp + "." + body``), so the workflow
can verify it came from CyberPulse.

What is sent depends on where the webhook lives:
  * a lab address (private, loopback, *.lab/.local/.internal/.test): the incident id,
    case id, rule, policy decision, response (action id, type, status), observables and
    the redacted telemetry - the workflow is your own infrastructure;
  * anywhere else (e.g. a hosted n8n): only the pseudonymised summary used for chat
    notifications, because internal identifiers never go to an external service.

The workflow acts back through the normal authenticated API (``POST
/api/approvals/<action_id>/approve`` or ``/reject`` with an API key), so approval stays
with a human or a workflow step you configured to ask one. CyberPulse never gives the
external orchestrator a way around the kill switch, protected assets or rate limits.
"""

import json
import os
import urllib.request

from soar.ingest_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign_payload
from soar.notifications import external_summary, validate_webhook_url
from soar.thehive import lab_url


def internal_payload(incident):
    action = incident.get("containment_action") or {}
    return {
        "incident_id": incident.get("incident_id"), "case_id": incident.get("case_id"),
        "rule": incident.get("rule"), "policy_decision": incident.get("policy_decision"),
        "response": {k: action.get(k) for k in ("action_id", "action_type", "status", "execution_intent")},
        "observables": incident.get("observables"), "telemetry": incident.get("telemetry"),
        "simulated": bool(incident.get("simulated")),
        "approve_url": f"/api/approvals/{action.get('action_id')}/approve" if action.get("action_id") else None,
    }


def _post(url, body, headers, timeout=10):
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - URL checked by the caller
        return resp.status


class OrchestratorWebhook:
    def __init__(self, url=None, secret=None, post=_post):
        self.url = url if url is not None else os.environ.get("ORCHESTRATOR_WEBHOOK_URL", "")
        self.secret = secret if secret is not None else os.environ.get("ORCHESTRATOR_WEBHOOK_SECRET", "")
        self._post = post

    @property
    def enabled(self):
        return bool(self.url and self.secret)

    def payload_for(self, incident):
        if lab_url(self.url):
            return {"scope": "internal", "incident": internal_payload(incident)}
        return {"scope": "external", "incident": external_summary(incident)}

    def send(self, incident):
        """POST the signed incident. Never raises; returns a status dict for the incident."""
        if not self.enabled:
            return {"status": "DISABLED"}
        if not lab_url(self.url):
            ok, reason = validate_webhook_url(self.url)
            if not ok:
                return {"status": "BLOCKED", "message": reason}
        payload = self.payload_for(incident)
        body = json.dumps(payload, default=str).encode("utf-8")
        ts, signature = sign_payload(self.secret, body)
        headers = {"Content-Type": "application/json", TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: signature,
                   "User-Agent": "CyberPulse-SOC"}
        try:
            return {"status": "SENT", "code": self._post(self.url, body, headers), "scope": payload["scope"]}
        except Exception as exc:  # an external orchestrator must never break the pipeline
            return {"status": "ERROR", "message": f"{type(exc).__name__}: {exc}"}
