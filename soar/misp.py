"""
MISP IoC sharing (roadmap F37) - off by default.

Export: ``build_event`` turns a CyberPulse case (or any list of incidents) into a MISP
event. Only indicators that are safe to share leave: **public** IP addresses and file
hashes. Host names, accounts, internal IPs, command lines and telemetry are never
included. Events are created with distribution 0 (your organisation only) and
``tlp:amber``; widening distribution is a decision for a human in MISP.

Incidents from the simulator are synthetic, and synthetic indicators would pollute a
sharing community, so they are skipped unless ``include_simulated=True`` is passed
explicitly (for a private lab MISP).

Push: ``MispClient.push_event`` (``MISP_URL``, ``MISP_API_KEY``, ``MISP_SHARING_ENABLED=true``)
calls ``POST /events/add``. Pull: ``MispClient.fetch_iocs`` reads ``to_ids`` IP and hash
attributes from ``/attributes/restSearch`` for use as a local blocklist.

Status: request bodies follow the MISP REST API documentation; tested with a stubbed
HTTP layer only, never against a running MISP.
"""

import json
import os
import urllib.request

from soar.enrichment import classify_indicator, normalise_hash

THREAT_LEVEL = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3}  # MISP: 1 high, 2 medium, 3 low


class SharingDisabled(RuntimeError):
    pass


def _indicators(incident):
    telemetry = incident.get("telemetry") or {}
    details = telemetry.get("details") or {}
    candidates = [("ip-src", telemetry.get("source_ip"))]
    candidates += [("sha256", details.get(k)) for k in ("FileHash_SHA256", "Hashes")]
    for obs in incident.get("observables") or []:
        candidates.append(("ip-src" if obs.get("type", "").startswith("ip") else "sha256", obs.get("value")))
    for attr_type, value in candidates:
        kind = classify_indicator(value) if value else None
        if kind == "ip" and attr_type == "ip-src":
            yield "ip-src", str(value)
        elif kind == "hash":
            digest = normalise_hash(value)
            if digest and len(digest) == 64:
                yield "sha256", digest


def build_event(incidents, title, include_simulated=False):
    """MISP event dict from incidents; returns (event, skipped_simulated_count)."""
    attributes, seen, skipped, worst = [], set(), 0, "LOW"
    for inc in incidents:
        if inc.get("simulated") and not include_simulated:
            skipped += 1
            continue
        rule = inc.get("rule") or {}
        if THREAT_LEVEL.get(rule.get("severity"), 3) < THREAT_LEVEL[worst]:
            worst = rule.get("severity")
        for attr_type, value in _indicators(inc):
            if (attr_type, value) in seen:
                continue
            seen.add((attr_type, value))
            attributes.append({"type": attr_type, "category": "Network activity" if attr_type == "ip-src" else "Payload delivery",
                               "value": value, "to_ids": True, "distribution": 5,
                               "comment": f"{rule.get('rule_id')} {rule.get('mitre_id')}"})
    tags = [{"name": "tlp:amber"}, {"name": "cyberpulse"}] + ([{"name": "simulated"}] if include_simulated else [])
    event = {"Event": {"info": title, "distribution": 0, "threat_level_id": THREAT_LEVEL.get(worst, 3),
                       "analysis": 0, "Tag": tags, "Attribute": attributes}}
    return event, skipped


def _request(url, api_key, payload, timeout=15):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"Authorization": api_key, "Accept": "application/json",
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - https enforced below
        return json.loads(resp.read().decode("utf-8") or "{}")


class MispClient:
    def __init__(self, url=None, api_key=None, enabled=None, request=_request):
        self.url = (url if url is not None else os.environ.get("MISP_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("MISP_API_KEY", "")
        flag = enabled if enabled is not None else os.environ.get("MISP_SHARING_ENABLED", "false").lower() == "true"
        self.enabled = bool(flag and self.url and self.api_key)
        self._request = request

    def _check(self):
        if not self.enabled:
            raise SharingDisabled("set MISP_SHARING_ENABLED=true, MISP_URL and MISP_API_KEY")
        if not self.url.startswith("https://"):
            raise SharingDisabled("MISP_URL must use https")

    def push_event(self, event):
        self._check()
        if not event["Event"]["Attribute"]:
            return {"status": "NOTHING_TO_SHARE"}
        created = self._request(f"{self.url}/events/add", self.api_key, event)
        return {"status": "SENT", "event_id": (created.get("Event") or {}).get("id")}

    def fetch_iocs(self, last="1d"):
        """{"ip": set, "hash": set} of to_ids indicators published in the window."""
        self._check()
        body = {"returnFormat": "json", "type": ["ip-src", "ip-dst", "sha256"], "to_ids": 1, "last": last}
        data = self._request(f"{self.url}/attributes/restSearch", self.api_key, body)
        out = {"ip": set(), "hash": set()}
        for attr in (data.get("response") or {}).get("Attribute", []):
            kind = classify_indicator(attr.get("value"))
            if kind:
                out[kind].add(normalise_hash(attr["value"]) if kind == "hash" else attr["value"])
        return out
