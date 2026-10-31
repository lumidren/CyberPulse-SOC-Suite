"""
External Threat-Intelligence Enrichment (CyberPulse SOC Lab)

Optional lookups against VirusTotal (v3) and AbuseIPDB (v2). Disabled unless
EXTERNAL_ENRICHMENT_ENABLED=true and the provider's API key is set; the lab's
default enrichment is the local synthetic fixture in soar/soar_engine.py.

Privacy rule enforced here, not by convention: only publicly routable IP
addresses are ever sent. RFC 1918, loopback, link-local, CGNAT, multicast,
reserved and documentation ranges stay on this machine.
"""

import ipaddress
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timezone

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check?{}"


def external_enrichment_enabled():
    return os.environ.get("EXTERNAL_ENRICHMENT_ENABLED", "false").strip().lower() == "true"


def is_shareable_ip(value):
    """True only for globally routable addresses (never internal / RFC 1918)."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def _default_transport(url, headers, timeout=8):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - fixed https provider URLs
        return resp.status, json.loads(resp.read().decode("utf-8"))


class ThreatIntelClient:
    def __init__(self, vt_key=None, abuse_key=None, transport=None, enabled=None):
        self.vt_key = vt_key if vt_key is not None else os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = abuse_key if abuse_key is not None else os.environ.get("ABUSEIPDB_API_KEY", "")
        self.transport = transport or _default_transport
        self.enabled = external_enrichment_enabled() if enabled is None else enabled

    def lookup_ip(self, ip):
        """Query configured providers for one IP. Internal addresses are refused before any I/O."""
        if not self.enabled:
            return {"status": "DISABLED", "verdicts": []}
        if not is_shareable_ip(ip):
            return {"status": "SKIPPED_INTERNAL", "verdicts": [],
                    "reason": "Internal/non-routable address: never sent to external services."}
        verdicts = []
        if self.vt_key:
            verdicts.append(self._virustotal_ip(ip))
        if self.abuse_key:
            verdicts.append(self._abuseipdb_ip(ip))
        return {"status": "OK" if verdicts else "NO_PROVIDERS", "verdicts": verdicts}

    def _virustotal_ip(self, ip):
        status, body = self.transport(VT_IP_URL.format(urllib.parse.quote(ip)), {"x-apikey": self.vt_key})
        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if status == 200 else {}
        return {"source": "VirusTotal", "indicator": ip, "http_status": status,
                "malicious": stats.get("malicious"), "fetched_at": datetime.now(timezone.utc).isoformat()}

    def _abuseipdb_ip(self, ip):
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        status, body = self.transport(ABUSEIPDB_CHECK_URL.format(query),
                                      {"Key": self.abuse_key, "Accept": "application/json"})
        score = body.get("data", {}).get("abuseConfidenceScore") if status == 200 else None
        return {"source": "AbuseIPDB", "indicator": ip, "http_status": status,
                "abuse_confidence": score, "fetched_at": datetime.now(timezone.utc).isoformat()}
