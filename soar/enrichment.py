"""
External Threat-Intelligence Enrichment (CyberPulse SOC Lab)

Optional lookups against VirusTotal (v3) and AbuseIPDB (v2). Disabled unless
EXTERNAL_ENRICHMENT_ENABLED=true and the provider's API key is set; the lab's
default enrichment is the local synthetic fixture in soar/soar_engine.py.

Privacy rules enforced here, not by convention:

* Only publicly routable IP addresses are ever sent. RFC 1918, loopback,
  link-local, CGNAT, multicast, reserved and documentation ranges stay on
  this machine.
* The only other indicator type ever sent is a file hash (MD5/SHA-1/SHA-256
  hex digest). Hostnames, usernames, command lines, file names and file
  contents are never sent: anything that is not a public IP or a hash is
  refused before any request is built.
"""

import copy
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check?{}"


def virustotal_allowed():
    """VirusTotal's Public API is non-commercial only (see docs/THIRD_PARTY_APIS.md)."""
    tier = os.environ.get("VIRUSTOTAL_API_TIER", "public").strip().lower()
    commercial = os.environ.get("CYBERPULSE_COMMERCIAL_USE", "false").strip().lower() == "true"
    if tier == "public" and commercial:
        return False, "VirusTotal Public API is non-commercial only; set VIRUSTOTAL_API_TIER=premium with a Premium licence."
    return True, ""


def external_enrichment_enabled():
    return os.environ.get("EXTERNAL_ENRICHMENT_ENABLED", "false").strip().lower() == "true"


def is_shareable_ip(value):
    """True only for globally routable addresses (never internal / RFC 1918)."""
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def normalise_hash(value):
    """'SHA256=ABC...' or 'abc...' -> lower-case hex digest, or None if it is not a hash."""
    if not isinstance(value, str):
        return None
    digest = value.split("=", 1)[-1].strip()
    if _HEX_RE.match(digest) and len(digest) in HASH_LENGTHS:
        return digest.lower()
    return None


def classify_indicator(value):
    """'ip', 'hash', or None. None means: this value must never be sent anywhere."""
    if is_shareable_ip(value):
        return "ip"
    if normalise_hash(value):
        return "hash"
    return None


def _default_transport(url, headers, timeout=8):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - fixed https provider URLs
        return resp.status, json.loads(resp.read().decode("utf-8"))


class IocCache:
    """In-memory LRU cache with TTL for enrichment results (indicator -> verdicts).

    Holds only public IPs / file hashes and the provider verdicts for them. It is
    never written to disk, is emptied on restart, and can be cleared at any time
    with clear() (POST /api/enrichment/cache/clear).
    """

    def __init__(self, maxsize=None, ttl_sec=None, clock=time.time):
        self.maxsize = maxsize or int(os.environ.get("ENRICHMENT_CACHE_SIZE", "512"))
        self.ttl_sec = ttl_sec or int(os.environ.get("ENRICHMENT_CACHE_TTL_SEC", "3600"))
        self.clock = clock
        self._data = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            stored_at, value = item
            if self.clock() - stored_at > self.ttl_sec:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return copy.deepcopy(value)

    def put(self, key, value):
        with self._lock:
            self._data[key] = (self.clock(), copy.deepcopy(value))
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def clear(self):
        with self._lock:
            n = len(self._data)
            self._data.clear()
            return n

    def __len__(self):
        return len(self._data)


class ThreatIntelClient:
    def __init__(self, vt_key=None, abuse_key=None, transport=None, enabled=None, cache=None):
        self.vt_key = vt_key if vt_key is not None else os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = abuse_key if abuse_key is not None else os.environ.get("ABUSEIPDB_API_KEY", "")
        self.transport = transport or _default_transport
        self.enabled = external_enrichment_enabled() if enabled is None else enabled
        self.cache = cache or IocCache()

    def _cached(self, key, fetch):
        hit = self.cache.get(key)
        if hit is not None:
            hit["cached"] = True
            return hit
        result = fetch()
        if result.get("status") == "OK":
            self.cache.put(key, result)
        result["cached"] = False
        return result

    def lookup(self, indicator):
        """Single entry point: only public IPs and file hashes are ever queried."""
        kind = classify_indicator(indicator)
        if kind == "ip":
            return self.lookup_ip(indicator)
        if kind == "hash":
            return self.lookup_hash(indicator)
        return {"status": "REFUSED", "verdicts": [],
                "reason": "Only public IPs and file hashes may be sent; hostnames, usernames and content never are."}

    def lookup_hash(self, value):
        if not self.enabled:
            return {"status": "DISABLED", "verdicts": []}
        digest = normalise_hash(value)
        if not digest:
            return {"status": "REFUSED", "verdicts": [], "reason": "Not a file hash."}
        if not self.vt_key:
            return {"status": "NO_PROVIDERS", "verdicts": []}
        return self._cached(f"hash:{digest}", lambda: self._fetch_hash(digest))

    def _fetch_hash(self, digest):
        blocked = self._vt_terms_block(digest)
        if blocked:
            return {"status": "REFUSED_BY_TERMS", "verdicts": [blocked]}
        status, body = self.transport(VT_FILE_URL.format(digest), {"x-apikey": self.vt_key})
        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if status == 200 else {}
        return {"status": "OK", "verdicts": [{"source": "VirusTotal", "indicator": digest, "http_status": status,
                                              "malicious": stats.get("malicious"),
                                              "fetched_at": datetime.now(timezone.utc).isoformat()}]}

    def lookup_ip(self, ip):
        """Query configured providers for one IP. Internal addresses are refused before any I/O."""
        if not self.enabled:
            return {"status": "DISABLED", "verdicts": []}
        if not is_shareable_ip(ip):
            return {"status": "SKIPPED_INTERNAL", "verdicts": [],
                    "reason": "Internal/non-routable address: never sent to external services."}
        return self._cached(f"ip:{ip}", lambda: self._fetch_ip(ip))

    def _fetch_ip(self, ip):
        verdicts = []
        if self.vt_key:
            verdicts.append(self._virustotal_ip(ip))
        if self.abuse_key:
            verdicts.append(self._abuseipdb_ip(ip))
        return {"status": "OK" if verdicts else "NO_PROVIDERS", "verdicts": verdicts}

    def _vt_terms_block(self, indicator):
        allowed, reason = virustotal_allowed()
        if allowed:
            return None
        return {"source": "VirusTotal", "indicator": indicator, "http_status": None,
                "status": "REFUSED_BY_TERMS", "reason": reason,
                "fetched_at": datetime.now(timezone.utc).isoformat()}

    def _virustotal_ip(self, ip):
        blocked = self._vt_terms_block(ip)
        if blocked:
            return blocked
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
