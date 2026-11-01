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

# Shown next to every verdict that came from a provider (roadmap E60)
ATTRIBUTION = {
    "VirusTotal": "Reputation data from VirusTotal (https://www.virustotal.com), used under its terms.",
    "AbuseIPDB": "Reputation data from AbuseIPDB (https://www.abuseipdb.com), used under its terms.",
}


def strip_provider_data(incident):
    """Copy of an incident with third-party verdict payloads removed, for anything written
    to disk or shared (exports). Providers' data is used, never redistributed (E61)."""
    stripped = copy.deepcopy(incident)
    intel = stripped.get("threat_intel") or {}
    if "external" in intel:
        intel["external"] = {"note": "Third-party reputation data removed from exports (provider terms)."}
    return stripped


def attributed(verdict):
    verdict["attribution"] = ATTRIBUTION.get(verdict.get("source"), "")
    return verdict


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


DEGRADED_STATUSES = {"UNAVAILABLE", "RATE_LIMITED", "REFUSED_BY_TERMS"}


def enrichment_degraded(external):
    """True if enrichment was attempted but any provider answer is missing or failed."""
    for part in (external or {}).values():
        if not isinstance(part, dict):
            continue
        for verdict in part.get("verdicts", []):
            if verdict.get("status") in DEGRADED_STATUSES or (verdict.get("http_status") or 200) >= 400:
                return True
    return False


def _default_transport(url, headers, timeout=8, data=None):
    body = urllib.parse.urlencode(data).encode("ascii") if data else None
    req = urllib.request.Request(url, headers=headers, data=body, method="POST" if body else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - fixed https provider URLs
        return resp.status, json.loads(resp.read().decode("utf-8"))


class ProviderLimiter:
    """Client-side quota guard for one provider: per-minute rate, daily quota, backoff.

    Requests that would exceed the provider's published limits are never sent.
    After a 429 or 5xx, further requests wait an exponentially growing backoff
    (base 60 s, doubling, capped at 15 min); a success resets it.
    """

    def __init__(self, per_minute, per_day, clock=time.time, base_backoff=60, max_backoff=900):
        self.per_minute = per_minute
        self.per_day = per_day
        self.clock = clock
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self._minute = []
        self._day = []
        self._failures = 0
        self.blocked_until = 0.0
        self._lock = threading.Lock()

    def try_acquire(self):
        """(allowed, retry_after_sec)."""
        now = self.clock()
        with self._lock:
            if now < self.blocked_until:
                return False, round(self.blocked_until - now, 1)
            self._minute = [t for t in self._minute if now - t < 60]
            self._day = [t for t in self._day if now - t < 86400]
            if len(self._minute) >= self.per_minute:
                return False, round(60 - (now - self._minute[0]), 1)
            if len(self._day) >= self.per_day:
                return False, round(86400 - (now - self._day[0]), 1)
            self._minute.append(now)
            self._day.append(now)
            return True, 0

    def record(self, http_status, retry_after=None):
        with self._lock:
            if http_status == 429 or (http_status is not None and http_status >= 500):
                self._failures += 1
                backoff = min(self.max_backoff, self.base_backoff * 2 ** (self._failures - 1))
                if retry_after:
                    backoff = max(backoff, float(retry_after))
                self.blocked_until = self.clock() + backoff
            else:
                self._failures = 0


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
    def __init__(self, vt_key=None, abuse_key=None, transport=None, enabled=None, cache=None, clock=time.time):
        self.vt_key = vt_key if vt_key is not None else os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.abuse_key = abuse_key if abuse_key is not None else os.environ.get("ABUSEIPDB_API_KEY", "")
        self.transport = transport or _default_transport
        self.enabled = external_enrichment_enabled() if enabled is None else enabled
        self.cache = cache or IocCache()
        # VirusTotal Public API: 4 requests/minute and a daily quota (docs/THIRD_PARTY_APIS.md)
        self.vt_limiter = ProviderLimiter(int(os.environ.get("VT_RATE_LIMIT_PER_MIN", "4")),
                                          int(os.environ.get("VT_DAILY_QUOTA", "500")), clock=clock)
        # AbuseIPDB free plan: daily quota on the check endpoint (docs/THIRD_PARTY_APIS.md)
        self.abuse_limiter = ProviderLimiter(int(os.environ.get("ABUSEIPDB_RATE_LIMIT_PER_MIN", "60")),
                                             int(os.environ.get("ABUSEIPDB_DAILY_QUOTA", "1000")), clock=clock)
        # OTX, URLhaus, GreyNoise, Shodan, Censys: each enabled by its own key (soar/intel_providers.py)
        from soar.intel_providers import configured_providers
        self.providers = configured_providers(lambda per_min, per_day: ProviderLimiter(per_min, per_day, clock=clock))

    def _provider_call(self, url, headers, data):
        """Like _call, with an optional form body (URLhaus uses POST)."""
        try:
            return self.transport(url, headers, data=data) if data else self.transport(url, headers)
        except Exception as exc:
            self.last_error = str(exc)
            return None, {}

    def _provider_verdicts(self, kind, value):
        return [p.verdict(self._provider_call, kind, value) for p in self.providers if kind in p.kinds]

    def _call(self, url, headers):
        """Transport call that never raises: outages become (None, {})."""
        try:
            return self.transport(url, headers)
        except Exception as exc:  # network errors, timeouts, bad JSON, HTTP errors
            self.last_error = str(exc)
            return None, {}

    def _cached(self, key, fetch):
        hit = self.cache.get(key)
        if hit is not None:
            hit["cached"] = True
            return hit
        result = fetch()
        # Cache only genuine provider answers, never rate-limited / refused placeholders
        if result.get("status") == "OK" and all("status" not in v for v in result.get("verdicts", [])):
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
        if not self.vt_key and not any("hash" in p.kinds for p in self.providers):
            return {"status": "NO_PROVIDERS", "verdicts": []}
        return self._cached(f"hash:{digest}", lambda: self._fetch_hash(digest))

    def _fetch_hash(self, digest):
        extra = self._provider_verdicts("hash", digest)
        if not self.vt_key:
            return {"status": "OK", "verdicts": extra}
        result = self._fetch_vt_hash(digest)
        result["verdicts"] += extra
        return result

    def _fetch_vt_hash(self, digest):
        blocked = self._vt_terms_block(digest) or self._vt_rate_block(digest)
        if blocked:
            return {"status": blocked["status"], "verdicts": [blocked]}
        status, body = self._call(VT_FILE_URL.format(digest), {"x-apikey": self.vt_key})
        self.vt_limiter.record(status if status is not None else 503)
        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if status == 200 else {}
        if status is None:
            return {"status": "UNAVAILABLE", "verdicts": [attributed({
                "source": "VirusTotal", "indicator": digest, "http_status": None, "status": "UNAVAILABLE",
                "fetched_at": datetime.now(timezone.utc).isoformat()})]}
        return {"status": "OK", "verdicts": [attributed({"source": "VirusTotal", "indicator": digest, "http_status": status,
                                                         "malicious": stats.get("malicious"),
                                                         "fetched_at": datetime.now(timezone.utc).isoformat()})]}

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
        verdicts += self._provider_verdicts("ip", ip)
        return {"status": "OK" if verdicts else "NO_PROVIDERS", "verdicts": verdicts}

    def _vt_terms_block(self, indicator):
        allowed, reason = virustotal_allowed()
        if allowed:
            return None
        return attributed({"source": "VirusTotal", "indicator": indicator, "http_status": None,
                "status": "REFUSED_BY_TERMS", "reason": reason,
                "fetched_at": datetime.now(timezone.utc).isoformat()})

    def _vt_rate_block(self, indicator):
        allowed, retry_after = self.vt_limiter.try_acquire()
        if allowed:
            return None
        return attributed({"source": "VirusTotal", "indicator": indicator, "http_status": None, "status": "RATE_LIMITED",
                "retry_after_sec": retry_after, "fetched_at": datetime.now(timezone.utc).isoformat()})

    def _virustotal_ip(self, ip):
        blocked = self._vt_terms_block(ip) or self._vt_rate_block(ip)
        if blocked:
            return blocked
        status, body = self._call(VT_IP_URL.format(urllib.parse.quote(ip)), {"x-apikey": self.vt_key})
        self.vt_limiter.record(status if status is not None else 503)
        stats = body.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) if status == 200 else {}
        verdict = attributed({"source": "VirusTotal", "indicator": ip, "http_status": status,
                              "malicious": stats.get("malicious"), "fetched_at": datetime.now(timezone.utc).isoformat()})
        if status is None:
            verdict["status"] = "UNAVAILABLE"
        return verdict

    def _abuseipdb_ip(self, ip):
        allowed, retry_after = self.abuse_limiter.try_acquire()
        if not allowed:
            return attributed({"source": "AbuseIPDB", "indicator": ip, "http_status": None, "status": "RATE_LIMITED",
                    "retry_after_sec": retry_after, "fetched_at": datetime.now(timezone.utc).isoformat()})
        query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        status, body = self._call(ABUSEIPDB_CHECK_URL.format(query),
                                  {"Key": self.abuse_key, "Accept": "application/json"})
        self.abuse_limiter.record(status if status is not None else 503)
        score = body.get("data", {}).get("abuseConfidenceScore") if status == 200 else None
        verdict = attributed({"source": "AbuseIPDB", "indicator": ip, "http_status": status,
                              "abuse_confidence": score, "fetched_at": datetime.now(timezone.utc).isoformat()})
        if status is None:
            verdict["status"] = "UNAVAILABLE"
        return verdict
