"""
Additional threat-intel providers (roadmap F41): AlienVault OTX, URLhaus, Shodan,
GreyNoise and Censys. Each is off until its key is set, and every one goes through
ThreatIntelClient, so the same rules apply as for VirusTotal and AbuseIPDB: external
enrichment must be enabled, only public IPs and file hashes are ever sent, answers are
cached, each provider has its own client-side rate limit and daily quota, failures
degrade to "UNAVAILABLE", and every verdict carries attribution.

Reputation providers return a 0-100 ``score`` and a ``flags`` boolean that the
consensus (soar/reputation.py) counts. Shodan and Censys describe *exposure* (open
ports, services), not maliciousness, so their verdicts carry ``context`` only and never
count toward a score.

Endpoints and response fields follow each provider's public API documentation as of
2026; none has been called with a real key from this repository.
"""

import base64
import os
import urllib.parse
from datetime import datetime, timezone

ATTRIBUTION = {
    "AlienVault OTX": "Pulse data from AlienVault OTX (https://otx.alienvault.com), used under its terms.",
    "URLhaus": "Data from URLhaus by abuse.ch (https://urlhaus.abuse.ch), used under its terms.",
    "Shodan": "Exposure data from Shodan (https://www.shodan.io), used under its terms.",
    "GreyNoise": "Classification from GreyNoise (https://www.greynoise.io), used under its terms.",
    "Censys": "Exposure data from Censys (https://search.censys.io), used under its terms.",
}


def _now():
    return datetime.now(timezone.utc).isoformat()


class Provider:
    name = ""
    env_key = ""
    kinds = ("ip",)
    default_per_min, default_per_day = 30, 1000

    def __init__(self, key, limiter):
        self.key = key
        self.limiter = limiter

    def request(self, kind, value):
        """(url, headers, form_data_or_None)"""
        raise NotImplementedError

    def parse(self, kind, value, status, body):
        """Fields to merge into the verdict for a 200 answer."""
        raise NotImplementedError

    def verdict(self, call, kind, value):
        base = {"source": self.name, "indicator": value, "attribution": ATTRIBUTION[self.name], "fetched_at": _now()}
        allowed, retry_after = self.limiter.try_acquire()
        if not allowed:
            return dict(base, http_status=None, status="RATE_LIMITED", retry_after_sec=retry_after)
        url, headers, data = self.request(kind, value)
        status, body = call(url, headers, data)
        self.limiter.record(status if status is not None else 503)
        if status is None:
            return dict(base, http_status=None, status="UNAVAILABLE")
        if status == 404:  # unknown to the provider: a valid, empty answer
            return dict(base, http_status=404, score=0.0, flags=False)
        if status != 200:
            return dict(base, http_status=status, status="UNAVAILABLE")
        return dict(base, http_status=200, **self.parse(kind, value, status, body or {}))


class OTX(Provider):
    name, env_key, kinds = "AlienVault OTX", "OTX_API_KEY", ("ip", "hash")
    default_per_min, default_per_day = 60, 10000
    FLAG_PULSES = 3

    def request(self, kind, value):
        section = ("IPv6" if ":" in value else "IPv4") if kind == "ip" else "file"
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{urllib.parse.quote(value)}/general"
        return url, {"X-OTX-API-KEY": self.key}, None

    def parse(self, kind, value, status, body):
        pulses = int(((body.get("pulse_info") or {}).get("count")) or 0)
        return {"pulses": pulses, "score": float(min(100, pulses * 20)), "flags": pulses >= self.FLAG_PULSES}


class URLhaus(Provider):
    name, env_key, kinds = "URLhaus", "URLHAUS_AUTH_KEY", ("ip", "hash")
    default_per_min, default_per_day = 30, 5000

    def request(self, kind, value):
        if kind == "ip":
            return "https://urlhaus-api.abuse.ch/v1/host/", {"Auth-Key": self.key}, {"host": value}
        return "https://urlhaus-api.abuse.ch/v1/payload/", {"Auth-Key": self.key}, {"sha256_hash": value}

    def parse(self, kind, value, status, body):
        found = body.get("query_status") == "ok"
        if kind == "ip":
            urls = int(body.get("url_count") or 0) if found else 0
            return {"malware_urls": urls, "score": float(min(100, 50 + urls * 10)) if urls else 0.0, "flags": urls >= 1}
        return {"known_payload": found, "score": 90.0 if found else 0.0, "flags": found}


class GreyNoise(Provider):
    name, env_key = "GreyNoise", "GREYNOISE_API_KEY"
    default_per_min, default_per_day = 10, 50  # community API: small daily allowance

    def request(self, kind, value):
        return f"https://api.greynoise.io/v3/community/{urllib.parse.quote(value)}", {"key": self.key}, None

    def parse(self, kind, value, status, body):
        classification = body.get("classification") or "unknown"
        # "benign" / RIOT = known business service or scanner: evidence against maliciousness, so never a flag
        return {"classification": classification, "riot": bool(body.get("riot")),
                "score": 80.0 if classification == "malicious" else 0.0, "flags": classification == "malicious"}


class Shodan(Provider):
    name, env_key = "Shodan", "SHODAN_API_KEY"
    default_per_min, default_per_day = 60, 100

    def request(self, kind, value):
        query = urllib.parse.urlencode({"key": self.key, "minify": "true"})
        return f"https://api.shodan.io/shodan/host/{urllib.parse.quote(value)}?{query}", {}, None

    def parse(self, kind, value, status, body):
        return {"context": {"ports": sorted(body.get("ports") or [])[:50], "vulns": sorted(body.get("vulns") or [])[:50],
                            "tags": body.get("tags") or []}}


class Censys(Provider):
    name, env_key = "Censys", "CENSYS_API_ID"
    default_per_min, default_per_day = 10, 250

    def request(self, kind, value):
        secret = os.environ.get("CENSYS_API_SECRET", "")
        token = base64.b64encode(f"{self.key}:{secret}".encode()).decode()
        return f"https://search.censys.io/api/v2/hosts/{urllib.parse.quote(value)}", {"Authorization": f"Basic {token}"}, None

    def parse(self, kind, value, status, body):
        services = (body.get("result") or {}).get("services") or []
        return {"context": {"services": sorted({f"{s.get('port')}/{s.get('service_name')}" for s in services})[:50]}}


PROVIDER_CLASSES = [OTX, URLhaus, GreyNoise, Shodan, Censys]


def configured_providers(limiter_factory, environ=os.environ):
    """Instances for every provider whose key is set; limits from <NAME>_RATE_LIMIT_PER_MIN / _DAILY_QUOTA."""
    providers = []
    for cls in PROVIDER_CLASSES:
        key = environ.get(cls.env_key, "")
        if not key:
            continue
        prefix = cls.env_key.rsplit("_", 2)[0]
        per_min = int(environ.get(f"{prefix}_RATE_LIMIT_PER_MIN", cls.default_per_min))
        per_day = int(environ.get(f"{prefix}_DAILY_QUOTA", cls.default_per_day))
        providers.append(cls(key, limiter_factory(per_min, per_day)))
    return providers
