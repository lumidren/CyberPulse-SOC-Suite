"""
Threat-intel feed ingestion, e.g. the CIPHER project's feeds (roadmap F38) - off by default.

A feed is downloaded in bulk and matched locally, so checking an event against it
sends nothing about the event anywhere (unlike per-indicator API lookups).

Sources (either or both):
  * ``CIPHER_FEED_URL``  - https URL, re-fetched every ``CIPHER_FEED_REFRESH_SEC`` (default 3600)
                           with ``If-None-Match`` so unchanged feeds cost one 304;
                           optional ``CIPHER_FEED_TOKEN`` sent as a Bearer token.
  * ``CIPHER_FEED_FILE`` - a local file, loaded at start and on each refresh.

Accepted formats:
  * JSON: ``{"indicators": [{"type": "ipv4"|"ipv6"|"sha256", "value": ..., "confidence": 0-100,
    "source": ..., "first_seen": ...}]}`` (the format CyberPulse expects from CIPHER;
    the CIPHER project's real output format has not been checked here);
  * STIX 2.1 bundles: ``indicator`` objects whose pattern is
    ``[ipv4-addr:value = '...']``, ``[ipv6-addr:value = '...']`` or ``[file:hashes.'SHA-256' = '...']``.

Only public IPs and SHA-256 hashes are kept; anything else in a feed is counted and
ignored. Matches are attached to the incident's threat intel as ``feed_matches``.
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

from soar.enrichment import classify_indicator, normalise_hash

STIX_PATTERN = re.compile(r"\[(ipv4-addr:value|ipv6-addr:value|file:hashes\.'SHA-256')\s*=\s*'([^']+)'\]")
MAX_FEED_BYTES = 20 * 1024 * 1024


def parse_feed(doc, default_source="feed"):
    """{"ip": {value: meta}, "hash": {value: meta}, "ignored": n} from a JSON or STIX 2.1 document."""
    out = {"ip": {}, "hash": {}, "ignored": 0}
    entries = []
    if isinstance(doc, dict) and doc.get("type") == "bundle":
        for obj in doc.get("objects") or []:
            if obj.get("type") != "indicator":
                continue
            m = STIX_PATTERN.search(str(obj.get("pattern", "")))
            if not m:
                out["ignored"] += 1
                continue
            entries.append({"value": m.group(2), "confidence": obj.get("confidence"),
                            "source": (obj.get("created_by_ref") or default_source), "first_seen": obj.get("valid_from")})
    elif isinstance(doc, dict):
        entries = list(doc.get("indicators") or [])
    for entry in entries:
        value = entry.get("value")
        kind = classify_indicator(value) if value else None
        if kind is None or (kind == "hash" and len(normalise_hash(value) or "") != 64):
            out["ignored"] += 1
            continue
        key = normalise_hash(value) if kind == "hash" else str(value)
        out[kind][key] = {"source": entry.get("source") or default_source, "confidence": entry.get("confidence"),
                          "first_seen": entry.get("first_seen")}
    return out


class FeedStore:
    def __init__(self):
        self.indicators = {"ip": {}, "hash": {}}
        self.status = {"loaded_at": None, "ip": 0, "hash": 0, "ignored": 0, "error": None, "sources": []}
        self._lock = threading.Lock()

    def replace(self, parsed, source):
        with self._lock:
            self.indicators = {"ip": parsed["ip"], "hash": parsed["hash"]}
            self.status.update(loaded_at=time.time(), ip=len(parsed["ip"]), hash=len(parsed["hash"]),
                               ignored=parsed["ignored"], error=None, sources=[source])

    def match(self, event):
        """Feed entries matching the event's source IP or file hashes."""
        details = event.get("details") or {}
        candidates = [("ip", event.get("source_ip"))]
        for key in ("FileHash_SHA256", "Hashes"):
            if details.get(key):
                candidates.append(("hash", normalise_hash(details[key])))
        hits = []
        with self._lock:
            for kind, value in candidates:
                meta = self.indicators[kind].get(str(value)) if value else None
                if meta:
                    hits.append({"type": kind, "value": value, **meta})
        return hits


class FeedClient:
    def __init__(self, store, url=None, path=None, token=None, opener=urllib.request.urlopen):
        self.store = store
        self.url = url if url is not None else os.environ.get("CIPHER_FEED_URL", "")
        self.path = path if path is not None else os.environ.get("CIPHER_FEED_FILE", "")
        self.token = token if token is not None else os.environ.get("CIPHER_FEED_TOKEN", "")
        self.refresh_sec = int(os.environ.get("CIPHER_FEED_REFRESH_SEC", "3600"))
        self.etag = None
        self._open = opener

    @property
    def configured(self):
        return bool(self.url or self.path)

    def refresh(self):
        """Load the file and/or fetch the URL. Never raises; errors are kept in the store status."""
        try:
            if self.path:
                with open(self.path, encoding="utf-8") as fh:
                    self.store.replace(parse_feed(json.load(fh), "file"), self.path)
            if self.url:
                if not self.url.startswith("https://"):
                    raise ValueError("CIPHER_FEED_URL must use https")
                headers = {"Accept": "application/json"}
                if self.etag:
                    headers["If-None-Match"] = self.etag
                if self.token:
                    headers["Authorization"] = f"Bearer {self.token}"
                req = urllib.request.Request(self.url, headers=headers)
                try:
                    with self._open(req, timeout=30) as resp:  # nosec B310 - https enforced above
                        body = resp.read(MAX_FEED_BYTES + 1)
                        if len(body) > MAX_FEED_BYTES:
                            raise ValueError("feed larger than 20 MB")
                        self.etag = resp.headers.get("ETag")
                        self.store.replace(parse_feed(json.loads(body.decode("utf-8")), "cipher"), self.url)
                except urllib.error.HTTPError as exc:
                    if exc.code != 304:
                        raise
            return self.store.status
        except Exception as exc:
            self.store.status["error"] = f"{type(exc).__name__}: {exc}"
            return self.store.status
