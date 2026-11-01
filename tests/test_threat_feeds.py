"""Bulk threat feeds (CIPHER) matched locally (roadmap F38)."""

import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.threat_feeds import FeedClient, FeedStore, parse_feed  # noqa: E402

SHA = "b" * 64
JSON_FEED = {"indicators": [{"type": "ipv4", "value": "203.0.113.200", "confidence": 90, "source": "cipher"},
                            {"type": "ipv4", "value": "8.8.8.8", "confidence": 40},
                            {"type": "ipv4", "value": "10.0.0.5"},
                            {"type": "sha256", "value": SHA},
                            {"type": "domain", "value": "evil.example"}]}
STIX = {"type": "bundle", "objects": [
    {"type": "indicator", "pattern": "[ipv4-addr:value = '8.8.4.4']", "confidence": 70},
    {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = '{SHA}']"},
    {"type": "indicator", "pattern": "[domain-name:value = 'x.example']"},
    {"type": "malware", "name": "ignored"}]}


class Resp:
    def __init__(self, body, etag="v1"):
        self._body, self.headers = body, {"ETag": etag}

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestThreatFeeds(unittest.TestCase):

    def test_json_feed_keeps_public_ips_and_hashes_only(self):
        parsed = parse_feed(JSON_FEED)
        self.assertEqual(set(parsed["ip"]), {"8.8.8.8"})  # documentation and private ranges are not public
        self.assertEqual(set(parsed["hash"]), {SHA})
        self.assertEqual(parsed["ignored"], 3)

    def test_stix_bundle(self):
        parsed = parse_feed(STIX)
        self.assertEqual((set(parsed["ip"]), set(parsed["hash"]), parsed["ignored"]), ({"8.8.4.4"}, {SHA}, 1))

    def test_local_matching(self):
        store = FeedStore()
        store.replace(parse_feed(STIX), "test")
        hits = store.match({"source_ip": "8.8.4.4", "details": {"FileHash_SHA256": SHA.upper()}})
        self.assertEqual(sorted(h["type"] for h in hits), ["hash", "ip"])
        self.assertEqual(store.match({"source_ip": "1.1.1.1", "details": {}}), [])

    def test_client_file_url_etag_and_errors(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(JSON_FEED, fh)
        try:
            store = FeedStore()
            self.assertEqual(FeedClient(store, url="", path=fh.name).refresh()["ip"], 1)
        finally:
            os.unlink(fh.name)
        seen = []

        def opener(req, timeout=30):
            seen.append(dict(req.header_items()))
            if len(seen) == 2:
                raise urllib.error.HTTPError(req.full_url, 304, "Not Modified", {}, io.BytesIO())
            return Resp(json.dumps(STIX).encode())
        store = FeedStore()
        client = FeedClient(store, url="https://cipher.lab/feed.json", path="", token="t", opener=opener)
        self.assertEqual(client.refresh()["ip"], 1)
        self.assertEqual(client.refresh()["error"], None, "304 keeps the current feed")
        self.assertEqual(seen[1].get("If-none-match"), "v1")
        self.assertEqual(seen[0].get("Authorization"), "Bearer t")
        self.assertIn("https", FeedClient(FeedStore(), url="http://x/feed", path="").refresh()["error"])


if __name__ == "__main__":
    unittest.main()
