"""OTX, URLhaus, Shodan, GreyNoise and Censys enrichers (roadmap F41)."""

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.enrichment import ThreatIntelClient  # noqa: E402
from soar.reputation import consensus  # noqa: E402

KEYS = {"OTX_API_KEY": "o", "URLHAUS_AUTH_KEY": "u", "GREYNOISE_API_KEY": "g", "SHODAN_API_KEY": "s",
        "CENSYS_API_ID": "c", "CENSYS_API_SECRET": "cs"}
SHA = "c" * 64


class Transport:
    def __init__(self):
        self.calls = []

    def __call__(self, url, headers, data=None):
        self.calls.append((url, headers, data))
        if "otx.alienvault.com" in url:
            return 200, {"pulse_info": {"count": 5}}
        if "urlhaus-api" in url:
            return 200, ({"query_status": "ok", "url_count": 2} if data and "host" in data else {"query_status": "no_results"})
        if "greynoise" in url:
            return 200, {"classification": "malicious", "riot": False}
        if "shodan" in url:
            return 200, {"ports": [443, 22], "vulns": ["CVE-2024-0001"], "tags": []}
        if "censys" in url:
            return 200, {"result": {"services": [{"port": 22, "service_name": "SSH"}]}}
        return 404, {}


def client(transport, env=KEYS):
    with mock.patch.dict(os.environ, env, clear=False):
        return ThreatIntelClient(vt_key="", abuse_key="", transport=transport, enabled=True)


class TestIntelProviders(unittest.TestCase):

    def test_ip_lookup_queries_every_configured_provider(self):
        t = Transport()
        result = client(t).lookup("8.8.8.8")
        sources = {v["source"] for v in result["verdicts"]}
        self.assertEqual(sources, {"AlienVault OTX", "URLhaus", "GreyNoise", "Shodan", "Censys"})
        self.assertTrue(all(v["attribution"] for v in result["verdicts"]))
        urlhaus = next(c for c in t.calls if "urlhaus" in c[0])
        self.assertEqual(urlhaus[2], {"host": "8.8.8.8"})

    def test_internal_values_never_sent(self):
        t = Transport()
        c = client(t)
        for value in ("10.0.2.15", "WIN-DC01", "CORP\\j.doe"):
            c.lookup(value)
        self.assertEqual(t.calls, [])

    def test_context_providers_never_score(self):
        intel = {"external": {"ip": client(Transport()).lookup("8.8.8.8")}}
        result = consensus(intel)
        self.assertNotIn("Shodan", [s["source"] for s in result["sources"]])
        self.assertNotIn("Censys", [s["source"] for s in result["sources"]])
        self.assertEqual(set(result["flagging_sources"]), {"AlienVault OTX", "URLhaus", "GreyNoise"})
        self.assertTrue(result["corroborated"])

    def test_hash_lookup_without_virustotal(self):
        t = Transport()
        result = client(t).lookup(SHA)
        self.assertEqual({v["source"] for v in result["verdicts"]}, {"AlienVault OTX", "URLhaus"})
        self.assertFalse(any("greynoise" in c[0] or "shodan" in c[0] for c in t.calls), "IP-only providers")

    def test_rate_limit_and_outage_degrade(self):
        env = dict(KEYS, GREYNOISE_DAILY_QUOTA="1")
        t = Transport()
        c = client(t, env)
        c.lookup("8.8.8.8")
        c.cache.clear()
        second = c.lookup("8.8.8.8")
        grey = next(v for v in second["verdicts"] if v["source"] == "GreyNoise")
        self.assertEqual(grey["status"], "RATE_LIMITED")

        def down(url, headers, data=None):
            raise OSError("no route")
        result = client(down, {"OTX_API_KEY": "o"}).lookup("8.8.8.8")
        self.assertEqual(result["verdicts"][0]["status"], "UNAVAILABLE")

    def test_off_without_keys(self):
        with mock.patch.dict(os.environ, {k: "" for k in KEYS}):
            self.assertEqual(ThreatIntelClient(vt_key="", abuse_key="", enabled=True).providers, [])


if __name__ == "__main__":
    unittest.main()
