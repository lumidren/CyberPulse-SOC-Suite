"""External threat-intel enrichment safeguards (roadmap E49-E64). No real network calls."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.enrichment import ThreatIntelClient, classify_indicator, is_shareable_ip  # noqa: E402


class RecordingTransport:
    """Fake HTTP transport: records every outbound request instead of sending it."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def __call__(self, url, headers, timeout=8):
        self.calls.append(url)
        if "virustotal" in url:
            return 200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}}
        return 200, {"data": {"abuseConfidenceScore": 87}}


def client(transport, **kw):
    return ThreatIntelClient(vt_key="vt-test", abuse_key="abuse-test", transport=transport, enabled=True, **kw)


class TestInternalIndicatorsNeverLeave(unittest.TestCase):

    def test_shareable_ip_rules(self):
        for internal in ["10.0.0.5", "172.16.4.4", "192.168.1.1", "127.0.0.1", "169.254.169.254",
                         "100.64.0.1", "::1", "fe80::1", "fd00::1", "224.0.0.1", "203.0.113.9"]:
            self.assertFalse(is_shareable_ip(internal), internal)
        self.assertTrue(is_shareable_ip("8.8.8.8"))

    def test_internal_ip_lookup_makes_no_request(self):
        transport = RecordingTransport()
        for ip in ["10.0.0.45", "192.168.10.3", "127.0.0.1"]:
            result = client(transport).lookup_ip(ip)
            self.assertEqual(result["status"], "SKIPPED_INTERNAL")
        self.assertEqual(transport.calls, [])

    def test_public_ip_is_looked_up(self):
        transport = RecordingTransport()
        result = client(transport).lookup_ip("8.8.8.8")
        self.assertEqual(result["status"], "OK")
        self.assertEqual(len(transport.calls), 2)

    def test_disabled_by_default(self):
        transport = RecordingTransport()
        previous = os.environ.pop("EXTERNAL_ENRICHMENT_ENABLED", None)
        try:
            result = ThreatIntelClient(vt_key="k", abuse_key="k", transport=transport).lookup_ip("8.8.8.8")
        finally:
            if previous is not None:
                os.environ["EXTERNAL_ENRICHMENT_ENABLED"] = previous
        self.assertEqual(result["status"], "DISABLED")
        self.assertEqual(transport.calls, [])


class TestOnlyTypedIndicatorsAreSent(unittest.TestCase):

    def test_non_indicators_refused_without_request(self):
        transport = RecordingTransport()
        c = client(transport)
        for value in ["WIN-DC01.corp.local", "CORP\\Administrator", "j.doe@corp.local",
                      "powershell.exe -enc AAAA", "C:\\Users\\j.doe\\secret.docx", "MZ\x90\x00 file bytes"]:
            self.assertIsNone(classify_indicator(value), value)
            self.assertEqual(c.lookup(value)["status"], "REFUSED")
        self.assertEqual(transport.calls, [])

    def test_hash_lookup_sends_only_the_digest(self):
        transport = RecordingTransport()
        digest = "F058F9A5D60E36E4E2C79E89DCE9A32158814F23D6980D4181F54B00D499E0C1"
        self.assertEqual(client(transport).lookup("SHA256=" + digest)["status"], "OK")
        self.assertEqual(transport.calls, ["https://www.virustotal.com/api/v3/files/" + digest.lower()])

    def test_pipeline_never_sends_hosts_or_users(self):
        os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
        from simulator.attack_simulator import SCRIPTED_GENERATORS
        from soar.soar_engine import SOAROrchestrator
        transport = RecordingTransport()
        orch = SOAROrchestrator()
        orch.intel_client = client(transport)
        sent_hosts_users = []
        for _name, gen in SCRIPTED_GENERATORS:
            event = gen()
            orch.process_event(event)
            for url in transport.calls:
                for secret in (event["computer_name"], event["user"].split("\\")[-1]):
                    if secret and secret.lower() in url.lower():
                        sent_hosts_users.append((secret, url))
        self.assertEqual(sent_hosts_users, [])


class TestEnrichmentCanBeDisabled(unittest.TestCase):

    def test_health_check_does_not_probe_providers_when_disabled(self):
        from soar import health_monitor
        probed = []
        original = health_monitor.check_http_endpoint
        health_monitor.check_http_endpoint = lambda url, timeout=0.8: (probed.append(url), (False, None))[1]
        try:
            result = health_monitor.IntegrationHealthMonitor().check_all_integrations(enrichment_enabled=False)
        finally:
            health_monitor.check_http_endpoint = original
        self.assertEqual(probed, [])
        self.assertEqual(result["services"]["virustotal"]["status"], "DISABLED")
        self.assertEqual(result["services"]["abuseipdb"]["status"], "DISABLED")

    def test_health_check_probes_when_enabled(self):
        from soar import health_monitor
        probed = []
        original = health_monitor.check_http_endpoint
        health_monitor.check_http_endpoint = lambda url, timeout=0.8: (probed.append(url), (True, 1.0))[1]
        try:
            health_monitor.IntegrationHealthMonitor().check_all_integrations(enrichment_enabled=True)
        finally:
            health_monitor.check_http_endpoint = original
        self.assertEqual(len(probed), 2)


class TestIocCache(unittest.TestCase):

    def test_repeat_lookup_served_from_cache(self):
        transport = RecordingTransport()
        c = client(transport)
        first = c.lookup("8.8.8.8")
        second = c.lookup("8.8.8.8")
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(len(transport.calls), 2)  # two providers, queried once

    def test_ttl_and_lru_eviction_and_clear(self):
        from soar.enrichment import IocCache
        now = [0.0]
        cache = IocCache(maxsize=2, ttl_sec=10, clock=lambda: now[0])
        cache.put("a", {"v": 1})
        cache.put("b", {"v": 2})
        cache.put("c", {"v": 3})            # evicts least-recently-used "a"
        self.assertIsNone(cache.get("a"))
        now[0] += 11                         # TTL elapsed
        self.assertIsNone(cache.get("b"))
        cache.put("d", {"v": 4})
        self.assertEqual(cache.clear(), 2)
        self.assertEqual(len(cache), 0)


class TestVirusTotalTerms(unittest.TestCase):

    def _with_env(self, **env):
        previous = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        return previous

    def _restore(self, previous):
        for k, v in previous.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_public_tier_refused_for_commercial_use(self):
        previous = self._with_env(VIRUSTOTAL_API_TIER="public", CYBERPULSE_COMMERCIAL_USE="true")
        try:
            transport = RecordingTransport()
            c = ThreatIntelClient(vt_key="vt", abuse_key="", transport=transport, enabled=True)
            result = c.lookup("8.8.8.8")
            self.assertEqual(result["verdicts"][0]["status"], "REFUSED_BY_TERMS")
            self.assertEqual(transport.calls, [])
        finally:
            self._restore(previous)

    def test_premium_tier_allowed_for_commercial_use(self):
        previous = self._with_env(VIRUSTOTAL_API_TIER="premium", CYBERPULSE_COMMERCIAL_USE="true")
        try:
            transport = RecordingTransport()
            ThreatIntelClient(vt_key="vt", abuse_key="", transport=transport, enabled=True).lookup("8.8.8.8")
            self.assertEqual(len(transport.calls), 1)
        finally:
            self._restore(previous)


class TestVirusTotalRateLimit(unittest.TestCase):

    def test_four_per_minute_then_rate_limited(self):
        now = [1000.0]
        transport = RecordingTransport()
        c = ThreatIntelClient(vt_key="vt", abuse_key="", transport=transport, enabled=True, clock=lambda: now[0])
        statuses = [c.lookup(f"8.8.4.{i}")["verdicts"][0].get("status", "OK") for i in range(6)]
        self.assertEqual(statuses, ["OK"] * 4 + ["RATE_LIMITED"] * 2)
        self.assertEqual(len(transport.calls), 4)
        now[0] += 61
        self.assertEqual(c.lookup("8.8.4.99")["verdicts"][0].get("status", "OK"), "OK")
        # a rate-limited answer must not be cached: retrying later reaches the provider
        self.assertEqual(c.lookup("8.8.4.5")["verdicts"][0].get("status", "OK"), "OK")

    def test_backoff_after_429(self):
        from soar.enrichment import ProviderLimiter
        now = [0.0]
        limiter = ProviderLimiter(per_minute=100, per_day=1000, clock=lambda: now[0])
        self.assertTrue(limiter.try_acquire()[0])
        limiter.record(429)
        allowed, retry = limiter.try_acquire()
        self.assertFalse(allowed)
        self.assertEqual(retry, 60)
        now[0] += 61
        self.assertTrue(limiter.try_acquire()[0])
        limiter.record(429)                       # second consecutive failure doubles the wait
        self.assertEqual(limiter.try_acquire()[1], 120)


class TestAbuseIpdbLimits(unittest.TestCase):

    def test_daily_quota_enforced(self):
        transport = RecordingTransport()
        previous = os.environ.get("ABUSEIPDB_DAILY_QUOTA")
        os.environ["ABUSEIPDB_DAILY_QUOTA"] = "2"
        try:
            c = ThreatIntelClient(vt_key="", abuse_key="ab", transport=transport, enabled=True)
        finally:
            if previous is None:
                os.environ.pop("ABUSEIPDB_DAILY_QUOTA", None)
            else:
                os.environ["ABUSEIPDB_DAILY_QUOTA"] = previous
        results = [c.lookup(f"8.8.8.{i}")["verdicts"][0].get("status", "OK") for i in range(3)]
        self.assertEqual(results, ["OK", "OK", "RATE_LIMITED"])
        self.assertEqual(len(transport.calls), 2)

    def test_never_reports_to_abuseipdb(self):
        import inspect
        from soar import enrichment
        self.assertNotIn("/report", inspect.getsource(enrichment))


if __name__ == "__main__":
    unittest.main()
