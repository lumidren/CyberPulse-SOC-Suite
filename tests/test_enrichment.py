"""External threat-intel enrichment safeguards (roadmap E49-E64). No real network calls."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.enrichment import ThreatIntelClient, is_shareable_ip  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
