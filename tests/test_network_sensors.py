"""Zeek / Suricata network sensors (roadmap F72)."""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.ingest_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, IngestVerifier, sign_payload  # noqa: E402
from soar.network_sensors import MAX_BATCH, SensorFormatError, convert_batch, suricata_to_event, zeek_to_event  # noqa: E402

DNS = {"ts": 1793500000.5, "uid": "C1", "id.orig_h": "10.0.2.15", "id.resp_h": "10.0.0.53", "id.resp_p": 53,
       "query": "example.com", "qtype_name": "A", "rcode_name": "NOERROR", "payload_should_not_pass": "x"}
EVE = {"timestamp": "2026-11-01T10:00:00Z", "event_type": "alert", "src_ip": "10.0.2.15", "dest_ip": "203.0.113.50",
       "dest_port": 443, "proto": "TCP", "alert": {"signature_id": 1, "signature": "ET TEST", "category": "x", "severity": 1}}


class TestAdapters(unittest.TestCase):

    def test_zeek_and_suricata_mapping(self):
        event = zeek_to_event("dns", DNS)
        self.assertEqual((event["event_source"], event["source_ip"], event["details"]["query"]),
                         ("zeek:dns", "10.0.2.15", "example.com"))
        self.assertNotIn("payload_should_not_pass", event["details"])
        self.assertTrue(event["timestamp"].startswith("2026-"))
        alert = suricata_to_event(EVE)
        self.assertEqual((alert["event_source"], alert["details"]["Severity"]), ("suricata:alert", 1))

    def test_batch_validation(self):
        for bad in ({"sensor": "zeek", "log": "smb", "records": [DNS]}, {"sensor": "zeek", "log": "dns", "records": []},
                    {"sensor": "snort", "records": [DNS]}, {"sensor": "suricata", "records": [{"event_type": "flow"}]},
                    {"sensor": "zeek", "log": "dns", "records": [DNS] * (MAX_BATCH + 1)}):
            with self.assertRaises(SensorFormatError):
                convert_batch(bad)


class TestNetworkIngest(unittest.TestCase):

    def test_signed_batch_creates_incidents(self):
        import server
        saved = server.ingest_verifier
        server.ingest_verifier = IngestVerifier("net-secret")
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"

        def post(payload, signed=True):
            raw = json.dumps(payload).encode()
            ts, sig = sign_payload("net-secret", raw)
            headers = {"Content-Type": "application/json"}
            if signed:
                headers.update({TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sig})
            req = urllib.request.Request(base + "/api/ingest/network", data=raw, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        try:
            self.assertEqual(post({"sensor": "suricata", "records": [EVE]}, signed=False)[0], 401)
            status, body = post({"sensor": "suricata", "records": [EVE, dict(EVE, alert=dict(EVE["alert"], severity=3))]})
            self.assertEqual((status, body["accepted"], len(body["incidents"])), (200, 2, 1))
            status, body = post({"sensor": "zeek", "log": "dns", "records": [DNS]})
            self.assertEqual((status, body["accepted"], body["incidents"]), (200, 1, []))
        finally:
            httpd.shutdown()
            httpd.server_close()
            server.ingest_verifier = saved


class TestDnsTunnelCorrelation(unittest.TestCase):

    def test_fifty_unique_subdomains_fire_once(self):
        from soar.sigma_correlation import CorrelationEngine
        engine = CorrelationEngine()
        fired = []
        for i in range(60):
            event = zeek_to_event("dns", dict(DNS, ts=1793500000 + i, query=f"chunk{i:04d}x.exfil.example.net"))
            fired += [r["rule_id"] for r in engine.observe(event)]
        self.assertEqual(fired, ["SOC-RULE-053"])

    def test_repeated_same_name_does_not_fire(self):
        from soar.sigma_correlation import CorrelationEngine
        engine = CorrelationEngine()
        fired = [r for i in range(80) for r in engine.observe(zeek_to_event("dns", dict(DNS, ts=1793500000 + i)))]
        self.assertEqual(fired, [])

    def test_parent_domain_is_added_for_correlation(self):
        self.assertEqual(zeek_to_event("dns", dict(DNS, query="a.b.exfil.example.net."))["details"]["query_parent"],
                         "example.net")


class TestTlsFingerprints(unittest.TestCase):

    def test_blocklist_parsing_and_placeholders_are_marked(self):
        from scripts.update_tls_blocklist import RULE, read_ja3, read_ja4
        self.assertEqual(read_ja3("# header\n" + "A" * 32 + ",x\nshort,y\n"), ["a" * 32])
        self.assertEqual(read_ja4("t13d1516h2_8daaf6152771_02713d6af862\nnot-ja4\n"), ["t13d1516h2_8daaf6152771_02713d6af862"])
        with open(RULE, encoding="utf-8") as fh:
            self.assertIn("SYNTHETIC LAB PLACEHOLDERS", fh.read())

    def test_ja3_is_a_hunting_pivot(self):
        from soar.event_store import field_value
        event = zeek_to_event("ssl", {"id.orig_h": "10.0.2.15", "ja3": "b" * 32, "server_name": "x.example"})
        self.assertEqual(field_value(event, "ja3"), "b" * 32)


if __name__ == "__main__":
    unittest.main()
