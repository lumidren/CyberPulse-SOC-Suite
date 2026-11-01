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


if __name__ == "__main__":
    unittest.main()
