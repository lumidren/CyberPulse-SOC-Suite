"""HMAC authentication of the webhook receiver (POST /api/ingest)."""

import http.client
import json
import os
import sys
import threading
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from soar.ingest_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, IngestVerifier, sign_payload  # noqa: E402

SECRET = "test-ingest-secret"
EVENT = {
    "event_id": 4625, "computer_name": "CORP-RDP-GW01", "source_ip": "203.0.113.50",
    "user": "lab.admin", "details": {"FailedAttemptsCount": 2},
}


class TestIngestVerifier(unittest.TestCase):

    def test_valid_signature_accepted_once(self):
        now = [1_000_000.0]
        v = IngestVerifier(SECRET, clock=lambda: now[0])
        ts, sig = sign_payload(SECRET, b"{}", now[0])
        self.assertEqual(v.verify(ts, sig, b"{}"), (True, ""))
        self.assertEqual(v.verify(ts, sig, b"{}")[1], "Replayed request.")

    def test_tampered_body_and_wrong_secret_rejected(self):
        v = IngestVerifier(SECRET)
        ts, sig = sign_payload(SECRET, b'{"a":1}')
        self.assertFalse(v.verify(ts, sig, b'{"a":2}')[0])
        ts, sig = sign_payload("other-secret", b'{"a":1}')
        self.assertFalse(v.verify(ts, sig, b'{"a":1}')[0])

    def test_stale_timestamp_rejected(self):
        now = [1_000_000.0]
        v = IngestVerifier(SECRET, clock=lambda: now[0])
        ts, sig = sign_payload(SECRET, b"{}", now[0] - 301)
        self.assertIn("window", v.verify(ts, sig, b"{}")[1])

    def test_disabled_without_secret(self):
        self.assertFalse(IngestVerifier("").verify("1", "sha256=x", b"{}")[0])


class TestIngestEndpoint(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.original_verifier = server.ingest_verifier
        server.ingest_verifier = IngestVerifier(SECRET)
        cls.httpd = server.create_server(host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        server.ingest_verifier = cls.original_verifier

    def _post(self, path, body, headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        conn.request("POST", path, body=body, headers=dict({"Content-Type": "application/json"}, **headers))
        resp = conn.getresponse()
        data = json.loads(resp.read().decode("utf-8"))
        conn.close()
        return resp.status, data

    def test_signed_event_is_ingested_without_api_key(self):
        body = json.dumps(EVENT).encode("utf-8")
        ts, sig = sign_payload(SECRET, body)
        status, data = self._post("/api/ingest", body, {TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sig})
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "INGESTED_AND_PROCESSED")

    def test_unsigned_event_rejected_even_with_api_key(self):
        status, _ = self._post("/api/ingest", json.dumps(EVENT), {"X-API-Key": server.API_KEY})
        self.assertEqual(status, 401)

    def test_manual_ingest_uses_normal_auth(self):
        status, _ = self._post("/api/ingest/manual", json.dumps(EVENT), {"X-API-Key": server.API_KEY})
        self.assertEqual(status, 200)
        status, _ = self._post("/api/ingest/manual", json.dumps(EVENT), {})
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
