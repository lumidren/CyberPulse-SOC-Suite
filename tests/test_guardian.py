"""GUARDIAN anomaly alerts as an ingest source (roadmap F39)."""

import os
import sys
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.guardian import GuardianFormatError, guardian_to_event  # noqa: E402
from soar.ingest_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign_payload  # noqa: E402

ALERT = {"alert_id": "g-1", "detected_at": "2026-11-01T10:00:00Z", "anomaly_type": "rare_logon_time",
         "score": 0.93, "model": "iforest-v3", "mitre_technique": "T1078",
         "entity": {"type": "user", "id": "j.doe", "host": "WIN-WORKSTATION09", "ip": "10.0.2.15"}}


class TestGuardian(unittest.TestCase):

    def test_mapping(self):
        event = guardian_to_event(ALERT)
        self.assertEqual((event["event_source"], event["user"], event["computer_name"]),
                         ("guardian:anomaly", "j.doe", "WIN-WORKSTATION09"))
        self.assertEqual(event["details"]["AnomalyScore"], 0.93)

    def test_rejects_bad_alerts(self):
        for bad in ({**ALERT, "score": 3}, {**ALERT, "score": "high"}, {k: v for k, v in ALERT.items() if k != "alert_id"}, []):
            with self.assertRaises(GuardianFormatError):
                guardian_to_event(bad)

    def test_signed_endpoint_alerts_on_high_scores_only(self):
        import json
        import urllib.request
        os.environ["INGEST_HMAC_SECRET"] = "guardian-test-secret"
        import server
        from soar.ingest_auth import IngestVerifier
        original_verifier = server.ingest_verifier
        server.ingest_verifier = IngestVerifier("guardian-test-secret")
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"

        def post(payload, signed=True):
            raw = json.dumps(payload).encode()
            ts, sig = sign_payload("guardian-test-secret", raw)
            headers = {"Content-Type": "application/json"}
            if signed:
                headers.update({TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: sig})
            req = urllib.request.Request(base + "/api/ingest/guardian", data=raw, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        try:
            self.assertEqual(post(ALERT, signed=False)[0], 401)
            status, body = post(ALERT)
            self.assertEqual((status, body["alerted"]), (200, True))
            status, body = post({**ALERT, "alert_id": "g-2", "score": 0.3})
            self.assertEqual((status, body["alerted"]), (200, False))
            self.assertEqual(post({**ALERT, "score": 9})[0], 400)
        finally:
            httpd.shutdown()
            httpd.server_close()
            server.ingest_verifier = original_verifier
            os.environ.pop("INGEST_HMAC_SECRET", None)


if __name__ == "__main__":
    unittest.main()
