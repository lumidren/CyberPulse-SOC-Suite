"""
REST API Integration & Hardening Test Suite for the CyberPulse SOC Lab
Boots the real threaded HTTP server on an ephemeral port and verifies
authentication, rate limiting, routing (including incident subresources),
pagination, payload limits, and the SSRF webhook guard.
"""

import json
import os
import sys
import unittest
import urllib.error
import urllib.request

# Ensure project root in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server
from server import API_KEY, SlidingWindowRateLimiter, create_server
from soar.notifications import validate_webhook_url


def _request(base_url, path, method="GET", body=None, api_key=API_KEY, headers=None):
    """Issue an HTTP request to the test server; returns (status, parsed_body)."""
    url = base_url + path
    req_headers = {"Content-Type": "application/json"}
    if api_key is not None:
        req_headers["X-API-Key"] = api_key
    if headers:
        req_headers.update(headers)

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8")
        status = e.code
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = raw
    return status, parsed


class TestRestApiIntegration(unittest.TestCase):
    """Live integration tests against the threaded server on an ephemeral port."""

    @classmethod
    def setUpClass(cls):
        import threading
        cls.httpd = create_server(host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_healthz_is_unauthenticated(self):
        """Liveness probe must respond without an API key for LB healthchecks"""
        status, body = _request(self.base_url, "/healthz", api_key=None)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertIn("version", body)

    def test_api_requires_authentication(self):
        """/api/* endpoints reject missing and invalid API keys with 401"""
        status, body = _request(self.base_url, "/api/detections", api_key=None)
        self.assertEqual(status, 401)
        status, _ = _request(self.base_url, "/api/detections", api_key="wrong-key")
        self.assertEqual(status, 401)

    def test_api_accepts_valid_key_and_bearer(self):
        """Valid X-API-Key and Authorization: Bearer are both accepted"""
        status, body = _request(self.base_url, "/api/detections")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["total_rules"], 8)

        status, _ = _request(
            self.base_url, "/api/version",
            api_key=None, headers={"Authorization": f"Bearer {API_KEY}"}
        )
        self.assertEqual(status, 200)

    def test_incident_subresource_routing(self):
        """GET /api/incidents/<id>/<sub> routes resolve (regression for shadowed routes)"""
        status, body = _request(self.base_url, "/api/simulate", method="POST", body={"type": "t1003"})
        self.assertEqual(status, 200)
        inc_id = body["incident"]["incident_id"]

        for sub, key in [
            ("attack-graph", "attack_graph"),
            ("evidence", "evidence_package"),
            ("ai-analysis", "ai_analysis"),
            ("identity", "identity_blast_radius"),
        ]:
            status, sub_body = _request(self.base_url, f"/api/incidents/{inc_id}/{sub}")
            self.assertEqual(status, 200, f"subresource {sub} failed")
            self.assertIn(key, sub_body)

        # HTML report subresource
        status, report = _request(self.base_url, f"/api/incidents/{inc_id}/report")
        self.assertEqual(status, 200)
        self.assertIn("<!DOCTYPE html>", report)

        # Unknown incident still yields 404
        status, _ = _request(self.base_url, "/api/incidents/INC-DOES-NOT-EXIST/evidence")
        self.assertEqual(status, 404)

    def test_incident_list_pagination(self):
        """Incident list honors limit/offset and reports totals"""
        for _ in range(3):
            _request(self.base_url, "/api/simulate", method="POST", body={"type": "t1110"})

        status, body = _request(self.base_url, "/api/incidents?limit=2&offset=0")
        self.assertEqual(status, 200)
        self.assertLessEqual(body["count"], 2)
        self.assertEqual(body["limit"], 2)
        self.assertEqual(body["offset"], 0)
        self.assertGreaterEqual(body["total"], 3)

    def test_malformed_json_body_rejected(self):
        """POST with invalid JSON returns 400 instead of silently proceeding"""
        req = urllib.request.Request(
            self.base_url + "/api/simulate",
            data=b"{not valid json",
            headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=15)
        self.assertEqual(ctx.exception.code, 400)

    def test_oversized_body_rejected(self):
        """POST bodies above MAX_BODY_BYTES are rejected with 413"""
        original = server.MAX_BODY_BYTES
        server.MAX_BODY_BYTES = 64
        try:
            status, body = _request(
                self.base_url, "/api/simulate", method="POST",
                body={"type": "t1003", "padding": "A" * 512},
            )
            self.assertEqual(status, 413)
        finally:
            server.MAX_BODY_BYTES = original

    def test_unknown_api_endpoint_is_404(self):
        """Unknown /api/* GET paths return a JSON 404, not the static fallback"""
        status, body = _request(self.base_url, "/api/nonexistent")
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    def test_security_headers_present(self):
        """Baseline security headers are attached to API responses"""
        req = urllib.request.Request(
            self.base_url + "/healthz", headers={"X-API-Key": API_KEY}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")

    def test_rollback_without_valid_incident(self):
        """Rollback on a missing incident returns 404"""
        status, _ = _request(
            self.base_url, "/api/incidents/INC-MISSING/rollback",
            method="POST", body={"actor": "tester"},
        )
        self.assertEqual(status, 404)


class TestRateLimiter(unittest.TestCase):

    def test_sliding_window_saturation(self):
        """Limiter allows up to max_events then blocks within the window"""
        limiter = SlidingWindowRateLimiter(max_events=3, window_sec=60)
        self.assertTrue(limiter.allow("10.0.0.1"))
        self.assertTrue(limiter.allow("10.0.0.1"))
        self.assertTrue(limiter.allow("10.0.0.1"))
        self.assertFalse(limiter.allow("10.0.0.1"))
        # Independent keys are unaffected
        self.assertTrue(limiter.allow("10.0.0.2"))

    def test_hit_without_recording(self):
        """Saturation check does not consume event slots"""
        limiter = SlidingWindowRateLimiter(max_events=1, window_sec=60)
        self.assertFalse(limiter.hit_without_recording("ip"))
        limiter.allow("ip")
        self.assertTrue(limiter.hit_without_recording("ip"))


class TestWebhookUrlValidation(unittest.TestCase):

    def test_valid_public_https_webhooks(self):
        ok, _ = validate_webhook_url("https://discord.com/api/webhooks/123/token")
        self.assertTrue(ok)
        ok, _ = validate_webhook_url("https://hooks.slack.com/services/T000/B000/XXXX")
        self.assertTrue(ok)

    def test_rejects_non_http_schemes(self):
        for url in ["file:///etc/passwd", "ftp://host/x", "gopher://host", ""]:
            ok, reason = validate_webhook_url(url)
            self.assertFalse(ok, f"should reject {url!r}: {reason}")

    def test_rejects_internal_targets_by_default(self):
        for url in [
            "http://127.0.0.1:8080/hook",
            "http://localhost/hook",
            "http://10.0.1.10:55000/api",
            "http://192.168.1.1/admin",
            "http://169.254.169.254/latest/meta-data/",
        ]:
            ok, reason = validate_webhook_url(url)
            self.assertFalse(ok, f"should reject {url!r}: {reason}")


if __name__ == "__main__":
    unittest.main()
