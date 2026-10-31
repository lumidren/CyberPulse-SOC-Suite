"""
Dashboard authentication tests: login page, session cookie, page gating,
logout, and CSRF protection for cookie-authenticated state changes.
"""

import http.client
import json
import os
import sys
import threading
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import API_KEY, create_server  # noqa: E402


class DashboardClient:
    def __init__(self, port):
        self.port = port
        self.cookie = None
        self.csrf = None

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hdrs = {"Content-Type": "application/json"}
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        hdrs.update(headers or {})
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8")
        set_cookie = resp.getheader("Set-Cookie")
        conn.close()
        try:
            data = json.loads(raw)
        except ValueError:
            data = raw
        return resp.status, data, resp, set_cookie

    def login(self, key=API_KEY):
        status, data, _, set_cookie = self.request("POST", "/api/session", {"api_key": key})
        if status == 200:
            self.cookie = set_cookie.split(";", 1)[0]
            self.csrf = data["csrf_token"]
        return status, data, set_cookie


class TestDashboardAuth(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = create_server(host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_console_redirects_to_login_without_session(self):
        client = DashboardClient(self.port)
        for path in ["/", "/index.html", "/app.js"]:
            status, _, resp, _ = client.request("GET", path)
            self.assertEqual(status, 302, path)
            self.assertEqual(resp.getheader("Location"), "/login.html")
        status, body, _, _ = client.request("GET", "/login.html")
        self.assertEqual(status, 200)
        self.assertIn("Sign in", body)

    def test_api_key_is_not_shipped_to_the_browser(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "app.js"),
                  encoding="utf-8") as fh:
            js = fh.read()
        self.assertNotIn("cyberpulse-dev-secret-key", js)
        self.assertNotIn("X-API-Key", js)

    def test_login_sets_hardened_cookie_and_unlocks_console(self):
        client = DashboardClient(self.port)
        status, _, _ = client.login("wrong-key")
        self.assertEqual(status, 401)

        status, data, set_cookie = client.login()
        self.assertEqual(status, 200)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        self.assertTrue(data["csrf_token"])

        self.assertEqual(client.request("GET", "/")[0], 200)
        self.assertEqual(client.request("GET", "/api/detections")[0], 200)
        _, session, _, _ = client.request("GET", "/api/session")
        self.assertTrue(session["authenticated"])

    def test_logout_ends_session(self):
        client = DashboardClient(self.port)
        client.login()
        self.assertEqual(client.request("POST", "/api/session/logout", {})[0], 403)  # forged logout refused
        client.request("POST", "/api/session/logout", {}, headers={"X-CSRF-Token": client.csrf})
        self.assertEqual(client.request("GET", "/api/detections")[0], 401)
        self.assertEqual(client.request("GET", "/")[0], 302)


class TestCsrfProtection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = create_server(host="127.0.0.1", port=0)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_cookie_post_without_csrf_token_is_rejected(self):
        client = DashboardClient(self.port)
        client.login()
        status, body, _, _ = client.request("POST", "/api/simulate", {"type": "t1003"})
        self.assertEqual(status, 403)
        self.assertIn("CSRF", body["error"])

    def test_cookie_post_with_csrf_token_is_accepted(self):
        client = DashboardClient(self.port)
        client.login()
        status, _, _, _ = client.request("POST", "/api/simulate", {"type": "t1003"},
                                         headers={"X-CSRF-Token": client.csrf})
        self.assertEqual(status, 200)

    def test_cross_origin_cookie_post_is_rejected(self):
        client = DashboardClient(self.port)
        client.login()
        status, _, _, _ = client.request("POST", "/api/simulate", {"type": "t1003"},
                                         headers={"X-CSRF-Token": client.csrf, "Origin": "https://evil.example"})
        self.assertEqual(status, 403)

    def test_api_key_clients_need_no_csrf_token(self):
        client = DashboardClient(self.port)
        status, _, _, _ = client.request("POST", "/api/simulate", {"type": "t1003"}, headers={"X-API-Key": API_KEY})
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
