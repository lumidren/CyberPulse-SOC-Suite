"""Role-based access: lead, analyst, auditor (roadmap F61)."""

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

from soar.roles import allowed, parse_role_keys, role_for_key  # noqa: E402

ANALYST_KEY = "analyst-key-0123456789abcdef"
AUDITOR_KEY = "auditor-key-0123456789abcdef"


class TestRolePolicy(unittest.TestCase):

    def test_parse_and_match(self):
        keys, problems = parse_role_keys("lead-key-0123456789abcdefgh", {
            "CYBERPULSE_ROLE_KEYS": f"analyst:{ANALYST_KEY},auditor:{AUDITOR_KEY},auditor:short,boss:{'x' * 30}"})
        self.assertEqual([r for r, _ in keys], ["lead", "analyst", "auditor"])
        self.assertEqual(len(problems), 2)
        self.assertEqual(role_for_key(AUDITOR_KEY, keys), "auditor")
        self.assertIsNone(role_for_key("nope", keys))

    def test_permissions(self):
        self.assertTrue(allowed("auditor", "GET", "/api/incidents"))
        self.assertFalse(allowed("auditor", "POST", "/api/cases/C-1"))
        self.assertTrue(allowed("auditor", "POST", "/api/session/logout"))
        self.assertTrue(allowed("analyst", "POST", "/api/cases/C-1"))
        self.assertFalse(allowed("analyst", "POST", "/api/approvals/ACT-1/approve"))
        self.assertFalse(allowed("analyst", "POST", "/api/policy/config"))
        self.assertTrue(allowed("analyst", "POST", "/api/safety/kill-switch", {"engaged": True}))
        self.assertFalse(allowed("analyst", "POST", "/api/safety/kill-switch", {"engaged": False}))
        self.assertTrue(allowed("lead", "POST", "/api/approvals/ACT-1/approve"))
        self.assertFalse(allowed(None, "GET", "/api/incidents"))


class TestRoleEnforcement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import server
        cls.server = server
        cls.saved = server.ROLE_KEYS
        server.ROLE_KEYS = [("lead", server.API_KEY), ("analyst", ANALYST_KEY), ("auditor", AUDITOR_KEY)]
        cls.httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.server.ROLE_KEYS = cls.saved

    def call(self, path, key, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method="POST" if body is not None else "GET",
                                     headers={"X-API-Key": key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_server_enforces_roles(self):
        self.assertEqual(self.call("/api/incidents", AUDITOR_KEY), 200)
        self.assertEqual(self.call("/api/hunts", AUDITOR_KEY, {"name": "x1", "query": "abc", "analyst": "a"}), 403)
        self.assertEqual(self.call("/api/policy/config", ANALYST_KEY, {"mode": "DRY_RUN"}), 403)
        self.assertEqual(self.call("/api/safety/kill-switch", ANALYST_KEY, {"engaged": False, "actor": "a"}), 403)
        self.assertEqual(self.call("/api/hunts", ANALYST_KEY, {"name": "role test hunt", "query": "abc", "analyst": "a"}), 200)
        self.assertEqual(self.call("/api/policy/config", self.server.API_KEY, {"mode": "APPROVAL_REQUIRED"}), 200)

    def test_login_session_carries_role(self):
        req = urllib.request.Request(self.base + "/api/session", data=json.dumps({"api_key": AUDITOR_KEY}).encode(),
                                     method="POST", headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(json.loads(resp.read())["role"], "auditor")


if __name__ == "__main__":
    unittest.main()
