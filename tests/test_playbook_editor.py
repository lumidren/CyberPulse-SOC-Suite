"""Playbook editor API: drafts are validated, never written (roadmap F33)."""

import os
import re
import sys
import threading
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from server import create_server  # noqa: E402
from tests.test_server_api import _request  # noqa: E402


class TestPlaybookEditorApi(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = create_server(host="127.0.0.1", port=0)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_list_playbooks_and_actions(self):
        status, body = _request(self.base, "/api/playbooks")
        self.assertEqual(status, 200)
        self.assertIn("credential-theft", [p["name"] for p in body["playbooks"]])
        self.assertIn("ISOLATE_HOST_AND_KILL_PROCESS", body["allowed_actions"])

    def test_validate_reports_routes_and_rejects_unsafe_drafts(self):
        before = sorted(os.listdir(os.path.join(ROOT, "playbooks")))
        ok = 'name: "t"\nversion: "1.0.0"\ndescription: "d"\nmatch:\n  techniques: ["T1218"]\nresponse:\n  notify: true\n'
        status, body = _request(self.base, "/api/playbooks/validate", method="POST", body={"yaml": ok})
        self.assertEqual(status, 200)
        self.assertTrue(body["valid"], body)
        self.assertIn("SOC-RULE-015", body["routes"])
        overlap = ok.replace("T1218", "T1486")
        status, body = _request(self.base, "/api/playbooks/validate", method="POST", body={"yaml": overlap})
        self.assertTrue(body["warnings"], "overlap with ransomware.yml must be reported")
        bad = 'name: "t"\nversion: "1"\ndescription: "d"\nresponse:\n  execute_automatically: true\n'
        status, body = _request(self.base, "/api/playbooks/validate", method="POST", body={"yaml": bad})
        self.assertFalse(body["valid"])
        self.assertEqual(sorted(os.listdir(os.path.join(ROOT, "playbooks"))), before, "validation must not write files")

    def test_editor_never_injects_html(self):
        with open(os.path.join(ROOT, "web", "playbooks.js"), encoding="utf-8") as fh:
            script = fh.read()
        self.assertIsNone(re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", script))


if __name__ == "__main__":
    unittest.main()
