"""Triage package per incident (roadmap F49)."""

import io
import json
import os
import sys
import tempfile
import threading
import unittest
import zipfile

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402
from soar.triage_package import build_zip, verify_zip, write_automatic  # noqa: E402


class TestTriagePackage(unittest.TestCase):

    def setUp(self):
        self.orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        self.incident = self.orchestrator.process_event(simulate_t1003_lsass_dump())
        self.case = self.orchestrator.case_manager.cases[self.incident["case_id"]]

    def test_contents_manifest_and_integrity(self):
        data, digest, manifest = build_zip(self.incident, self.case)
        names = set(zipfile.ZipFile(io.BytesIO(data)).namelist())
        self.assertEqual(names, {"README.txt", "incident.json", "telemetry.json", "timeline.json", "evidence.json", "custody.json",
                                 "response.json", "case.json", "tasks.md", "manifest.json"})
        self.assertEqual(set(manifest), names - {"manifest.json"})
        self.assertEqual(verify_zip(data), [])
        self.assertEqual(len(digest), 64)

    def test_tampering_is_detected(self):
        data, _, _ = build_zip(self.incident, self.case)
        src = zipfile.ZipFile(io.BytesIO(data))
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as dst:
            for name in src.namelist():
                content = src.read(name)
                dst.writestr(name, b'{"tampered": true}' if name == "telemetry.json" else content)
        self.assertEqual(verify_zip(out.getvalue()), ["telemetry.json: hash mismatch"])

    def test_provider_data_stripped_and_accounts_masked(self):
        data, _, _ = build_zip(self.incident, self.case)
        incident = json.loads(zipfile.ZipFile(io.BytesIO(data)).read("incident.json"))
        self.assertIn("note", incident["threat_intel"]["external"])
        self.assertNotIn("finance_admin", json.dumps(incident))

    def test_automatic_write_is_off_by_default(self):
        self.assertEqual(self.incident["triage_package"], {"status": "DISABLED"})
        with tempfile.TemporaryDirectory() as folder:
            result = write_automatic(self.incident, self.case, directory=folder)
            self.assertEqual(result["status"], "WRITTEN")
            self.assertTrue(os.path.exists(os.path.join(folder, result["file"])))

    def test_download_endpoint(self):
        import urllib.request
        import server
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            inc = server.orchestrator.process_event(simulate_t1003_lsass_dump())
            req = urllib.request.Request(f"http://127.0.0.1:{httpd.server_address[1]}/api/incidents/{inc['incident_id']}/triage-package",
                                         headers={"X-API-Key": server.API_KEY})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
                self.assertEqual(resp.headers["Content-Type"], "application/zip")
                self.assertEqual(verify_zip(body), [])
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
