"""Hash-chained chain of custody for evidence (roadmap F50)."""

import os
import sys
import threading
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar.custody import CustodyLedger, sha256_of  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class TestCustody(unittest.TestCase):

    def test_chain_detects_edits_deletions_and_reordering(self):
        ledger = CustodyLedger(clock=lambda: "2026-11-01T00:00:00+00:00")
        for i in range(3):
            ledger.record("INC-1", "collected", f"a{i}", sha256_of({"i": i}), "tester")
        self.assertTrue(ledger.verify("INC-1")["intact"])
        ledger.logs["INC-1"][1]["actor"] = "someone-else"
        self.assertFalse(ledger.verify("INC-1")["intact"])
        ledger.logs["INC-1"][1]["actor"] = "tester"
        del ledger.logs["INC-1"][0]
        self.assertFalse(ledger.verify("INC-1")["intact"])

    def test_pipeline_records_collection_and_detects_changed_evidence(self):
        orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        incident = orchestrator.process_event(simulate_t1003_lsass_dump())
        log = orchestrator.custody.logs[incident["incident_id"]]
        self.assertEqual([(e["action"], e["artifact"]) for e in log],
                         [("collected", "evidence_package"), ("collected", "telemetry")])
        self.assertTrue(orchestrator.custody.verify_artifact(incident["incident_id"], "evidence_package",
                                                             incident["evidence_package"]))
        incident["evidence_package"]["tampered"] = True
        self.assertFalse(orchestrator.custody.verify_artifact(incident["incident_id"], "evidence_package",
                                                              incident["evidence_package"]))

    def test_export_is_recorded_and_endpoint_verifies(self):
        import urllib.request
        import server
        from tests.test_server_api import _request
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            inc_id = server.orchestrator.process_event(simulate_t1003_lsass_dump())["incident_id"]
            req = urllib.request.Request(f"{base}/api/incidents/{inc_id}/triage-package", headers={"X-API-Key": server.API_KEY})
            with urllib.request.urlopen(req, timeout=10) as resp:
                digest = resp.headers["X-Package-SHA256"]
            status, body = _request(base, f"/api/incidents/{inc_id}/custody")
            self.assertEqual(status, 200)
            self.assertTrue(body["verification"]["intact"])
            self.assertTrue(body["evidence_unchanged"])
            self.assertEqual((body["custody"][-1]["action"], body["custody"][-1]["sha256"]), ("exported", digest))
            self.assertEqual(body["custody"][-1]["actor"], "api-key")
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
