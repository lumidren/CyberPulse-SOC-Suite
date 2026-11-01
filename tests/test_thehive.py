"""TheHive / Cortex integration, off by default (roadmap F36)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402
from soar.thehive import PAP_RED, CortexClient, TheHiveClient, alert_payload, lab_url  # noqa: E402


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, url, key, payload, timeout=10):
        self.calls.append((url, payload))
        return {"_id": "~123"}


class TestTheHive(unittest.TestCase):

    def setUp(self):
        self.incident = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED").process_event(simulate_t1003_lsass_dump())

    def test_disabled_by_default_and_says_so(self):
        self.assertEqual(self.incident["thehive_sync"]["status"], "DISABLED")
        self.assertIn("Local case record", self.incident["timeline"][-1]["title"])

    def test_sends_alert_with_internal_values_held_back_from_analyzers(self):
        rec = Recorder()
        client = TheHiveClient(url="http://10.0.1.20:9000", api_key="k", enabled=True, post=rec)
        result = client.send(self.incident, "CASE-1")
        self.assertEqual(result, {"status": "SENT", "thehive_alert_id": "~123"})
        url, payload = rec.calls[0]
        self.assertTrue(url.endswith("/api/v1/alert"))
        self.assertEqual(payload["sourceRef"], "CASE-1")
        self.assertIn("simulated", payload["tags"])
        for obs in payload["observables"]:
            if obs["data"] in (self.incident["telemetry"]["computer_name"], "WIN-WORKSTATION09") or "\\" in obs["data"]:
                self.assertEqual(obs["pap"], PAP_RED)
                self.assertIn("internal", obs["tags"])

    def test_refuses_non_lab_url_and_survives_errors(self):
        rec = Recorder()
        self.assertEqual(TheHiveClient(url="https://thehive.example.com", api_key="k", enabled=True,
                                       post=rec).send(self.incident, "C")["status"], "REFUSED")
        self.assertEqual(rec.calls, [])

        def boom(*a, **k):
            raise ConnectionError("down")
        self.assertEqual(TheHiveClient(url="http://10.0.1.20:9000", api_key="k", enabled=True,
                                       post=boom).send(self.incident, "C")["status"], "ERROR")

    def test_payload_shape(self):
        payload = alert_payload(self.incident, "CASE-9")
        self.assertEqual(payload["severity"], 4)
        self.assertIn("Playbook tasks:", payload["description"])
        self.assertTrue(lab_url("http://thehive.lab:9000"))
        self.assertFalse(lab_url("http://8.8.8.8:9000"))


class TestCortex(unittest.TestCase):

    def test_only_public_ips_and_hashes(self):
        rec = Recorder()
        cortex = CortexClient(url="http://10.0.1.21:9001", api_key="k", post=rec)
        self.assertEqual(cortex.run_analyzer("VirusTotal_GetReport_3_1", "10.0.2.15")["status"], "REFUSED")
        self.assertEqual(cortex.run_analyzer("VirusTotal_GetReport_3_1", "WIN-DC01")["status"], "REFUSED")
        self.assertEqual(rec.calls, [])
        self.assertEqual(cortex.run_analyzer("AbuseIPDB_1_0", "8.8.8.8")["status"], "SUBMITTED")
        self.assertEqual(rec.calls[0][1]["dataType"], "ip")


if __name__ == "__main__":
    unittest.main()
