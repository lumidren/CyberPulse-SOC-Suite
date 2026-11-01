"""MISP IoC sharing (roadmap F37)."""

import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.misp import MispClient, SharingDisabled, build_event  # noqa: E402

SHA = "a" * 64


def incident(ip, simulated=False, sha=None, host="WIN-DC01", user="CORP\\j.doe"):
    details = {"CommandLine": "secret.exe --token abc"}
    if sha:
        details["FileHash_SHA256"] = sha
    return {"simulated": simulated, "rule": {"rule_id": "SOC-RULE-001", "mitre_id": "T1003.001", "severity": "CRITICAL"},
            "telemetry": {"source_ip": ip, "computer_name": host, "user": user, "details": details},
            "observables": [{"type": "ip-src", "value": ip}, {"type": "hostname", "value": host}]}


class TestMisp(unittest.TestCase):

    def test_only_public_ips_and_hashes_are_shared(self):
        event, skipped = build_event([incident("8.8.4.4", sha=SHA), incident("10.0.2.15")], "test")
        values = [a["value"] for a in event["Event"]["Attribute"]]
        self.assertEqual(sorted(values), sorted(["8.8.4.4", SHA]))
        text = json.dumps(event)
        for secret in ("10.0.2.15", "WIN-DC01", "j.doe", "secret.exe"):
            self.assertNotIn(secret, text)
        self.assertEqual(event["Event"]["distribution"], 0, "organisation only")
        self.assertIn({"name": "tlp:amber"}, event["Event"]["Tag"])
        self.assertEqual(skipped, 0)

    def test_simulated_incidents_are_not_shared_by_default(self):
        event, skipped = build_event([incident("8.8.4.4", simulated=True)], "lab")
        self.assertEqual((event["Event"]["Attribute"], skipped), ([], 1))
        event, _ = build_event([incident("8.8.4.4", simulated=True)], "lab", include_simulated=True)
        self.assertIn({"name": "simulated"}, event["Event"]["Tag"])

    def test_client_needs_opt_in_https_and_filters_pulled_iocs(self):
        with self.assertRaises(SharingDisabled):
            MispClient(url="https://misp.lab", api_key="k", enabled=False).fetch_iocs()
        with self.assertRaises(SharingDisabled):
            MispClient(url="http://misp.lab", api_key="k", enabled=True).fetch_iocs()
        calls = []

        def fake(url, key, payload, timeout=15):
            calls.append((url, payload))
            return {"response": {"Attribute": [{"value": "8.8.8.8"}, {"value": "10.1.1.1"}, {"value": SHA}]}}
        iocs = MispClient(url="https://misp.lab", api_key="k", enabled=True, request=fake).fetch_iocs()
        self.assertEqual(iocs, {"ip": {"8.8.8.8"}, "hash": {SHA}})
        self.assertTrue(calls[0][0].endswith("/attributes/restSearch"))

    def test_push_skips_empty_events(self):
        client = MispClient(url="https://misp.lab", api_key="k", enabled=True, request=lambda *a, **k: {"Event": {"id": "7"}})
        empty, _ = build_event([incident("10.0.0.1")], "nothing")
        self.assertEqual(client.push_event(empty)["status"], "NOTHING_TO_SHARE")
        full, _ = build_event([incident("8.8.4.4")], "one")
        self.assertEqual(client.push_event(full), {"status": "SENT", "event_id": "7"})


class TestMispApi(unittest.TestCase):

    def test_preview_and_push_disabled_by_default(self):
        import threading
        os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
        import server
        from simulator.attack_simulator import simulate_t1003_lsass_dump
        from tests.test_server_api import _request
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            case_id = server.orchestrator.process_event(simulate_t1003_lsass_dump())["case_id"]
            status, body = _request(base, f"/api/cases/{case_id}/misp")
            self.assertEqual(status, 200)
            # Other tests may already have filed incidents for the same host into this case
            self.assertGreaterEqual(body["skipped_simulated_incidents"], 1)
            self.assertEqual(body["event"]["Event"]["Attribute"], [])
            status, body = _request(base, f"/api/cases/{case_id}/misp/push", method="POST", body={})
            self.assertEqual(status, 503)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
