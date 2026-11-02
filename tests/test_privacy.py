"""Identity masking in displayed data (roadmap E45)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")  # tests run in a declared lab
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.privacy import mask_identities, mask_username  # noqa: E402


class TestMasking(unittest.TestCase):

    def test_mask_username(self):
        self.assertEqual(mask_username(r"CORP\j.doe"), r"CORP\j***e")
        self.assertEqual(mask_username("finance_admin"), "f******n")
        self.assertEqual(mask_username("ab"), "a*")
        self.assertEqual(mask_username("Unknown"), "Unknown")

    def test_nested_payload_masked(self):
        payload = {"incident": {"telemetry": {"user": r"CORP\j.doe", "details": {"TargetUserName": "lab.admin"}},
                                "observables": [{"type": "user-account", "value": r"CORP\j.doe"},
                                                {"type": "ip-src", "value": "10.0.0.5"}]}}
        masked = mask_identities(payload)
        self.assertEqual(masked["incident"]["telemetry"]["user"], r"CORP\j***e")
        self.assertEqual(masked["incident"]["telemetry"]["details"]["TargetUserName"], "l******n")  # at most six asterisks
        self.assertEqual(masked["incident"]["observables"][0]["value"], r"CORP\j***e")
        self.assertEqual(masked["incident"]["observables"][1]["value"], "10.0.0.5")
        self.assertEqual(payload["incident"]["telemetry"]["user"], r"CORP\j.doe")  # original untouched

    def test_account_names_masked_outside_account_fields(self):
        payload = {"telemetry": {"user": r"CORP\finance_admin",
                                 "details": {"Image": r"C:\Users\finance_admin\AppData\Local\Temp\locker.exe"}},
                   "recommended_containment": ["Disable account finance_admin immediately."],
                   "graph": {"nodes": [{"id": r"CORP\finance_admin", "label": r"User: CORP\finance_admin"}],
                             "edges": [{"source": r"CORP\finance_admin", "target": "host:WS-01"}]}}
        masked = mask_identities(payload)
        self.assertNotIn("finance_admin", repr(masked))
        self.assertEqual(masked["telemetry"]["details"]["Image"], r"C:\Users\f******n\AppData\Local\Temp\locker.exe")
        self.assertEqual(masked["recommended_containment"], ["Disable account f******n immediately."])
        node, edge = masked["graph"]["nodes"][0], masked["graph"]["edges"][0]
        self.assertEqual(node["id"], edge["source"])  # edges still reach their node
        self.assertEqual(node["label"], r"User: CORP\f******n")

    def test_profile_paths_masked_without_a_known_account(self):
        masked = mask_identities({"details": {"TargetFilename": r"C:\Users\m.worker\Documents\a.docx",
                                              "Shared": r"C:\Users\Public\Desktop\note.txt"}})
        self.assertEqual(masked["details"]["TargetFilename"], r"C:\Users\m******r\Documents\a.docx")
        self.assertEqual(masked["details"]["Shared"], r"C:\Users\Public\Desktop\note.txt")

    def test_names_inside_longer_words_are_left_alone(self):
        payload = {"user": r"CORP\Administrator", "RoleArn": "arn:aws:iam::000000000000:role/AdministratorAccess"}
        self.assertEqual(mask_identities(payload)["RoleArn"], payload["RoleArn"])

    def test_api_masks_by_default(self):
        import threading
        import urllib.request
        import json
        import server
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{httpd.server_address[1]}/api/simulate"
            req = urllib.request.Request(url, data=b'{"type": "t1003"}', method="POST",
                                         headers={"Content-Type": "application/json", "X-API-Key": server.API_KEY})
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = json.loads(resp.read())
            self.assertEqual(body["incident"]["telemetry"]["user"], r"CORP\A******r")
            # server-side record keeps the real value for detection and containment
            stored = server.orchestrator.dfir_engine.incidents[body["incident"]["incident_id"]]
            self.assertEqual(stored["telemetry"]["user"], r"CORP\Administrator")
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestNoRealEmployeeData(unittest.TestCase):

    def test_identity_endpoints_are_labelled_synthetic(self):
        import json
        import threading
        import urllib.request
        import server
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            for path in ["/api/identity/graph", "/api/identity/delegation-risks", "/api/identity/bloodhound-export"]:
                req = urllib.request.Request(base + path, headers={"X-API-Key": server.API_KEY})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    self.assertIn("SYNTHETIC", json.loads(resp.read())["data_source"], path)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_directory_contains_only_lab_domains(self):
        from soar.identity_graph import LAB_AD_TOPOLOGY
        for name, user in LAB_AD_TOPOLOGY.items():
            for spn in user.get("spn", []):
                self.assertRegex(spn.lower(), r"\.(cyberpulse|corp)\.local", f"{name}: {spn}")


class TestDataMinimisation(unittest.TestCase):

    def test_unneeded_fields_dropped_at_ingest(self):
        from soar.syslog_receiver import WebhookIngestionHandler
        res = WebhookIngestionHandler().handle_ingest({
            "event_id": 1, "computer_name": "WIN-WORKSTATION09", "source_ip": "10.0.0.45",
            "employee_email": "someone@example.com",           # unknown top-level field
            "details": {"CommandLine": "whoami", "HomeAddress": "1 Main St", "SalaryBand": "B"}})
        event = res["normalized_event"]
        self.assertNotIn("employee_email", event)
        self.assertEqual(set(event["details"]), {"CommandLine"})
        self.assertEqual(res["dropped_fields"], ["HomeAddress", "SalaryBand"])
        self.assertNotIn("1 Main St", str(res))

    def test_simulator_fields_are_all_allowlisted(self):
        from simulator.attack_simulator import SCRIPTED_GENERATORS
        from soar.input_validation import DETAIL_FIELD_ALLOWLIST
        for _name, gen in SCRIPTED_GENERATORS:
            self.assertEqual(set(gen()["details"]) - DETAIL_FIELD_ALLOWLIST, set(), _name)


class TestRetention(unittest.TestCase):

    def test_old_incidents_and_actions_are_purged(self):
        from datetime import datetime, timedelta, timezone
        from simulator.attack_simulator import simulate_t1110_brute_force
        from soar.soar_engine import SOAROrchestrator
        orch = SOAROrchestrator()
        old = orch.process_event(simulate_t1110_brute_force())
        new = orch.process_event(simulate_t1110_brute_force())
        old["created_at"] = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()

        result = orch.apply_retention(days=30)
        self.assertEqual(result["incidents_purged"], 1)
        self.assertEqual(result["actions_purged"], 1)
        self.assertNotIn(old["incident_id"], orch.dfir_engine.incidents)
        self.assertIn(new["incident_id"], orch.dfir_engine.incidents)
        self.assertNotIn(old["containment_action"]["action_id"], orch.containment_engine.action_registry)

    def test_syslog_buffer_is_bounded_and_purged(self):
        import time
        from soar.syslog_receiver import SyslogReceiver
        rx = SyslogReceiver()
        rx.events.extend([{"received_at": time.time() - 90 * 86400}, {"received_at": time.time()}])
        self.assertEqual(rx.purge_older_than(time.time() - 30 * 86400), 1)
        self.assertEqual(len(rx.events), 1)
        self.assertIsNotNone(rx.events.maxlen)


if __name__ == "__main__":
    unittest.main()
