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
