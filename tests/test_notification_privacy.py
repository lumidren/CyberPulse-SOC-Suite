"""Chat/webhook notifications carry no internal identifiers (hard rule; roadmap E50/E51)."""

import json
import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import SCRIPTED_GENERATORS  # noqa: E402
from soar.notifications import WebhookDispatcher, external_summary, pseudonym  # noqa: E402
from soar.safety import AutomationSafety  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class TestNotificationPrivacy(unittest.TestCase):

    def test_no_internal_identifier_in_any_outbound_payload(self):
        orchestrator = SOAROrchestrator(policy_mode="DRY_RUN")
        dispatcher = WebhookDispatcher()
        for _, generator in SCRIPTED_GENERATORS:
            event = generator()
            alert = orchestrator.process_event(event)
            secrets_ = [event.get("computer_name"), event.get("user"),
                        (event.get("details") or {}).get("TargetUserName")]
            if not str(event.get("source_ip", "")).startswith(("198.51.100.", "203.0.113.", "192.0.2.")):
                secrets_.append(event.get("source_ip"))
            for payload in (dispatcher.format_slack_payload(alert), dispatcher.format_discord_payload(alert),
                            external_summary(alert)):
                text = json.dumps(payload)
                for secret in filter(None, secrets_):
                    self.assertNotIn(str(secret), text, f"{secret!r} leaked by {generator.__name__}")

    def test_pseudonyms_are_stable_and_opaque(self):
        self.assertEqual(pseudonym("WIN-DC01"), pseudonym("win-dc01"))
        self.assertNotEqual(pseudonym("WIN-DC01"), pseudonym("WIN-DC02"))
        self.assertNotIn("DC01", pseudonym("WIN-DC01"))

    def test_internal_ip_withheld_public_shown(self):
        s = external_summary({"telemetry": {"source_ip": "10.0.2.15"}})
        self.assertNotIn("10.0.2.15", json.dumps(s))
        self.assertEqual(external_summary({"telemetry": {"source_ip": "198.51.100.7"}})["source_ip"], "198.51.100.7")

    def test_breaker_page_has_no_host_names(self):
        pages = []
        safety = AutomationSafety()
        safety.pager = pages.append
        safety.breaker_max_hosts = 2
        for host in ("WIN-SECRET-01", "WIN-SECRET-02"):
            safety.record_execution({"action_type": "ISOLATE_HOST_AND_KILL_PROCESS", "target_host": host})
        self.assertTrue(pages)
        self.assertFalse(any("WIN-SECRET" in p for p in pages))
        self.assertIn("WIN-SECRET-01", safety.status()["isolation_circuit_breaker"]["trips"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
