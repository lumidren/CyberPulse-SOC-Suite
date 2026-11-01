"""LLM-assisted triage summary: pseudonymised payload, advisory draft, analyst decides (roadmap F96)."""

import json
import os
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import simulate_t1003_lsass_dump  # noqa: E402
from soar import llm_triage  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402

ON = {"LLM_TRIAGE_ENABLED": "true"}


class StubClient:
    """Records the request instead of calling the API."""

    def __init__(self, text="What fired: LSASS access.", stop_reason="end_turn"):
        self.requests = []
        self.response = SimpleNamespace(model="claude-opus-5-5", stop_reason=stop_reason,
                                        content=[SimpleNamespace(type="text", text=text)] if text else [])
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.requests.append(kwargs)
        return self.response


def lsass_incident():
    return SOAROrchestrator(policy_mode="APPROVAL_REQUIRED").process_event(simulate_t1003_lsass_dump())


class TestLlmTriage(unittest.TestCase):

    def test_disabled_by_default(self):
        with self.assertRaises(llm_triage.LlmTriageDisabled):
            llm_triage.draft_summary(lsass_incident(), "analyst_a", client=StubClient(), environ={})

    def test_payload_carries_no_internal_identifiers(self):
        incident = lsass_incident()
        client = StubClient()
        llm_triage.draft_summary(incident, "analyst_a", client=client, environ=ON)
        request = client.requests[0]
        sent = request["messages"][0]["content"]
        telemetry = incident["telemetry"]
        for value in (telemetry["computer_name"], telemetry["user"], json.dumps(telemetry["user"])[1:-1],
                      "sourceimage", "4812"):  # raw event details and the PID
            self.assertNotIn(value.lower(), sent.lower())
        self.assertEqual(llm_triage.find_leaks(sent, incident), [])
        self.assertIn('"host": "host-', sent)
        self.assertIn("SOC-RULE", sent)
        # Request shape for Claude Opus 5.5: effort instead of thinking budgets, scalar server-side fallbacks
        self.assertEqual(request["model"], "claude-opus-5-5")
        self.assertEqual((request["fallbacks"], request["betas"]), ("default", ["server-side-fallback-2026-07-01"]))
        self.assertNotIn("thinking", request)
        self.assertNotIn("temperature", request)

    def test_leak_guard_refuses_before_sending(self):
        incident = lsass_incident()
        client = StubClient()
        payload = dict(llm_triage.build_payload(incident), note="seen from 10.0.5.23")
        with mock.patch.object(llm_triage, "build_payload", return_value=payload):
            with self.assertRaises(llm_triage.PayloadRefused):
                llm_triage.draft_summary(incident, "analyst_a", client=client, environ=ON)
        self.assertEqual(client.requests, [])
        self.assertIn("computer_name", llm_triage.find_leaks("host WIN-WORKSTATION09", incident))
        self.assertEqual(llm_triage.find_leaks("attacker 198.51.100.33", incident), [])

    def test_draft_is_advisory_and_the_analyst_decides(self):
        orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        incident = orchestrator.process_event(simulate_t1003_lsass_dump())
        actions_before = dict(orchestrator.containment_engine.action_registry)
        record = llm_triage.draft_summary(incident, "analyst_a", client=StubClient(text="Approve isolation now."), environ=ON)
        self.assertEqual((record["status"], record["advisory"]), ("DRAFT", True))
        # Even a draft that "recommends" an action changes nothing
        self.assertEqual(orchestrator.containment_engine.action_registry, actions_before)
        with self.assertRaises(ValueError):
            llm_triage.review_summary(incident, "analyst_a", "approve")
        accepted = llm_triage.review_summary(incident, "analyst_a", "accept", text="LSASS read by an unsigned tool; check parent.")
        self.assertEqual((accepted["status"], accepted["edited"]), ("ACCEPTED", True))
        self.assertEqual(accepted["original_text"], "Approve isolation now.")
        with self.assertRaises(ValueError):
            llm_triage.review_summary(incident, "analyst_b", "reject")

    def test_refusal_and_reject(self):
        incident = lsass_incident()
        refused = llm_triage.draft_summary(incident, "analyst_a", client=StubClient(text="", stop_reason="refusal"), environ=ON)
        self.assertEqual((refused["status"], refused["text"]), ("REFUSED", ""))
        with self.assertRaises(ValueError):
            llm_triage.review_summary(incident, "analyst_a", "accept")
        llm_triage.draft_summary(incident, "analyst_a", client=StubClient(), environ=ON)
        self.assertEqual(llm_triage.review_summary(incident, "analyst_a", "reject")["status"], "REJECTED")

    def test_endpoints_record_decisions_and_report_disabled(self):
        import server
        from tests.test_server_api import _request
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            inc_id = server.orchestrator.process_event(simulate_t1003_lsass_dump())["incident_id"]
            status, body = _request(base, f"/api/incidents/{inc_id}/llm-summary", "POST", {"analyst": "analyst_a"})
            self.assertEqual((status, body["error"][:22]), (503, "LLM triage is disabled"))
            with mock.patch.dict(os.environ, ON), mock.patch.object(llm_triage, "_default_client", return_value=StubClient()):
                status, body = _request(base, f"/api/incidents/{inc_id}/llm-summary", "POST", {"analyst": "analyst_a"})
            self.assertEqual((status, body["llm_summary"]["status"]), (200, "DRAFT"))
            status, body = _request(base, f"/api/incidents/{inc_id}/llm-summary/review", "POST",
                                    {"analyst": "analyst_a", "decision": "accept"})
            self.assertEqual((status, body["llm_summary"]["status"], body["llm_summary"]["edited"]), (200, "ACCEPTED", False))
            notes = server.orchestrator.dfir_engine.incidents[inc_id]["analyst_notes"]
            self.assertIn("AI-drafted", notes[-1]["note"])
            events = [e["event"] for e in server.orchestrator.containment_engine.ledger.entries[-2:]]
            self.assertEqual(events, ["llm_summary_requested", "llm_summary_accepted"])
            status, body = _request(base, f"/api/incidents/{inc_id}/llm-summary")
            self.assertEqual((status, body["llm_summary"]["reviewed_by"]), (200, "analyst_a"))
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
