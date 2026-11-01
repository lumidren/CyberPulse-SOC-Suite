"""Case management: incidents auto-filed into cases with context (roadmap F35)."""

import os
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from simulator.attack_simulator import (simulate_cloud_aws_assumerole, simulate_t1003_lsass_dump,  # noqa: E402
                                        simulate_t1562_defender_tamper)
from soar.case_manager import CaseManager  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 1, 9, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


class TestCaseManager(unittest.TestCase):

    def setUp(self):
        self.orchestrator = SOAROrchestrator(policy_mode="APPROVAL_REQUIRED")
        self.clock = Clock()
        self.orchestrator.case_manager = CaseManager(clock=self.clock)
        self.cases = self.orchestrator.case_manager

    def test_same_host_incidents_share_a_case_with_context(self):
        a = self.orchestrator.process_event(simulate_t1562_defender_tamper())
        b = self.orchestrator.process_event(simulate_t1003_lsass_dump())
        self.assertEqual(a["case_id"], b["case_id"])
        case = self.cases.cases[a["case_id"]]
        self.assertEqual(case["incidents"], [a["incident_id"], b["incident_id"]])
        self.assertEqual(case["severity"], "CRITICAL")
        self.assertEqual({"SOC-RULE-005", "SOC-RULE-001"}, set(case["rules"]))
        self.assertTrue(case["responses"] and case["tasks"])
        self.assertTrue(case["simulated"])
        self.assertTrue(case["title"].endswith("WIN-WORKSTATION09"), "title keeps the host's real spelling")

    def test_other_host_or_later_activity_opens_a_new_case(self):
        a = self.orchestrator.process_event(simulate_t1003_lsass_dump())
        cloud = self.orchestrator.process_event(simulate_cloud_aws_assumerole())
        self.assertNotEqual(a["case_id"], cloud["case_id"])
        self.clock.now += timedelta(hours=3)
        later = self.orchestrator.process_event(simulate_t1003_lsass_dump())
        self.assertNotEqual(a["case_id"], later["case_id"])

    def test_status_assignee_notes_and_tasks_are_audited(self):
        case_id = self.orchestrator.process_event(simulate_t1003_lsass_dump())["case_id"]
        self.assertEqual(self.cases.update(case_id, "alice", status="Investigating", assignee="alice")["status"], "SUCCESS")
        task = self.cases.cases[case_id]["tasks"][0]["title"]
        self.assertEqual(self.cases.update(case_id, "alice", task=task, task_status="Done")["status"], "SUCCESS")
        self.assertEqual(self.cases.update(case_id, "alice", note="confirmed")["status"], "SUCCESS")
        actors = [e["actor"] for e in self.cases.cases[case_id]["timeline"]]
        self.assertGreaterEqual(actors.count("alice"), 4)
        self.assertEqual(self.cases.update(case_id, "", note="x")["status"], "ERROR")
        self.assertEqual(self.cases.update(case_id, "alice", status="Bogus")["status"], "ERROR")
        self.cases.update(case_id, "alice", status="Closed")
        self.assertEqual(self.cases.update(case_id, "alice", note="late")["status"], "ERROR", "closed is final")

    def test_retention_purges_orphaned_cases(self):
        self.orchestrator.process_event(simulate_t1003_lsass_dump())
        result = self.orchestrator.apply_retention(days=0, now=datetime.now(timezone.utc) + timedelta(days=1))
        self.assertEqual(result["cases_purged"], 1)
        self.assertEqual(self.cases.cases, {})


class TestCaseApi(unittest.TestCase):

    def test_list_get_and_update(self):
        import server
        from tests.test_server_api import _request
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            incident = server.orchestrator.process_event(simulate_t1003_lsass_dump())
            status, body = _request(base, "/api/cases")
            self.assertEqual(status, 200)
            self.assertIn(incident["case_id"], [c["case_id"] for c in body["cases"]])
            status, body = _request(base, f"/api/cases/{incident['case_id']}", method="POST",
                                    body={"analyst": "bob", "status": "Investigating"})
            self.assertEqual(status, 200)
            self.assertEqual(body["case"]["status"], "Investigating")
            status, _ = _request(base, "/api/cases/CASE-nope")
            self.assertEqual(status, 404)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
