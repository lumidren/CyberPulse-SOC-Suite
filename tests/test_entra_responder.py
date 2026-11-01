"""Live Entra ID session revocation and MFA step-up (roadmap F44)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.entra_responder import EntraResponder  # noqa: E402
from soar.resilient_containment import ResilientContainmentEngine  # noqa: E402

ENV = {"ENTRA_RESPONDER_ENABLED": "true", "ENTRA_TENANT_ID": "tenant-1", "ENTRA_CLIENT_ID": "app-1",
       "ENTRA_CLIENT_SECRET": "s", "ENTRA_STEPUP_GROUP_ID": "grp-1"}
UPN = "j.doe@corp.example"


class FakeGraph:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        if self.fail_on and self.fail_on in url:
            return 403, {}
        if "oauth2/v2.0/token" in url:
            return 200, {"access_token": "tok"}
        if method == "GET" and "/users/" in url:
            return 200, {"id": "user-guid"}
        return 204, {}


class TestEntraResponder(unittest.TestCase):

    def test_disabled_without_config(self):
        self.assertFalse(EntraResponder(environ={}).enabled)
        self.assertFalse(EntraResponder(environ=dict(ENV, ENTRA_RESPONDER_ENABLED="false")).enabled)

    def test_contain_and_release_sequence(self):
        graph = FakeGraph()
        responder = EntraResponder(environ=ENV, http=graph)
        self.assertEqual(responder.contain(UPN)["steps"], ["sessions revoked", "added to MFA step-up group"])
        urls = [u for _, u in graph.calls]
        self.assertTrue(urls[1].endswith(f"/users/{UPN}/revokeSignInSessions"))
        self.assertTrue(urls[3].endswith("/groups/grp-1/members/$ref"))
        responder.release(UPN)
        self.assertEqual(graph.calls[-1], ("DELETE", "https://graph.microsoft.com/v1.0/groups/grp-1/members/user-guid/$ref"))

    def test_engine_runs_live_only_after_approval_and_rolls_back(self):
        engine = ResilientContainmentEngine()
        graph = FakeGraph()
        engine.entra = EntraResponder(environ=ENV, http=graph)
        staged = engine.execute_containment("REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA", target_host="entra",
                                            target_ip="198.51.100.9", target_user=UPN, pid=0, process_name="n/a",
                                            execution_intent="PENDING_APPROVAL")
        self.assertEqual(graph.calls, [], "nothing happens before approval")
        approved = engine.approve_action(staged["action_id"], approver="analyst_a")
        self.assertEqual(approved["status"], "SUCCESS")
        record = engine.action_registry[staged["action_id"]]
        self.assertEqual(record["execution_mode"], "live")
        rollback = engine.rollback_containment(staged["action_id"], actor="analyst_a")
        self.assertEqual(rollback["live_result"]["steps"], ["removed from MFA step-up group"])

    def test_graph_failure_flags_for_manual_review(self):
        engine = ResilientContainmentEngine()
        engine.entra = EntraResponder(environ=ENV, http=FakeGraph(fail_on="revokeSignInSessions"))
        staged = engine.execute_containment("REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA", target_host="entra",
                                            target_ip="198.51.100.9", target_user=UPN, pid=0, process_name="n/a",
                                            execution_intent="PENDING_APPROVAL")
        engine.approve_action(staged["action_id"], approver="analyst_a")
        self.assertEqual(engine.action_registry[staged["action_id"]]["status"], "FLAGGED_FOR_MANUAL_REVIEW")


if __name__ == "__main__":
    unittest.main()
