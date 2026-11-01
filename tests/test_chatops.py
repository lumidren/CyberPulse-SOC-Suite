"""ChatOps approval buttons for Slack / Teams / Telegram (roadmap F31)."""

import hashlib
import hmac
import json
import os
import sys
import unittest
from urllib.parse import urlencode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.chatops import (ChatOpsApprovals, parse_approvers, slack_approval_message, teams_approval_card,  # noqa: E402
                          telegram_approval_message)
from soar.resilient_containment import ResilientContainmentEngine  # noqa: E402

NOW = 1_800_000_000
SECRET = "slack-test-secret"


def stage(engine, host="WIN-WORKSTATION09"):
    return engine.execute_containment(action_type="ISOLATE_HOST_AND_KILL_PROCESS", target_host=host,
                                      target_ip="10.0.2.15", target_user="CORP\\j.doe", pid=4812,
                                      process_name="tool.exe", execution_intent="PENDING_APPROVAL")


def slack_body(user, value):
    return urlencode({"payload": json.dumps({"user": {"id": user}, "actions": [{"value": value}]})}).encode()


def slack_sig(body, ts=NOW, secret=SECRET):
    return "v0=" + hmac.new(secret.encode(), f"v0:{ts}:".encode() + body, hashlib.sha256).hexdigest()


class TestChatOps(unittest.TestCase):

    def setUp(self):
        self.engine = ResilientContainmentEngine()
        self.chat = ChatOpsApprovals(self.engine, slack_secret=SECRET, telegram_secret="tg-secret",
                                     approvers=parse_approvers("slack:U1,telegram:42"), clock=lambda: NOW)
        self.action = stage(self.engine)

    def test_slack_signature_checks(self):
        body = slack_body("U1", f"approve:{self.action['action_id']}")
        self.assertTrue(self.chat.verify_slack(str(NOW), slack_sig(body), body)[0])
        self.assertFalse(self.chat.verify_slack(str(NOW), slack_sig(body, secret="wrong"), body)[0])
        self.assertFalse(self.chat.verify_slack(str(NOW - 600), slack_sig(body, ts=NOW - 600), body)[0], "replay")
        self.assertFalse(ChatOpsApprovals(self.engine, slack_secret="").verify_slack(str(NOW), "v0=x", body)[0])

    def test_authorised_slack_user_approves(self):
        reply = self.chat.handle_slack(slack_body("U1", f"approve:{self.action['action_id']}"))
        self.assertIn("SUCCESS", reply["text"])
        record = self.engine.action_registry[self.action["action_id"]]
        self.assertNotEqual(record["status"], "PENDING_ANALYST_APPROVAL")

    def test_unlisted_user_cannot_decide(self):
        reply = self.chat.handle_slack(slack_body("U-intruder", f"approve:{self.action['action_id']}"))
        self.assertIn("not an authorised approver", reply["text"])
        self.assertEqual(self.engine.action_registry[self.action["action_id"]]["status"], "PENDING_ANALYST_APPROVAL")

    def test_telegram_reject_and_secret(self):
        self.assertFalse(self.chat.verify_telegram("nope")[0])
        self.assertTrue(self.chat.verify_telegram("tg-secret")[0])
        reply = self.chat.handle_telegram({"callback_query": {"id": "q1", "from": {"id": 42},
                                                              "data": f"reject:{self.action['action_id']}"}})
        self.assertTrue(reply["text"].startswith("SUCCESS"))

    def test_kill_switch_still_blocks_chat_approval_without_leaking_names(self):
        self.engine.safety.engage_kill_switch("analyst", "test")
        reply = self.chat.handle_slack(slack_body("U1", f"approve:{self.action['action_id']}"))
        self.assertIn("not applied", reply["text"])
        self.assertNotIn("WIN-WORKSTATION09", reply["text"])

    def test_messages_use_pseudonyms(self):
        for message in (slack_approval_message(self.action), telegram_approval_message(self.action, chat_id=1),
                        teams_approval_card(self.action, "https://soc.lab.local")):
            text = json.dumps(message)
            self.assertNotIn("WIN-WORKSTATION09", text)
            self.assertNotIn("j.doe", text)
        self.assertLessEqual(len(f"approve:{self.action['action_id']}"), 64, "Telegram callback_data limit")


class TestChatOpsRoutes(unittest.TestCase):

    def test_routes_require_platform_signature_not_api_key(self):
        import threading
        import urllib.error
        import urllib.request
        from server import create_server
        httpd = create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            for path in ("/api/chatops/slack", "/api/chatops/telegram"):
                req = urllib.request.Request(base + path, data=b"payload=%7B%7D", method="POST",
                                             headers={"Content-Type": "application/x-www-form-urlencoded"})
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(req, timeout=10)
                self.assertEqual(ctx.exception.code, 401, path)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
