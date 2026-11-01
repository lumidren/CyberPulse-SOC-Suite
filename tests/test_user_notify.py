"""Automatic user notification for suspicious sign-ins (roadmap F43)."""

import json
import os
import re
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.user_notify import UserNotifier, build_message  # noqa: E402


class FakeSMTP:
    sent = []
    tls = []

    def __init__(self, host, port, timeout=15):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        FakeSMTP.tls.append(True)

    def login(self, user, password):
        pass

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


def incident(user="CORP\\j.doe", technique="T1078", simulated=False):
    return {"simulated": simulated, "created_at": "2026-11-01T10:15:00+00:00",
            "rule": {"rule_id": "SOC-RULE-010", "mitre_id": technique},
            "telemetry": {"user": user, "computer_name": "WIN-DC01", "source_ip": "198.51.100.9", "details": {}}}


class TestUserNotify(unittest.TestCase):

    def setUp(self):
        FakeSMTP.sent, FakeSMTP.tls = [], []
        fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"j.doe": "j.doe@corp.example", "svc_backup": "ops@corp.example"}, fh)
        fh.close()
        self.directory = fh.name
        self.now = [1_000_000.0]
        self.env = {"USER_NOTIFY_ENABLED": "true", "USER_NOTIFY_SMTP_HOST": "smtp.corp.example",
                    "USER_NOTIFY_FROM": "security@corp.example", "USER_NOTIFY_DIRECTORY": fh.name,
                    "USER_NOTIFY_HELPDESK": "ext. 4000"}

    def tearDown(self):
        os.unlink(self.directory)

    def notifier(self, env=None):
        return UserNotifier(environ=env or self.env, smtp_factory=FakeSMTP, clock=lambda: self.now[0])

    def test_sends_once_over_tls_then_cools_down(self):
        n = self.notifier()
        self.assertEqual(n.notify(incident())["status"], "SENT")
        self.assertEqual(FakeSMTP.tls, [True])
        self.assertEqual(FakeSMTP.sent[0]["To"], "j.doe@corp.example")
        self.assertEqual(n.notify(incident())["status"], "SKIPPED_COOLDOWN")
        self.now[0] += 25 * 3600
        self.assertEqual(n.notify(incident())["status"], "SENT")

    def test_guards(self):
        n = self.notifier()
        self.assertEqual(UserNotifier(environ={}).notify(incident())["status"], "DISABLED")
        self.assertEqual(n.notify(incident(simulated=True))["status"], "SKIPPED_SIMULATED")
        self.assertEqual(n.notify(incident(technique="T1003.001"))["status"], "NOT_A_SIGN_IN_ALERT")
        self.assertEqual(n.notify(incident(user="CORP\\svc_backup"))["status"], "SKIPPED_PROTECTED_OR_SERVICE")
        self.assertEqual(n.notify(incident(user="CORP\\unknown.person"))["status"], "NO_ADDRESS")
        self.assertEqual(FakeSMTP.sent, [])

    def test_message_has_no_links_or_incident_details(self):
        body = build_message("j.doe", "security@corp.example", "j.doe@corp.example", "ext. 4000",
                             "2026-11-01T10:15").get_content()
        self.assertIsNone(re.search(r"https?://|www\.", body))
        for detail in ("SOC-RULE", "198.51.100", "WIN-DC01", "T1078"):
            self.assertNotIn(detail, body)
        self.assertIn("ext. 4000", body)


if __name__ == "__main__":
    unittest.main()
