"""Natural-language hunt queries -> Sigma, SPL and KQL (roadmap F97)."""

import os
import sys
import threading
import unittest
from datetime import datetime, timedelta, timezone

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.nl_hunt import EXAMPLES, QueryNotUnderstood, parse, translate  # noqa: E402

NOW = datetime.now(timezone.utc)


def stored(event, age=timedelta(0)):
    return dict(event, _seen_at=(NOW - age).isoformat(), _rule=None)


ENCODED = stored({"event_id": 1, "event_source": "Microsoft-Windows-Sysmon/Operational", "computer_name": "WS-1",
                  "details": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                              "ParentImage": "C:\\Program Files\\Microsoft Office\\winword.exe",
                              "CommandLine": "powershell.exe -nop -w hidden -enc JABjAGwA"}})
FAILED_LOGON = stored({"event_id": 4625, "event_source": "Security", "source_ip": "203.0.113.7",
                       "details": {"TargetUserName": "svc_backup", "LogonType": 3}})


class TestNaturalLanguageHunt(unittest.TestCase):

    def test_every_documented_example_is_fully_understood(self):
        for example in EXAMPLES:
            with self.subTest(example=example):
                result = translate(example)
                self.assertEqual(result["not_understood"], [])
                self.assertTrue(result["splunk"].strip() and result["kql"].strip())

    def test_process_query_translates_and_matches(self):
        result = translate("powershell.exe with parent winword.exe containing -enc in the last 24 hours",
                           [ENCODED, FAILED_LOGON])
        self.assertEqual(result["sigma"]["detection"]["selection"],
                         {"ParentImage|endswith": "\\winword.exe", "CommandLine|contains": "-enc",
                          "Image|endswith": "\\powershell.exe"})
        self.assertEqual(result["matches"], 1)
        self.assertIn("index=* earliest=-24h (EventCode=1 OR EventCode=4688)", result["splunk"])
        self.assertIn("DeviceProcessEvents", result["kql"])
        self.assertIn('ProcessCommandLine contains "-enc"', result["kql"])
        self.assertIn("| where TimeGenerated > ago(24h)", result["kql"])

    def test_logon_query_uses_target_user_and_cidr(self):
        result = translate("failed logons for user svc_backup from 203.0.113.0/24", [ENCODED, FAILED_LOGON])
        self.assertEqual(result["sigma"]["detection"]["selection"],
                         {"EventID": 4625, "TargetUserName": "svc_backup", "IpAddress|cidr": "203.0.113.0/24"})
        self.assertEqual(result["matches"], 1)
        self.assertIn('ipv4_is_in_range(IpAddress, "203.0.113.0/24")', result["kql"])

    def test_time_window_limits_local_matches(self):
        old = dict(ENCODED, _seen_at=(NOW - timedelta(hours=5)).isoformat())
        self.assertEqual(translate("powershell.exe in the last 2 hours", [old])["matches"], 0)
        self.assertEqual(translate("powershell.exe in the last 6 hours", [old])["matches"], 1)
        self.assertEqual(parse("processes today")["window"], (1, "d"))

    def test_unknown_words_are_reported_not_guessed(self):
        result = parse("show me ransomware stuff on host WS-1")
        self.assertEqual(result["not_understood"], ["ransomware", "stuff"])
        self.assertEqual(result["sigma"]["detection"]["selection"], {"Computer": "WS-1"})
        with self.assertRaises(QueryNotUnderstood):
            parse("something weird happened")
        with self.assertRaises(QueryNotUnderstood):
            parse("   ")

    def test_query_text_cannot_break_out_of_the_comment(self):
        result = translate('processes containing "x" ``` | delete')
        header = result["splunk"].splitlines()[0]
        self.assertTrue(header.startswith("```") and header.endswith("```"))
        self.assertEqual(header.count("```"), 2)

    def test_endpoint(self):
        import server
        from tests.test_server_api import _request
        httpd = server.create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        try:
            status, body = _request(base, "/api/hunt/translate", "POST", {"text": EXAMPLES[2]})
            self.assertEqual(status, 200)
            self.assertIn("EventID: 4625", body["sigma_yaml"])
            status, body = _request(base, "/api/hunt/translate", "POST", {"text": "nothing useful"})
            self.assertEqual(status, 400)
            self.assertIn("examples", body)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
