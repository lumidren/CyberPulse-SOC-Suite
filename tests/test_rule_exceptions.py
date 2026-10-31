"""Per-rule exceptions / allowlist (roadmap F15)."""

import os
import shutil
import sys
import tempfile
import threading
import unittest
from datetime import date

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import yaml  # noqa: E402

from soar.rule_exceptions import DEFAULT_EXCEPTIONS, ExceptionRegistry, RuleException  # noqa: E402
from soar.sigma_engine import SigmaEngine, SigmaRuleError  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402

ENCODED_PS = {"event_id": 1, "event_source": "Microsoft-Windows-Sysmon/Operational",
              "details": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          "ParentImage": "C:\\Windows\\System32\\svchost.exe",
                          "CommandLine": "powershell.exe -NoProfile -File C:\\Scripts\\inventory.ps1"}}


def exc(**overrides):
    doc = {"id": "EXC-T1", "rule": "SOC-RULE-004", "reason": "test", "owner": "tester",
           "created": "2026-11-01", "expires": "2026-12-01",
           "match": {"CommandLine|contains": "C:\\Scripts\\", "ParentImage|endswith": "\\svchost.exe"}}
    doc.update(overrides)
    return doc


class TestExceptionValidation(unittest.TestCase):

    def test_required_fields(self):
        doc = exc()
        del doc["owner"]
        with self.assertRaises(SigmaRuleError):
            RuleException(doc)

    def test_lifetime_capped(self):
        with self.assertRaises(SigmaRuleError):
            RuleException(exc(expires="2027-11-01"))
        with self.assertRaises(SigmaRuleError):
            RuleException(exc(expires="2026-10-01"))

    def test_cannot_disable_a_whole_rule(self):
        with self.assertRaises(SigmaRuleError):
            RuleException(exc(match={}))
        with self.assertRaises(SigmaRuleError):
            RuleException(exc(match={"CommandLine": "*"}))


class TestSuppression(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "exceptions.yml")
        with open(self.path, "w", encoding="utf-8") as fh:
            yaml.safe_dump({"exceptions": [exc()]}, fh)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def orchestrator(self, today):
        o = SOAROrchestrator(policy_mode="DRY_RUN")
        o.exceptions = ExceptionRegistry(self.path, clock=lambda: today)
        return o

    def test_active_exception_suppresses_and_counts(self):
        o = self.orchestrator(date(2026, 11, 15))
        self.assertIsNone(o.evaluate_detection(ENCODED_PS))
        self.assertEqual(o.exceptions.status()["exceptions"][0]["suppressed"], 1)

    def test_expired_exception_stops_suppressing(self):
        o = self.orchestrator(date(2026, 12, 2))
        self.assertEqual(o.evaluate_detection(ENCODED_PS)["rule_id"], "SOC-RULE-004")
        self.assertEqual(o.exceptions.status()["exceptions"][0]["status"], "expired")

    def test_only_matching_events_are_suppressed(self):
        o = self.orchestrator(date(2026, 11, 15))
        other = {**ENCODED_PS, "details": {**ENCODED_PS["details"], "ParentImage": "C:\\Windows\\System32\\cmd.exe"}}
        self.assertEqual(o.evaluate_detection(other)["rule_id"], "SOC-RULE-004")


class TestCommittedExceptions(unittest.TestCase):
    """Entries in rules/exceptions.yml load and never hide a rule's own attack samples."""

    def test_load_and_reference_real_rules(self):
        registry = ExceptionRegistry(DEFAULT_EXCEPTIONS)
        soc_ids = {r.soar.get("soc_rule_id") for r in SigmaEngine().rules}
        for e in registry.exceptions:
            self.assertIn(e.rule, soc_ids, e.id)

    def test_no_exception_suppresses_a_positive_sample(self):
        registry = ExceptionRegistry(DEFAULT_EXCEPTIONS)
        rule_by_file = {os.path.basename(r.file): r.soar.get("soc_rule_id") for r in SigmaEngine().rules}
        samples_dir = os.path.join(ROOT, "rules", "tests")
        for name in os.listdir(samples_dir):
            with open(os.path.join(samples_dir, name), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            soc_id = rule_by_file.get(doc["rule"])
            for sample in doc.get("positive") or []:
                hidden = [e.id for e in registry.exceptions if e.rule == soc_id and e.covers(sample["event"])]
                self.assertEqual(hidden, [], f"{doc['rule']}: '{sample['name']}' would be suppressed")


class TestExceptionsApi(unittest.TestCase):

    def test_endpoint_lists_exceptions(self):
        from tests.test_server_api import _request
        from server import create_server
        httpd = create_server(host="127.0.0.1", port=0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            status, body = _request(f"http://127.0.0.1:{httpd.server_address[1]}", "/api/exceptions")
            self.assertEqual(status, 200)
            self.assertIn("exceptions", body)
            self.assertEqual(body["max_lifetime_days"], 180)
            status, _ = _request(f"http://127.0.0.1:{httpd.server_address[1]}", "/api/exceptions", api_key=None)
            self.assertEqual(status, 401)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
