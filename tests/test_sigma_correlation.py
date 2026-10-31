"""Sigma correlation rules (roadmap F12)."""

import os
import re
import shutil
import sys
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.sigma_correlation import CorrelationEngine, correlation_fingerprint, parse_timespan  # noqa: E402
from soar.sigma_engine import SigmaRuleError  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


def failed_logon(second, user="lab.admin", ip="198.51.100.9", minute=0, **details):
    return {"event_id": 4625, "event_source": "Security", "source_ip": ip,
            "timestamp": f"2026-11-01T10:{minute:02d}:{second:02d}Z",
            "details": {"LogonType": 10, "TargetUserName": user, **details}}


def ids(results):
    return [r["rule_id"] for r in results]


class TestBruteForceCorrelation(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_fires_on_tenth_failure_once(self):
        fired = [ids(self.engine.observe(failed_logon(i))) for i in range(15)]
        self.assertEqual(fired[9], ["SOC-RULE-043"])
        self.assertEqual(sum(1 for f in fired if f), 1, "one burst must produce one alert")

    def test_nine_failures_do_not_fire(self):
        self.assertFalse(any(self.engine.observe(failed_logon(i)) for i in range(9)))

    def test_groups_by_source_and_account(self):
        events = [failed_logon(i, user=f"user{i % 2}") for i in range(10)]
        self.assertFalse(any(self.engine.observe(e) for e in events))

    def test_window_expires(self):
        for i in range(5):
            self.engine.observe(failed_logon(i))
        later = [self.engine.observe(failed_logon(i, minute=7)) for i in range(5)]
        self.assertFalse(any(later), "failures more than 5 minutes apart must not add up")

    def test_pre_aggregated_events_are_left_to_rule_002(self):
        self.assertFalse(any(self.engine.observe(failed_logon(i, FailedAttemptsCount=18)) for i in range(12)))

    def test_pipeline_returns_correlation_alert(self):
        orchestrator = SOAROrchestrator(policy_mode="DRY_RUN")
        results = [orchestrator.evaluate_detection(failed_logon(i)) for i in range(10)]
        self.assertTrue(all(r is None for r in results[:9]))
        self.assertEqual(results[9]["rule_id"], "SOC-RULE-043")
        self.assertEqual(results[9]["correlation"]["type"], "event_count")


class TestSprayingAndMassWrite(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationEngine()

    def test_spraying_fires_on_tenth_distinct_account(self):
        fired = [ids(self.engine.observe(failed_logon(i, user=f"user{i:02d}", SubStatus="0xc000006a")))
                 for i in range(10)]
        self.assertIn("SOC-RULE-044", fired[9])
        self.assertFalse(any("SOC-RULE-044" in f for f in fired[:9]))

    def test_spraying_ignores_one_account_retried(self):
        fired = [ids(self.engine.observe(failed_logon(i, SubStatus="0xc000006a"))) for i in range(20)]
        self.assertFalse(any("SOC-RULE-044" in f for f in fired))

    def file_write(self, n, image="C:\\Users\\Public\\enc.exe", path="C:\\Users\\j.doe\\Documents"):
        return {"event_id": 11, "event_source": "Microsoft-Windows-Sysmon", "computer_name": "WIN-WORKSTATION09",
                "timestamp": f"2026-11-01T10:00:{n // 10:02d}.{n % 10}Z",
                "details": {"Image": image, "TargetFilename": f"{path}\\file{n}.docx.locked"}}

    def test_mass_write_fires_at_100_files_in_a_minute(self):
        fired = [ids(self.engine.observe(self.file_write(n))) for n in range(100)]
        self.assertEqual(fired[99], ["SOC-RULE-045"])
        self.assertFalse(any(fired[:99]))

    def test_mass_write_ignores_known_writers_and_system_paths(self):
        defender = [self.engine.observe(self.file_write(n, image="C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe"))
                    for n in range(150)]
        system = [self.engine.observe(self.file_write(n, path="C:\\Windows\\Temp")) for n in range(150)]
        self.assertFalse(any(defender) or any(system))


class TestCorrelationTypes(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dir)

    def load(self, correlation):
        body = textwrap.dedent("""\
            title: base a
            name: a
            logsource: {product: windows, service: security}
            detection: {s: {EventID: 1}, condition: s}
            ---
            title: base b
            name: b
            logsource: {product: windows, service: security}
            detection: {s: {EventID: 2}, condition: s}
            ---
            title: corr
            id: test-corr
            tags: [attack.t1110.003]
            """) + textwrap.indent(correlation, "")
        with open(os.path.join(self.dir, "c.yml"), "w", encoding="utf-8") as fh:
            fh.write(body)
        return CorrelationEngine(rules_dir=self.dir, mapping_path=None)

    def ev(self, event_id, second, **details):
        return {"event_id": event_id, "event_source": "Security", "source_ip": "198.51.100.1",
                "timestamp": f"2026-11-01T10:00:{second:02d}Z", "details": details}

    def test_value_count(self):
        engine = self.load("correlation: {type: value_count, rules: [a], group-by: [IpAddress], timespan: 1m,"
                           " condition: {gte: 3, field: TargetUserName}}\n")
        same = [engine.observe(self.ev(1, i, TargetUserName="x")) for i in range(5)]
        self.assertFalse(any(same), "repeats of one value must not count")
        # "x" plus two new accounts makes three distinct values
        fired = [engine.observe(self.ev(1, 10 + i, TargetUserName=f"u{i}")) for i in range(2)]
        self.assertEqual([ids(f) for f in fired], [[], ["test-corr"]])

    def test_temporal_needs_all_rules(self):
        engine = self.load("correlation: {type: temporal, rules: [a, b], group-by: [IpAddress], timespan: 1m}\n")
        self.assertFalse(engine.observe(self.ev(1, 0)))
        self.assertFalse(engine.observe(self.ev(1, 1)))
        self.assertEqual(ids(engine.observe(self.ev(2, 2))), ["test-corr"])

    def test_unknown_base_rule_is_rejected(self):
        with self.assertRaises(SigmaRuleError):
            self.load("correlation: {type: event_count, rules: [missing], timespan: 1m, condition: {gte: 2}}\n")

    def test_bad_timespan(self):
        self.assertEqual(parse_timespan("5m"), 300)
        with self.assertRaises(SigmaRuleError):
            parse_timespan("5 minutes")


class TestCorrelationCatalogue(unittest.TestCase):

    def test_mapped_versioned_and_in_changelog(self):
        with open(os.path.join(ROOT, "rules", "RULE_CHANGELOG.md"), encoding="utf-8") as fh:
            changelog = fh.read()
        rules = CorrelationEngine().rules
        self.assertGreaterEqual(len(rules), 1)
        for rule in rules:
            self.assertTrue(rule.soar.get("soc_rule_id"), rule.file)
            self.assertEqual(rule.soar.get("detection_sha256"), correlation_fingerprint(rule),
                             f"{rule.file}: logic changed, bump version and fingerprint")
            self.assertTrue(re.search(rf"^## {re.escape(rule.soar['soc_rule_id'])}:", changelog, re.M))
            self.assertTrue(rule.technique_ids, rule.file)


if __name__ == "__main__":
    unittest.main()
