"""Sigma engine: rule loading, modifiers, conditions and rule lint (roadmap F2)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.sigma_engine import SigmaEngine, SigmaRule, SigmaRuleError  # noqa: E402


def rule(detection, logsource=None):
    doc = {"id": "test", "title": "t", "level": "high", "logsource": logsource or {"product": "windows", "service": "security"},
           "detection": detection}
    return SigmaRule("test.yml", doc, {})


def event(**details):
    return {"event_id": details.pop("event_id", 4625), "event_source": "Security", "details": details}


class TestSigmaMatching(unittest.TestCase):

    def test_modifiers(self):
        r = rule({"sel": {"CommandLine|contains": "mpPreference", "Image|endswith": "\\powershell.exe",
                          "Count|gte": 10, "Ip|cidr": "10.0.0.0/8"}, "condition": "sel"})
        hit = event(CommandLine="Set-MpPreference -X", Image="C:\\x\\PowerShell.exe", Count=12, Ip="10.1.2.3")
        self.assertTrue(r.matches(hit))
        self.assertFalse(r.matches(event(CommandLine="x", Image="a\\powershell.exe", Count=12, Ip="10.1.2.3")))
        self.assertFalse(r.matches(dict(hit, details=dict(hit["details"], Count=9))))

    def test_lists_all_wildcards_and_null(self):
        self.assertTrue(rule({"s": {"A": ["x", "y"]}, "condition": "s"}).matches(event(A="y")))
        self.assertFalse(rule({"s": {"A|contains|all": ["ab", "cd"]}, "condition": "s"}).matches(event(A="abxx")))
        self.assertTrue(rule({"s": {"A": "C:\\Win*\\*.exe"}, "condition": "s"}).matches(event(A="c:\\windows\\cmd.exe")))
        self.assertTrue(rule({"s": {"Missing": None}, "condition": "s"}).matches(event(A="1")))

    def test_conditions(self):
        det = {"sel_a": {"A": "1"}, "sel_b": {"B": "2"}, "filter": {"C": "3"}}
        self.assertTrue(rule(dict(det, condition="1 of sel_* and not filter")).matches(event(A="1")))
        self.assertFalse(rule(dict(det, condition="all of sel_*")).matches(event(A="1")))
        self.assertFalse(rule(dict(det, condition="(sel_a or sel_b) and not filter")).matches(event(A="1", C="3")))

    def test_logsource_constrains_events(self):
        r = rule({"s": {"Image|endswith": ".exe"}, "condition": "s"}, {"product": "windows", "category": "process_creation"})
        self.assertTrue(r.matches({"event_id": 1, "details": {"Image": "a.exe"}}))
        self.assertFalse(r.matches({"event_id": 10, "details": {"Image": "a.exe"}}))

    def test_unsupported_syntax_fails_loudly(self):
        with self.assertRaises(SigmaRuleError):
            rule({"s": {"A": 1}, "condition": "s | count() > 5"})
        with self.assertRaises(SigmaRuleError):
            rule({"s": {"A": 1}, "condition": "s and missing"})
        with self.assertRaises(SigmaRuleError):
            rule({"s": {"A|base64offset": 1}, "condition": "s"}).matches(event(A=1))


class TestRuleLint(unittest.TestCase):
    """Every rule in rules/sigma/ must load, be unique and map to a SOAR playbook."""

    def test_all_rules_load_and_are_mapped(self):
        engine = SigmaEngine()
        self.assertGreaterEqual(len(engine.rules), 11)
        ids = [r.id for r in engine.rules]
        self.assertEqual(len(ids), len(set(ids)), "duplicate Sigma rule ids")
        unmapped = [r.file for r in engine.rules if not r.soar]
        self.assertEqual(unmapped, [], "rules without an entry in rules/soar_mapping.yml")
        soc_ids = [r.soar["soc_rule_id"] for r in engine.rules]
        self.assertEqual(len(soc_ids), len(set(soc_ids)), "duplicate SOC rule ids")

    def test_every_rule_is_tagged_with_a_technique(self):
        for r in SigmaEngine().rules:
            self.assertTrue(r.technique_ids, r.file)


if __name__ == "__main__":
    unittest.main()
