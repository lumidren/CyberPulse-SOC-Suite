"""Rule-set breadth: 40+ rules covering the ATT&CK tactics end to end (roadmap F1)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.input_validation import DETAIL_FIELD_ALLOWLIST  # noqa: E402
from soar.sigma_correlation import CorrelationEngine  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402

TACTICS = {"initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
           "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
           "exfiltration", "impact"}


class TestRuleCoverage(unittest.TestCase):

    def setUp(self):
        self.rules = SigmaEngine().rules

    def test_at_least_forty_rules(self):
        self.assertGreaterEqual(len(self.rules), 40)

    def test_every_tactic_has_a_rule(self):
        covered = {str(t).split(".", 1)[1] for r in self.rules for t in r.tags
                   if str(t).startswith("attack.") and not str(t).startswith("attack.t")}
        self.assertEqual(TACTICS - covered, set())

    def test_rule_fields_survive_ingest_minimisation(self):
        # Data minimisation (E48) must not strip a field a rule needs
        aliases = {"EventID", "Computer", "IpAddress", "SourceIp", "sourceIPAddress", "IPAddress", "User"}
        needed = {spec.split("|")[0] for r in self.rules for sel in r.selections.values()
                  for item in (sel if isinstance(sel, list) else [sel]) if isinstance(item, dict) for spec in item}
        self.assertEqual(needed - DETAIL_FIELD_ALLOWLIST - aliases, set())

    def test_correlation_fields_survive_ingest_minimisation(self):
        aliases = {"EventID", "Computer", "IpAddress", "SourceIp", "sourceIPAddress", "IPAddress", "User"}
        engine = CorrelationEngine()
        needed = {spec.split("|")[0] for r in engine.base_rules.values() for sel in r.selections.values()
                  if isinstance(sel, dict) for spec in sel}
        for corr in engine.rules:
            needed |= set(corr.group_by) | ({corr.value_field} if corr.value_field else set())
        self.assertEqual(needed - DETAIL_FIELD_ALLOWLIST - aliases, set())


if __name__ == "__main__":
    unittest.main()
