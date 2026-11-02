"""Sigma -> SPL / Lucene / KQL / Wazuh conversion (roadmap F5)."""

import os
import sys
import unittest
import xml.dom.minidom

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.convert_rules import render_all  # noqa: E402
from soar.sigma_convert import TARGETS, convert  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402


class TestSigmaConvert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rules = {os.path.basename(r.file): r for r in SigmaEngine().rules}

    def test_every_rule_converts_to_every_target(self):
        for name, rule in self.rules.items():
            for target in TARGETS:
                self.assertTrue(convert(rule, target).strip(), f"{name} -> {target}")

    def test_known_translations(self):
        lsass = self.rules["win_lsass_dumping.yml"]
        self.assertIn("EventCode=10", convert(lsass, "splunk"))
        self.assertIn("NOT", convert(lsass, "splunk"))
        ps = self.rules["win_powershell_obfuscation.yml"]
        self.assertTrue(convert(ps, "kql").splitlines()[1].startswith("DeviceProcessEvents"))
        self.assertIn('ProcessCommandLine contains "-EncodedCommand"', convert(ps, "kql"))
        self.assertIn("process.command_line:*", convert(ps, "elastic"))

    def test_wazuh_output_is_valid_xml_with_product_groups(self):
        xml_text = render_all()[os.path.join("wazuh", "cyberpulse_sigma_generated.xml")]
        doc = xml.dom.minidom.parseString(xml_text)
        self.assertGreaterEqual(len(doc.getElementsByTagName("rule")), len(self.rules))
        aws = convert(self.rules["cloud_aws_assumerole_abuse.yml"], "wazuh")
        self.assertIn("<if_group>amazon</if_group>", aws)
        self.assertIn('name="aws.eventName"', aws)

    def test_category_event_ids_survive_every_target(self):
        lsass = self.rules["win_lsass_dumping.yml"]  # process_access: no dedicated KQL table
        self.assertIn("EventID in (10) and (", convert(lsass, "kql"))
        self.assertIn('name="win.system.eventID" type="pcre2">(?i)(?:^10$)', convert(lsass, "wazuh"))
        ps = self.rules["win_powershell_obfuscation.yml"]  # process_creation: DeviceProcessEvents implies it
        self.assertNotIn("EventID in", convert(ps, "kql"))
        self.assertIn("(?:^1$|^4688$)", convert(ps, "wazuh"))

    def test_log_source_filter_wraps_the_whole_query(self):
        """`event.code:1 AND (a) OR (b)` would let branch b match any event; the query must be one group."""
        for name, rule in self.rules.items():
            body = convert(rule, "elastic").splitlines()[1]
            if not body.startswith("(event.code:"):
                continue
            query = body.split(") AND ", 1)[1]
            depth = 0
            for i, ch in enumerate(query):
                depth += {"(": 1, ")": -1}.get(ch, 0)
                if depth == 0:
                    self.assertEqual(i, len(query) - 1, f"{name}: query is not one parenthesised group")
                    break

    def test_committed_conversions_are_current(self):
        stale = []
        for rel, body in render_all().items():
            path = os.path.join(ROOT, "rules", "converted", rel)
            with open(path, encoding="utf-8") as fh:
                if fh.read().replace("\r\n", "\n") != body:
                    stale.append(rel)
        self.assertEqual(stale, [], "run: python scripts/convert_rules.py")


if __name__ == "__main__":
    unittest.main()
