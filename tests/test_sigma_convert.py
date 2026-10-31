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
