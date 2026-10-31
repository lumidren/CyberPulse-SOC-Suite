"""Rule versioning and per-rule changelog (roadmap F7)."""

import os
import re
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.rule_versioning import detection_fingerprint  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


class TestRuleVersioning(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(ROOT, "rules", "RULE_CHANGELOG.md"), encoding="utf-8") as fh:
            self.changelog = fh.read()
        self.rules = SigmaEngine().rules

    def test_every_rule_has_a_version_and_changelog_entry(self):
        for r in self.rules:
            version = r.soar.get("version", "")
            self.assertRegex(version, SEMVER, r.file)
            section = re.search(rf"^## {re.escape(r.soar['soc_rule_id'])}:.*?(?=^## |\Z)", self.changelog, re.M | re.S)
            self.assertIsNotNone(section, f"{r.soar['soc_rule_id']} missing from RULE_CHANGELOG.md")
            self.assertIn(f"**{version}**", section.group(0), f"{r.file}: version {version} not in changelog")

    def test_detection_changes_require_a_version_bump(self):
        stale = [r.file for r in self.rules if r.soar.get("detection_sha256") != detection_fingerprint(r.doc)]
        self.assertEqual(stale, [], "detection logic changed: bump the rule version, add a RULE_CHANGELOG.md entry, "
                                    "and update detection_sha256 in rules/soar_mapping.yml")


if __name__ == "__main__":
    unittest.main()
