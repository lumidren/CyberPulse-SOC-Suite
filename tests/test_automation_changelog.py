"""Every change in automation behaviour is recorded in the changelog (roadmap E100)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.automation_fingerprint import fingerprint, recorded  # noqa: E402


class TestAutomationChangelog(unittest.TestCase):

    def test_latest_changelog_entry_matches_current_automation(self):
        found = recorded()
        self.assertTrue(found, "CHANGELOG.md has no 'Automation fingerprint' line")
        self.assertEqual(found[0], fingerprint(),
                         "automation behaviour changed: describe it under 'Automation behaviour' in CHANGELOG.md "
                         "and record the new fingerprint (python scripts/automation_fingerprint.py)")

    def test_fingerprint_is_stable(self):
        self.assertEqual(fingerprint(), fingerprint())


if __name__ == "__main__":
    unittest.main()
