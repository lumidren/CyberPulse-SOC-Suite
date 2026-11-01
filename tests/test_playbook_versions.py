"""Playbook versioning and test cases (roadmap F34)."""

import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.playbooks import PlaybookRegistry, pb_for_test, run_cases, version_problems  # noqa: E402


class TestPlaybookVersions(unittest.TestCase):

    def test_all_playbook_cases_pass(self):
        failed = [(name, f) for name, f in run_cases() if f]
        self.assertEqual(failed, [], "run: python -m soar.playbooks --test")

    def test_behaviour_changes_need_a_version_bump(self):
        self.assertEqual(version_problems(), [])

    def test_changelog_lists_every_current_version(self):
        with open(os.path.join(ROOT, "playbooks", "CHANGELOG.md"), encoding="utf-8") as fh:
            changelog = fh.read()
        for pb in PlaybookRegistry().playbooks:
            section = re.search(rf"^## {re.escape(pb.name)}\n(.*?)(?=^## |\Z)", changelog, re.M | re.S)
            self.assertIsNotNone(section, pb.name)
            self.assertIn(f"**{pb.version}**", section.group(1), pb.name)

    def test_fingerprint_tracks_behaviour_not_wording(self):
        a = pb_for_test(description="one", tasks=["x"])
        b = pb_for_test(description="two", tasks=["x"])
        c = pb_for_test(description="one", tasks=["y"])
        self.assertEqual(a.fingerprint(), b.fingerprint())
        self.assertNotEqual(a.fingerprint(), c.fingerprint())


if __name__ == "__main__":
    unittest.main()
