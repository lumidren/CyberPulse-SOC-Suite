"""Release/versioning consistency (roadmap F95)."""

import os
import sys
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.release_notes import changelog_section, check, project_versions  # noqa: E402


class TestRelease(unittest.TestCase):

    def test_versions_agree_and_have_changelog_section(self):
        versions = set(project_versions().values())
        self.assertEqual(len(versions), 1, project_versions())
        self.assertEqual(check(versions.pop()), [])

    def test_bad_version_rejected(self):
        self.assertTrue(check("1.2"))
        self.assertIsNone(changelog_section("99.99.99"))

    def test_release_workflow_runs_tests_and_checks_tag(self):
        with open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8") as fh:
            wf = yaml.safe_load(fh)
        steps = " ".join(str(s) for s in wf["jobs"]["release"]["steps"])
        self.assertIn("unittest", steps)
        self.assertIn("release_notes.py --check", steps)


if __name__ == "__main__":
    unittest.main()
