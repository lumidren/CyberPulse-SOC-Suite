"""The CI workflow lints, tests and security-scans with a least-privilege token (roadmap F87)."""

import os
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCiWorkflow(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(ROOT, ".github", "workflows", "detection_ci.yml"), encoding="utf-8") as fh:
            self.wf = yaml.safe_load(fh)

    def test_least_privilege_token(self):
        self.assertEqual(self.wf["permissions"], {"contents": "read"})

    def test_lint_test_and_security_jobs(self):
        steps = " ".join(str(step) for job in self.wf["jobs"].values() for step in job["steps"])
        for needle in ["flake8", "unittest", "pip-audit", "bandit", "gitleaks"]:
            self.assertIn(needle, steps)

    def test_jobs_time_out(self):
        for name, job in self.wf["jobs"].items():
            self.assertIn("timeout-minutes", job, name)


if __name__ == "__main__":
    unittest.main()
