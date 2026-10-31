"""Static checks on the one-command lab compose file (roadmap F86)."""

import os
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLabCompose(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(ROOT, "compose.yaml"), encoding="utf-8") as fh:
            self.service = yaml.safe_load(fh)["services"]["cyberpulse"]

    def test_published_on_loopback_only(self):
        self.assertEqual(self.service["ports"], ["127.0.0.1:5000:5000"])

    def test_declared_lab_with_approval_default(self):
        env = self.service["environment"]
        self.assertEqual(env["CYBERPULSE_LAB_MODE"], "true")
        self.assertEqual(env["POLICY_MODE"], "APPROVAL_REQUIRED")
        self.assertNotIn("CYBERPULSE_ALLOW_FULL_AUTO", env)

    def test_container_hardening(self):
        self.assertTrue(self.service["read_only"])
        self.assertIn("ALL", self.service["cap_drop"])
        self.assertIn("no-new-privileges:true", self.service["security_opt"])

    def test_dockerfile_exists(self):
        self.assertTrue(os.path.isfile(os.path.join(ROOT, self.service["build"]["dockerfile"])))


if __name__ == "__main__":
    unittest.main()
