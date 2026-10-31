"""Configuration file + schema validation (roadmap F93)."""

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.config import SCHEMA, ConfigError, load_and_apply, validate  # noqa: E402


class TestConfigSchema(unittest.TestCase):

    def test_example_config_is_valid(self):
        env = {}
        load_and_apply(os.path.join(ROOT, "config", "cyberpulse.example.yml"), env=env)
        self.assertEqual(env["POLICY_MODE"], "APPROVAL_REQUIRED")
        self.assertEqual(env["CYBERPULSE_ALLOW_FULL_AUTO"], "false")

    def test_invalid_values_are_all_reported(self):
        problems = validate({}, env={"PORT": "99999", "POLICY_MODE": "YOLO", "CONFIDENCE_THRESHOLD": "1.5",
                                     "CYBERPULSE_LAB_CIDRS": "10.0.0.0/33", "WINRM_ENDPOINT": "http://x"})
        self.assertEqual(len(problems), 5, problems)

    def test_secrets_and_unknown_keys_refused_in_file(self):
        problems = validate({"CYBERPULSE_API_KEY": "abc", "MADE_UP": 1}, env={})
        self.assertTrue(any("secret" in p for p in problems))
        self.assertTrue(any("unknown setting MADE_UP" in p for p in problems))

    def test_environment_overrides_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as fh:
            fh.write("RETENTION_DAYS: 10\n")
        try:
            env = {"RETENTION_DAYS": "45"}
            load_and_apply(fh.name, env=env)
            self.assertEqual(env["RETENTION_DAYS"], "45")
        finally:
            os.unlink(fh.name)

    def test_server_refuses_to_start_with_bad_config(self):
        env = dict(os.environ, PORT="not-a-port")
        out = subprocess.run([sys.executable, "-c", "import server"], cwd=ROOT, env=env,
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 2)
        self.assertIn("PORT", out.stderr)

    def test_every_env_example_setting_is_in_schema(self):
        with open(os.path.join(ROOT, ".env.example"), encoding="utf-8") as fh:
            keys = {line.split("=", 1)[0] for line in fh if "=" in line and not line.lstrip().startswith("#")}
        documented_elsewhere = {"MISP_URL", "MISP_API_KEY", "WAZUH_API_URL", "WAZUH_API_USER", "WAZUH_API_PASSWORD",
                                "THEHIVE_URL", "THEHIVE_API_KEY", "DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL",
                                "WINRM_USER", "WINRM_CA_BUNDLE", "PFSENSE_API_URL", "PFSENSE_API_KEY",
                                "OPENSEARCH_ADMIN_PASSWORD", "CYBERPULSE_CONFIG"}
        self.assertEqual(keys - set(SCHEMA) - documented_elsewhere, set())


if __name__ == "__main__":
    unittest.main()
