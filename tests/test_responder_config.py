"""Responder transport and identity configuration checks (roadmap E75/E76)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.responder_config import validate_identity, validate_winrm  # noqa: E402


class TestWinRMTransport(unittest.TestCase):

    def test_https_with_verification_is_ok(self):
        result = validate_winrm({"WINRM_ENDPOINT": "https://10.0.0.10:5986/wsman", "WINRM_VERIFY_TLS": "true"})
        self.assertTrue(result["ok"], result)

    def test_plain_http_refused(self):
        result = validate_winrm({"WINRM_ENDPOINT": "http://10.0.0.10:5985/wsman"})
        self.assertFalse(result["ok"])
        self.assertIn("https", result["errors"][0])

    def test_skip_verify_refused(self):
        result = validate_winrm({"WINRM_ENDPOINT": "https://10.0.0.10:5986/wsman", "WINRM_VERIFY_TLS": "false"})
        self.assertFalse(result["ok"])
        self.assertTrue(any("certificate validation" in e for e in result["errors"]))

    def test_unconfigured_stays_simulated(self):
        result = validate_winrm({})
        self.assertFalse(result["configured"])
        self.assertTrue(result["ok"])


class TestLeastPrivilegeIdentity(unittest.TestCase):

    def test_privileged_identities_refused(self):
        for user in ["CORP\\Administrator", "administrator", "CORP\\krbtgt", "root", "CORP\\Domain Admins"]:
            self.assertFalse(validate_identity(user)["ok"], user)

    def test_dedicated_service_account_accepted(self):
        result = validate_identity("CORP\\svc_cyberpulse_soar")
        self.assertTrue(result["ok"])
        self.assertEqual(result["warnings"], [])
        self.assertTrue(validate_identity("CORP\\gmsa_soar$")["ok"])

    def test_admin_user_fails_full_winrm_check(self):
        result = validate_winrm({"WINRM_ENDPOINT": "https://10.0.0.10:5986/wsman", "WINRM_USER": "CORP\\Administrator"})
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
