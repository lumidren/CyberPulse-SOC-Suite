"""Static checks on the lab provisioning Vagrantfile (roadmap F89). Vagrant is not run in CI."""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestVagrantfile(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(ROOT, "deploy", "vagrant", "Vagrantfile"), encoding="utf-8") as fh:
            self.text = fh.read()

    def test_three_lab_vms_on_internal_networks(self):
        for vm in ['"ad-dc01"', '"win11-client"', '"wazuh-manager"']:
            self.assertIn(vm, self.text)
        self.assertEqual(self.text.count("virtualbox__intnet"), 3)
        self.assertNotIn("public_network", self.text)

    def test_winrm_uses_https_not_plain_http(self):
        self.assertIn("-Transport HTTPS", self.text)
        self.assertIn("5986", self.text)
        self.assertNotIn("Enable-PSRemoting", self.text)

    def test_sysmon_on_both_windows_hosts_and_credit(self):
        self.assertEqual(self.text.count("inline: WINDOWS_BASELINE"), 2)
        self.assertIn("olafhartong/sysmon-modular", self.text)


if __name__ == "__main__":
    unittest.main()
