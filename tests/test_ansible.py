"""Static checks on the Ansible roles for Sysmon and the Wazuh agent (roadmap F90).

Ansible is not run in CI; these tests check the files parse and keep their safety properties.
"""

import os
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy", "ansible")


def load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


class TestAnsibleRoles(unittest.TestCase):

    def test_playbook_applies_both_roles(self):
        play = load("site.yml")[0]
        self.assertEqual([r["role"] for r in play["roles"]], ["sysmon", "wazuh_agent"])

    def test_downloads_are_checksum_pinned(self):
        for role in ("sysmon", "wazuh_agent"):
            tasks = load(f"roles/{role}/tasks/main.yml")
            self.assertIn("ansible.builtin.assert", tasks[0])          # refuses to run without a checksum
            downloads = [t for t in tasks if "ansible.windows.win_get_url" in t]
            self.assertTrue(downloads)
            for t in downloads:
                self.assertEqual(t["ansible.windows.win_get_url"]["checksum_algorithm"], "sha256")

    def test_inventory_uses_validated_winrm_https(self):
        inv = load("inventory.example.yml")["lab_windows"]["vars"]
        self.assertEqual(inv["ansible_winrm_scheme"], "https")
        self.assertEqual(inv["ansible_winrm_server_cert_validation"], "validate")
        self.assertIn("vault", inv["ansible_password"])


if __name__ == "__main__":
    unittest.main()
