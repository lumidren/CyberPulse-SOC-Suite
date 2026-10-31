"""Legal notices required by the roadmap (E83-E88) stay in place."""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    """File text with whitespace collapsed, so wrapped sentences still match."""
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return " ".join(fh.read().split())


class TestLegalNotices(unittest.TestCase):

    def test_mitre_attack_attribution(self):
        legal = read("docs/LEGAL.md")
        self.assertIn("reproduced and distributed with the permission of The MITRE Corporation", legal)
        self.assertIn("Terms of Use", legal)
        self.assertIn("MITRE ATT&CK", read("README.md"))


    def test_trademark_disclaimer(self):
        legal = read("docs/LEGAL.md")
        for owner in ["Microsoft", "Fortinet", "pfSense", "VirusTotal"]:
            self.assertIn(owner, legal)
        self.assertIn("No endorsement is implied", legal)


if __name__ == "__main__":
    unittest.main()
