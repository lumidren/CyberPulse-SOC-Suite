"""Every Sigma rule carries authorship and references so credit is traceable (roadmap E82)."""

import os
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA_DIR = os.path.join(ROOT, "rules", "sigma")


def sigma_rules():
    for name in sorted(os.listdir(SIGMA_DIR)):
        if name.endswith(".yml"):
            with open(os.path.join(SIGMA_DIR, name), encoding="utf-8") as fh:
                yield name, yaml.safe_load(fh)


class TestSigmaProvenance(unittest.TestCase):

    def test_every_rule_has_author_and_reference(self):
        for name, rule in sigma_rules():
            self.assertTrue(rule.get("author"), f"{name}: missing author")
            refs = rule.get("references") or []
            self.assertTrue(any(str(r).startswith("https://") for r in refs), f"{name}: no reference URL")

    def test_provenance_readme_present(self):
        with open(os.path.join(SIGMA_DIR, "README.md"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("SigmaHQ", text)
        self.assertIn("DRL", text)


if __name__ == "__main__":
    unittest.main()
