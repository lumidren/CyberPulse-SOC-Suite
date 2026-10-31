"""Every Sigma rule carries authorship and references so credit is traceable (roadmap E82)."""

import os
import re
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


class TestSigmaSpec(unittest.TestCase):
    """Local Sigma 2.0 spec checks (sigma-cli additionally runs in CI)."""

    UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
    LEVELS = {"informational", "low", "medium", "high", "critical"}
    TAG = re.compile(r"^[a-z0-9_-]+\.[a-z0-9._-]+$")

    def test_rules_follow_the_spec(self):
        problems = []
        for name, rule in sigma_rules():
            if not self.UUID.match(str(rule.get("id", ""))):
                problems.append(f"{name}: id is not a UUID")
            if rule.get("status") not in self.STATUSES:
                problems.append(f"{name}: invalid status {rule.get('status')}")
            if rule.get("level") not in self.LEVELS:
                problems.append(f"{name}: invalid level {rule.get('level')}")
            if not re.match(r"^\d{4}-\d{2}-\d{2}$", str(rule.get("date", ""))):
                problems.append(f"{name}: date must be YYYY-MM-DD")
            for tag in rule.get("tags", []):
                if not self.TAG.match(str(tag)):
                    problems.append(f"{name}: malformed tag {tag}")
            if not (rule.get("logsource") or {}).get("product") and not (rule.get("logsource") or {}).get("category"):
                problems.append(f"{name}: logsource needs product or category")
            if "condition" not in (rule.get("detection") or {}):
                problems.append(f"{name}: detection.condition missing")
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
