"""Every Sigma rule is unit-tested with positive and negative samples (roadmap F3).

Samples live in rules/tests/<rule file>.yml. A positive sample must be matched by
its rule; a negative sample (benign look-alikes, documented exclusions) must not.
"""

import os
import sys
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.sigma_engine import SigmaEngine  # noqa: E402

SAMPLES_DIR = os.path.join(ROOT, "rules", "tests")


class TestRuleSamples(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rules = {os.path.basename(r.file): r for r in SigmaEngine().rules}

    def test_every_rule_has_positive_and_negative_samples(self):
        missing = []
        for name in self.rules:
            path = os.path.join(SAMPLES_DIR, name)
            if not os.path.exists(path):
                missing.append(name)
                continue
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            if not doc.get("positive") or not doc.get("negative"):
                missing.append(name)
        self.assertEqual(missing, [], "rules without positive+negative samples")

    def test_samples_behave_as_labelled(self):
        failures = []
        for name in sorted(os.listdir(SAMPLES_DIR)):
            if not name.endswith(".yml"):
                continue
            with open(os.path.join(SAMPLES_DIR, name), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            rule = self.rules.get(doc["rule"])
            if rule is None:
                failures.append(f"{name}: no rule {doc['rule']}")
                continue
            for case in doc.get("positive", []):
                if not rule.matches(case["event"]):
                    failures.append(f"{doc['rule']}: positive not matched: {case['name']}")
            for case in doc.get("negative", []):
                if rule.matches(case["event"]):
                    failures.append(f"{doc['rule']}: negative matched: {case['name']}")
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
