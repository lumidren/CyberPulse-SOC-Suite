"""ATT&CK Navigator coverage layer (roadmap F9)."""

import json
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.export_navigator import LAYER_PATH, build_layer, render  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402


class TestNavigatorLayer(unittest.TestCase):

    def test_layer_structure(self):
        layer = build_layer()
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["layer"], "4.5")
        for t in layer["techniques"]:
            self.assertRegex(t["techniqueID"], r"^T\d{4}(\.\d{3})?$")
            self.assertGreaterEqual(t["score"], 1)

    def test_every_rule_technique_is_on_the_layer(self):
        on_layer = {t["techniqueID"] for t in build_layer()["techniques"]}
        tagged = {tid for r in SigmaEngine().rules for tid in r.technique_ids}
        self.assertEqual(tagged - on_layer, set())

    def test_committed_layer_is_current(self):
        with open(LAYER_PATH, encoding="utf-8") as fh:
            committed = fh.read().replace("\r\n", "\n")
        self.assertEqual(committed, render(), "run: python scripts/export_navigator.py")
        self.assertTrue(json.loads(committed))
        self.assertTrue(re.search(r"synthetic", committed))


if __name__ == "__main__":
    unittest.main()
