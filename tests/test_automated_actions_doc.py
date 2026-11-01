"""Every automated action is documented with its failure mode (roadmap E93)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.document_actions import CONTAINMENT, REPORT, render  # noqa: E402
from soar.action_tiers import ACTION_TIERS  # noqa: E402


class TestAutomatedActionsDoc(unittest.TestCase):

    def test_every_action_has_description_and_failure_mode(self):
        self.assertEqual(set(ACTION_TIERS) - set(CONTAINMENT), set(), "add the action to scripts/document_actions.py")
        for action, (what, failure) in CONTAINMENT.items():
            self.assertTrue(what and failure, action)

    def test_committed_doc_is_current(self):
        with open(REPORT, encoding="utf-8") as fh:
            self.assertEqual(fh.read().replace("\r\n", "\n"), render(), "run: python scripts/document_actions.py")


if __name__ == "__main__":
    unittest.main()
