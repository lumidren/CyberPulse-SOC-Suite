"""Detection regression corpus: rule changes must not silently change old results (roadmap F27)."""

import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from scripts.regression_corpus import corpus, current, diff, evaluate, load_golden  # noqa: E402
from soar.sigma_engine import SigmaEngine  # noqa: E402


class TestRegressionCorpus(unittest.TestCase):

    def test_results_match_golden_file(self):
        changes = diff(load_golden(), current())
        detail = "\n".join(f"{k}: was {o} now {n}" for k, o, n in changes[:20])
        self.assertEqual(changes, [], "detection results changed; if intended run "
                                      "`python scripts/regression_corpus.py --accept` and commit the diff\n" + detail)

    def test_positive_samples_still_match_their_own_rule(self):
        # Hard rule, independent of the golden file: accepting cannot make a rule miss its own attack
        soc_by_file = {os.path.basename(r.file): r.soar.get("soc_rule_id") for r in SigmaEngine().rules}
        for key, event, kind, owner in corpus():
            expected = soc_by_file.get(owner, owner)
            if kind in ("positive", "generator"):
                self.assertIn(expected, evaluate(event)["all"], key)


if __name__ == "__main__":
    unittest.main()
