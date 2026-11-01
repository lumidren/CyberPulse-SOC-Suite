"""Weighted multi-source reputation consensus (roadmap F42)."""

import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.reputation import UNCORROBORATED_WEIGHT, consensus, weights  # noqa: E402


def v(source, score, flags):
    return {"source": source, "score": score, "flags": flags, "fetched_at": "t", "attribution": "a"}


def intel(*verdicts):
    return {"external": {"ip": {"verdicts": list(verdicts)}}}


class TestWeightedConsensus(unittest.TestCase):

    def test_all_flagging_equals_weighted_mean(self):
        r = consensus(intel(v("URLhaus", 70.0, True), v("AlienVault OTX", 100.0, True)))
        self.assertEqual(r["agreement"], 1.0)
        self.assertAlmostEqual(r["raw_score"], (70 * 1.0 + 100 * 0.6) / 1.6, places=1)
        self.assertEqual(r["score"], r["raw_score"])

    def test_dissent_dilutes(self):
        agree = consensus(intel(v("URLhaus", 80.0, True), v("GreyNoise", 80.0, True)))
        dissent = consensus(intel(v("URLhaus", 80.0, True), v("GreyNoise", 80.0, True),
                                  v("AlienVault OTX", 0.0, False)))
        self.assertLess(dissent["score"], agree["score"])
        self.assertAlmostEqual(dissent["agreement"], 1.8 / 2.4, places=3)

    def test_lone_source_is_uncorroborated(self):
        r = consensus(intel(v("URLhaus", 80.0, True)))
        self.assertFalse(r["corroborated"])
        self.assertEqual(r["score"], round(80.0 * UNCORROBORATED_WEIGHT, 1))

    def test_weights_are_configurable_and_zero_mutes_a_source(self):
        with mock.patch.dict(os.environ, {"REPUTATION_WEIGHTS": "AlienVault OTX=0,GreyNoise=bogus"}):
            self.assertEqual(weights()["AlienVault OTX"], 0.0)
            self.assertEqual(weights()["GreyNoise"], 0.8, "invalid values keep the default")
            r = consensus(intel(v("URLhaus", 80.0, True), v("AlienVault OTX", 100.0, True)))
        self.assertEqual(r["flagging_sources"], ["URLhaus"])
        self.assertFalse(r["corroborated"])

    def test_every_source_reports_its_weight(self):
        r = consensus(intel(v("URLhaus", 80.0, True), v("GreyNoise", 0.0, False)))
        self.assertEqual({s["source"]: s["weight"] for s in r["sources"]}, {"URLhaus": 1.0, "GreyNoise": 0.8})


if __name__ == "__main__":
    unittest.main()
