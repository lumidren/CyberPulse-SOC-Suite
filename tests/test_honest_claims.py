"""
Honest-Claims Guard for the CyberPulse SOC Lab

Fails the build if user-facing text reintroduces marketing or efficacy claims
that the project cannot back with a reproducible script. Each banned pattern
names the roadmap item that removed it.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCANNED_EXTENSIONS = (".md", ".py", ".html", ".js", ".json", ".yml", ".yaml")
EXCLUDED_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules"}
EXCLUDED_FILES = {
    os.path.join("docs", "ROADMAP.md"),          # quotes the banned phrases as roadmap items
    os.path.join("tests", "test_honest_claims.py"),
    "CHANGELOG.md",                              # history may quote removed wording
}

# (roadmap id, compiled pattern, explanation)
BANNED_CLAIMS = [
    ("E1", re.compile(r"enterprise[- ]grade", re.I), "It's a lab, not an enterprise-grade product."),
    ("E1", re.compile(r"\bENTERPRISE SOC\b|Enterprise (SOC|Operations) Platform", re.I),
     "Lab console must not be branded as an enterprise platform."),
    ("E2", re.compile(r"~3\.2s|3\.18 seconds|\b1\.40s\b|\b3\.28s\b|Simulated Benchmark"),
     "Latency figures must come from scripts/benchmark_pipeline.py, not hardcoded values."),
    ("E3", re.compile(r"\b0\s?% false[- ]positive|zero false[- ]positive", re.I),
     "State FP results as 'N false positives in M baseline events' (docs/VALIDATION_RESULTS.md)."),
    ("E4", re.compile(r"100% True-Positive|VALIDATED_100%", re.I),
     "Self-authored attack runs are a regression check; report 'X/Y scripted runs detected'."),
    ("E6", re.compile(r"15\s?[-–]\s?25\s?min", re.I),
     "Uncited manual-analyst benchmark; remove it or cite a source."),
    ("E7", re.compile(r"analyst_baseline|Manual Baseline", re.I),
     "Automated in-process seconds are not comparable to a human triage cycle."),
    ("E9", re.compile(r"production[- ]ready|^status:\s*production\b|Final Production Rule", re.I),
     "Rules are only tested on synthetic events; don't call them production-ready."),
]


def iter_scanned_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for name in filenames:
            if not name.endswith(SCANNED_EXTENSIONS):
                continue
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ROOT)
            if rel in EXCLUDED_FILES:
                continue
            yield rel, path


class TestHonestClaims(unittest.TestCase):

    def test_no_banned_claims(self):
        violations = []
        for rel, path in iter_scanned_files():
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, start=1):
                    for item_id, pattern, why in BANNED_CLAIMS:
                        if pattern.search(line):
                            violations.append(f"{rel}:{lineno} [{item_id}] {why} -> {line.strip()[:100]}")
        self.assertEqual(violations, [], "Banned claims found:\n" + "\n".join(violations))


class TestBenchmarkScript(unittest.TestCase):

    def test_benchmark_runs_and_labels_results(self):
        """The benchmark backing README latency numbers must run and label its basis"""
        import sys
        sys.path.insert(0, ROOT)
        from scripts.benchmark_pipeline import run_benchmark
        result = run_benchmark(runs=1)
        self.assertIn("Lab-measured", result["basis"])
        self.assertEqual(result["events_attempted"], result["events_detected"])
        self.assertIn("total_us", result["latency_us"])


if __name__ == "__main__":
    unittest.main()
