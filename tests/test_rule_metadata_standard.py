"""Detection rule metadata standard (rules/METADATA_STANDARD.md, roadmap F6)."""

import os
import re
import unittest

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA_DIR = os.path.join(ROOT, "rules", "sigma")
REQUIRED = ["title", "id", "status", "description", "references", "author", "date", "modified",
            "tags", "logsource", "detection", "falsepositives", "level"]
VAGUE_FP = re.compile(r"^(unknown|none|n/a|-)$", re.I)


def rules():
    for name in sorted(os.listdir(SIGMA_DIR)):
        if name.endswith(".yml"):
            with open(os.path.join(SIGMA_DIR, name), encoding="utf-8") as fh:
                yield name, yaml.safe_load(fh)


class TestRuleMetadataStandard(unittest.TestCase):

    def test_required_fields_present_and_meaningful(self):
        problems = []
        titles = set()
        for name, r in rules():
            for field in REQUIRED:
                if not r.get(field):
                    problems.append(f"{name}: missing {field}")
            if len(str(r.get("description", ""))) < 40:
                problems.append(f"{name}: description too short")
            if r.get("level") not in {"low", "medium", "high", "critical"}:
                problems.append(f"{name}: level must express severity")
            if not any(re.match(r"^attack\.t\d{4}", str(t)) for t in r.get("tags", [])):
                problems.append(f"{name}: needs an ATT&CK technique tag")
            if any(VAGUE_FP.match(str(fp).strip()) for fp in r.get("falsepositives", [])):
                problems.append(f"{name}: false-positive notes must be concrete")
            if str(r.get("modified", "")) < str(r.get("date", "")):
                problems.append(f"{name}: modified earlier than date")
            if r.get("title") in titles:
                problems.append(f"{name}: duplicate title")
            titles.add(r.get("title"))
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
