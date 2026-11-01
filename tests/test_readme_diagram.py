"""The README architecture diagram stays renderable (roadmap F80)."""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestReadmeDiagram(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            self.readme = fh.read()
        self.blocks = re.findall(r"```mermaid\n(.*?)\n```", self.readme, re.S)

    def test_one_flowchart_with_quoted_labels(self):
        self.assertEqual(len(self.blocks), 1)
        body = self.blocks[0]
        self.assertTrue(body.startswith("flowchart "))
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("subgraph "):
                self.assertRegex(line, r'^subgraph \w+\["[^"]+"\]$', "subgraph needs an id and a quoted title")
            for label in re.findall(r"\w+\[([^\]]*)\]", line):
                self.assertTrue(label.startswith('"') and label.endswith('"'), f"unquoted label: {label}")

    def test_every_edge_points_at_a_defined_node(self):
        body = self.blocks[0]
        defined = set(re.findall(r"(\w+)\[\"", body))
        used = set(re.findall(r"(?:-->|-\.->)\s*(\w+)", body)) | set(re.findall(r"^\s*(\w+)\s*(?:-->|-\.->)", body, re.M))
        self.assertEqual(used - defined, set())


if __name__ == "__main__":
    unittest.main()
