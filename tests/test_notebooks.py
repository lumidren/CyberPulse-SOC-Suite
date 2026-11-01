"""Hunting notebooks are valid and every code cell runs (roadmap F68)."""

import contextlib
import io
import json
import os
import sys
import unittest

os.environ.setdefault("CYBERPULSE_LAB_MODE", "true")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NB_DIR = os.path.join(ROOT, "notebooks")


class TestNotebooks(unittest.TestCase):

    def test_notebooks_are_clean_and_run(self):
        names = sorted(n for n in os.listdir(NB_DIR) if n.endswith(".ipynb"))
        self.assertGreaterEqual(len(names), 3)
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            for name in names:
                with open(os.path.join(NB_DIR, name), encoding="utf-8") as fh:
                    nb = json.load(fh)
                self.assertEqual(nb["nbformat"], 4, name)
                code = [c for c in nb["cells"] if c["cell_type"] == "code"]
                self.assertTrue(all(c["outputs"] == [] and c["execution_count"] is None for c in code),
                                f"{name}: clear outputs before committing")
                namespace = {"__name__": "__notebook__"}
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    for c in code:
                        exec(compile("".join(c["source"]), f"{name}", "exec"), namespace)  # noqa: S102
                self.assertTrue(out.getvalue(), f"{name} printed nothing")
        finally:
            os.chdir(cwd)
            sys.path[:] = [p for p in sys.path if p != ROOT] + [ROOT]


if __name__ == "__main__":
    unittest.main()
