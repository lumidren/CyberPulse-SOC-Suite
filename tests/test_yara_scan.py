"""YARA scanning of collected evidence (roadmap F70)."""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.yara_scan import BuiltinRule, YaraUnsupported, load_rules, scan_bytes, scan_evidence_file  # noqa: E402

NOTE = b"Your personal files are encrypted. Read HOW_TO_DECRYPT.txt"


class TestYaraScan(unittest.TestCase):

    def test_shipped_rules_load_and_match_ascii_and_wide(self):
        engine = load_rules()
        if engine[0] == "builtin":
            self.assertEqual(len(engine[1]), 3)
        self.assertEqual([m["rule"] for m in scan_bytes(NOTE, engine)], ["Detect_Ransomware_Canary_Note"])
        wide = NOTE.decode().encode("utf-16-le")
        self.assertEqual([m["rule"] for m in scan_bytes(wide, engine)], ["Detect_Ransomware_Canary_Note"])
        self.assertEqual(scan_bytes(b"quarterly report", engine), [])
        self.assertEqual(scan_bytes(b"Your personal files are encrypted", engine), [], "one string is below '2 of'")

    def test_builtin_conditions_and_refusals(self):
        body = '\n    strings:\n        $a = "alpha"\n        $b = { 41 42 43 }\n    condition:\n        $a and $b'
        rule = BuiltinRule("t", body)
        self.assertTrue(rule.matches(b"xx alpha yy ABC")[0])
        self.assertFalse(rule.matches(b"alpha only")[0])
        with self.assertRaises(YaraUnsupported):
            BuiltinRule("t", '\n    strings:\n        $a = "x" xor\n    condition:\n        $a')
        with self.assertRaises(YaraUnsupported):
            BuiltinRule("t", '\n    strings:\n        $a = "x"\n    condition:\n        $a at 0')

    def test_scans_only_inside_the_evidence_folder(self):
        with tempfile.TemporaryDirectory() as evidence, tempfile.NamedTemporaryFile(delete=False) as outside:
            with open(os.path.join(evidence, "note.txt"), "wb") as fh:
                fh.write(NOTE)
            ok = scan_evidence_file("note.txt", evidence_dir=evidence)
            self.assertEqual((ok["status"], [m["rule"] for m in ok["matches"]]), ("OK", ["Detect_Ransomware_Canary_Note"]))
            for bad in (outside.name, "../" + os.path.basename(outside.name), "missing.bin"):
                self.assertEqual(scan_evidence_file(bad, evidence_dir=evidence)["status"], "REFUSED")
        os.unlink(outside.name)
        self.assertEqual(scan_evidence_file("x", evidence_dir="")["status"], "DISABLED")


if __name__ == "__main__":
    unittest.main()
