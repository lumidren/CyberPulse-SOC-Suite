"""Lab sandbox submission (roadmap F47)."""

import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.sandbox import SandboxClient, SandboxRefused  # noqa: E402

SHA = "d" * 64


class FakeCape:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers, body=None, timeout=20):
        self.calls.append((method, url, headers, body))
        if "/search/sha256/" in url:
            return 200, {"data": [{"id": 41}]}
        return 200, {"data": {"task_ids": [42]}}


class TestSandbox(unittest.TestCase):

    def test_public_sandboxes_refused(self):
        client = SandboxClient(environ={"SANDBOX_URL": "https://sandbox.example.com"}, http=FakeCape())
        self.assertFalse(client.enabled)
        with self.assertRaises(SandboxRefused):
            client.search_hash(SHA)
        self.assertEqual(client.for_incident({"details": {"FileHash_SHA256": SHA}}), {"status": "DISABLED"})

    def test_hash_lookup_automatic_url_detonation_opt_in(self):
        cape = FakeCape()
        env = {"SANDBOX_URL": "http://10.0.1.50:8000", "SANDBOX_API_TOKEN": "t"}
        event = {"details": {"FileHash_SHA256": SHA, "Urls": ["http://evil.example/x"]}}
        result = SandboxClient(environ=env, http=cape).for_incident(event)
        self.assertEqual(result["hash_lookups"][0]["task_ids"], [41])
        self.assertIn("not automatic", result["url_detonations"])
        self.assertTrue(all("/create/url/" not in c[1] for c in cape.calls))
        self.assertEqual(cape.calls[0][2]["Authorization"], "Token t")
        result = SandboxClient(environ=dict(env, SANDBOX_AUTO_DETONATE_URLS="true"), http=cape).for_incident(event)
        self.assertEqual(result["url_detonations"][0]["task_ids"], [42])

    def test_file_submission_only_from_evidence_dir(self):
        cape = FakeCape()
        with tempfile.TemporaryDirectory() as evidence, tempfile.NamedTemporaryFile(delete=False) as outside:
            outside.write(b"x")
            sample = os.path.join(evidence, "sample.bin")
            with open(sample, "wb") as fh:
                fh.write(b"MZ-inert-test-bytes")
            client = SandboxClient(environ={"SANDBOX_URL": "http://sandbox.lab", "SANDBOX_EVIDENCE_DIR": evidence}, http=cape)
            self.assertEqual(client.submit_file(sample)["task_ids"], [42])
            self.assertIn(b"MZ-inert-test-bytes", cape.calls[-1][3])
            for bad in (outside.name, os.path.join(evidence, "..", os.path.basename(outside.name))):
                with self.assertRaises(SandboxRefused):
                    client.submit_file(bad)
        os.unlink(outside.name)

    def test_errors_are_contained(self):
        def boom(*a, **k):
            raise ConnectionError("sandbox down")
        result = SandboxClient(environ={"SANDBOX_URL": "http://10.0.1.50"}, http=boom).for_incident(
            {"details": {"FileHash_SHA256": SHA}})
        self.assertEqual(result["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
