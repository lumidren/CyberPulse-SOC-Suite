"""Live endpoint queries via osquery (Fleet) and Velociraptor (roadmap F71)."""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from soar.live_query import LiveQueryClient, LiveQueryRefused, osquery_catalogue, velociraptor_catalogue  # noqa: E402

ENV = {"FLEET_URL": "https://fleet.lab:8080", "FLEET_API_TOKEN": "t", "VELOCIRAPTOR_URL": "https://10.0.1.60:8889",
       "VELOCIRAPTOR_API_TOKEN": "v"}


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, url, token, payload, timeout=15):
        self.calls.append((url, payload))
        return {"campaign": {"id": 7}, "flow_id": "H.123"}


class TestLiveQuery(unittest.TestCase):

    def test_catalogues_are_reviewed_read_only_queries(self):
        osq = osquery_catalogue()
        self.assertEqual(sorted(osq), ["osq-1", "osq-2", "osq-3", "osq-4", "osq-5"])
        for entry in osq.values():
            self.assertTrue(entry["sql"].lower().startswith("select"))
        self.assertIn("Windows.Detection.LsassMemoryAccess", velociraptor_catalogue())

    def test_only_catalogue_queries_run_against_lab_servers(self):
        rec = Recorder()
        client = LiveQueryClient(environ=ENV, post=rec)
        result = client.run_osquery("osq-1", [3, "4"])
        self.assertEqual((result["status"], result["campaign_id"]), ("SUBMITTED", 7))
        self.assertEqual(rec.calls[0][1]["selected"], {"hosts": [3, 4]})
        self.assertTrue(rec.calls[0][1]["query"].startswith("SELECT"))
        with self.assertRaises(LiveQueryRefused):
            client.run_osquery("DROP TABLE x", [1])
        with self.assertRaises(LiveQueryRefused):
            LiveQueryClient(environ=dict(ENV, FLEET_URL="https://fleet.example.com"), post=rec).run_osquery("osq-1", [1])
        with self.assertRaises(LiveQueryRefused):
            LiveQueryClient(environ={}, post=rec).run_osquery("osq-1", [1])

    def test_velociraptor_hunt(self):
        rec = Recorder()
        client = LiveQueryClient(environ=ENV, post=rec)
        result = client.run_velociraptor("Windows.Detection.LsassMemoryAccess", ["C.0123456789abcdef", "bad"])
        self.assertEqual(result["hunt_id"], "H.123")
        self.assertEqual(rec.calls[0][1]["condition"]["clients"]["client_ids"], ["C.0123456789abcdef"])
        with self.assertRaises(LiveQueryRefused):
            client.run_velociraptor("Custom.Anything", ["C.0123456789abcdef"])


if __name__ == "__main__":
    unittest.main()
