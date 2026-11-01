"""
Live endpoint queries through osquery (Fleet) or Velociraptor (roadmap F71) - off by default.

Analysts can run **only the reviewed queries in this repository**, never free-form SQL or
VQL, against lab hosts:

  * osquery queries come from rules/osquery/hunting_queries.sql, one per numbered
    ``-- N. Title (T1234)`` block, and run as Fleet live queries
    (``POST {FLEET_URL}/api/v1/fleet/queries/run`` with ``FLEET_API_TOKEN``);
  * Velociraptor artifacts come from rules/velociraptor/*.yaml and are started as hunts
    (``POST {VELOCIRAPTOR_URL}/api/v1/CreateHunt`` with ``VELOCIRAPTOR_API_TOKEN`` through
    a REST gateway you run in front of Velociraptor's gRPC API).

Both URLs must be lab addresses. Every query is read-only by construction (SELECT
statements / CLIENT artifacts that only collect), and every run is audit-logged by the
server. Results stay in Fleet/Velociraptor; CyberPulse records the request id.

Status: request shapes follow the Fleet REST and Velociraptor API documentation; tested with a
stubbed HTTP layer only, never against a running Fleet or Velociraptor server.
"""

import glob
import json
import os
import re
import urllib.request

import yaml

from soar.sigma_engine import ROOT
from soar.thehive import lab_url

OSQUERY_FILE = os.path.join(ROOT, "rules", "osquery", "hunting_queries.sql")
VELOCIRAPTOR_DIR = os.path.join(ROOT, "rules", "velociraptor")
QUERY_HEADER_RE = re.compile(r"^--\s*(\d+)\.\s*(.+?)\s*\(([^)]*)\)\s*$", re.M)
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
FORBIDDEN_SQL = re.compile(r"\b(insert|update|delete|drop|alter|attach|create|pragma)\b", re.I)


class LiveQueryRefused(RuntimeError):
    pass


def osquery_catalogue(path=OSQUERY_FILE):
    """{"osq-N": {"title", "technique", "sql"}} parsed from the reviewed query file."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    headers = list(QUERY_HEADER_RE.finditer(text))
    catalogue = {}
    for i, h in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        sql = text[h.end():end].strip()
        sql = sql[:sql.index(";") + 1] if ";" in sql else sql
        if not sql.lower().lstrip().startswith("select") or FORBIDDEN_SQL.search(sql):
            raise LiveQueryRefused(f"query {h.group(1)} is not a read-only SELECT")
        technique = TECHNIQUE_RE.search(h.group(3))
        catalogue[f"osq-{h.group(1)}"] = {"title": h.group(2), "technique": technique.group(0) if technique else None,
                                         "sql": sql}
    numbered = re.findall(r"^--\s*(\d+)\.", text, re.M)
    if len(numbered) != len(catalogue):
        raise LiveQueryRefused("a numbered query in hunting_queries.sql has no '(technique)' header and would be skipped")
    return catalogue


def velociraptor_catalogue(directory=VELOCIRAPTOR_DIR):
    catalogue = {}
    for path in sorted(glob.glob(os.path.join(directory, "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if doc.get("type", "CLIENT") != "CLIENT":
            raise LiveQueryRefused(f"{doc.get('name')}: only CLIENT collection artifacts are allowed")
        catalogue[doc["name"]] = {"title": doc.get("description", "").strip().split("\n")[0],
                                  "references": doc.get("reference", [])}
    return catalogue


def _post(url, token, payload, timeout=15):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - lab_url() checked
        return json.loads(resp.read().decode("utf-8") or "{}")


class LiveQueryClient:
    def __init__(self, environ=os.environ, post=_post):
        self.fleet_url = environ.get("FLEET_URL", "").rstrip("/")
        self.fleet_token = environ.get("FLEET_API_TOKEN", "")
        self.velo_url = environ.get("VELOCIRAPTOR_URL", "").rstrip("/")
        self.velo_token = environ.get("VELOCIRAPTOR_API_TOKEN", "")
        self._post = post

    def run_osquery(self, query_id, host_ids):
        catalogue = osquery_catalogue()
        if query_id not in catalogue:
            raise LiveQueryRefused(f"unknown query {query_id!r}; only reviewed queries can run")
        if not (self.fleet_url and self.fleet_token):
            raise LiveQueryRefused("set FLEET_URL and FLEET_API_TOKEN")
        if not lab_url(self.fleet_url):
            raise LiveQueryRefused("FLEET_URL must be a lab address")
        hosts = [int(h) for h in host_ids][:100]
        if not hosts:
            raise LiveQueryRefused("name at least one Fleet host id")
        answer = self._post(f"{self.fleet_url}/api/v1/fleet/queries/run", self.fleet_token,
                            {"query": catalogue[query_id]["sql"], "selected": {"hosts": hosts}})
        return {"status": "SUBMITTED", "engine": "osquery/fleet", "query_id": query_id,
                "campaign_id": (answer.get("campaign") or {}).get("id")}

    def run_velociraptor(self, artifact, client_ids):
        if artifact not in velociraptor_catalogue():
            raise LiveQueryRefused(f"unknown artifact {artifact!r}; only reviewed artifacts can run")
        if not (self.velo_url and self.velo_token):
            raise LiveQueryRefused("set VELOCIRAPTOR_URL and VELOCIRAPTOR_API_TOKEN")
        if not lab_url(self.velo_url):
            raise LiveQueryRefused("VELOCIRAPTOR_URL must be a lab address")
        clients = [str(c) for c in client_ids if re.fullmatch(r"C\.[0-9a-f]{16}", str(c))][:100]
        if not clients:
            raise LiveQueryRefused("name at least one Velociraptor client id (C.xxxxxxxxxxxxxxxx)")
        answer = self._post(f"{self.velo_url}/api/v1/CreateHunt", self.velo_token,
                            {"hunt_description": f"CyberPulse: {artifact}",
                             "start_request": {"artifacts": [artifact]},
                             "condition": {"clients": {"client_ids": clients}}})
        return {"status": "SUBMITTED", "engine": "velociraptor", "artifact": artifact, "hunt_id": answer.get("flow_id") or answer.get("hunt_id")}
