"""
Sandbox submission (roadmap F47) - lab sandbox only, off by default.

Targets a self-hosted CAPE sandbox (``SANDBOX_URL``, ``SANDBOX_API_TOKEN``) through its
``/apiv2`` REST API. Public sandboxes are refused by design: a submitted file can hold
customer or employee data, and public reports are visible to anyone (including the
attacker). ``SANDBOX_URL`` must be a lab address.

What happens automatically, per incident:
  * a file hash in the event -> look up existing analyses (``/apiv2/tasks/search/sha256/``);
    nothing leaves the lab, no file is moved;
  * phishing URLs -> detonated only with ``SANDBOX_AUTO_DETONATE_URLS=true``, because
    visiting a link can tip off the sender and confirm the mailbox is live.

``submit_file`` sends a file for analysis, but only from ``SANDBOX_EVIDENCE_DIR`` (where
your EDR or the triage package drops collected samples), so the API can never be used to
read arbitrary files from the CyberPulse host.

Status: request shapes follow the CAPE v2 API documentation; tested with a stubbed HTTP
layer only, never against a running sandbox.
"""

import json
import os
import secrets
import urllib.parse
import urllib.request

from soar.enrichment import normalise_hash
from soar.thehive import lab_url


class SandboxRefused(RuntimeError):
    pass


def _http(method, url, headers, body=None, timeout=20):
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - lab_url() checked
        return resp.status, json.loads(resp.read().decode("utf-8") or "{}")


def _multipart(field, filename, content):
    boundary = "cyberpulse" + secrets.token_hex(12)
    head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode("utf-8")
    return head + content + f"\r\n--{boundary}--\r\n".encode("ascii"), f"multipart/form-data; boundary={boundary}"


class SandboxClient:
    def __init__(self, environ=os.environ, http=_http):
        self.url = environ.get("SANDBOX_URL", "").rstrip("/")
        self.token = environ.get("SANDBOX_API_TOKEN", "")
        self.evidence_dir = environ.get("SANDBOX_EVIDENCE_DIR", "")
        self.auto_urls = environ.get("SANDBOX_AUTO_DETONATE_URLS", "false").lower() == "true"
        self.enabled = bool(self.url and lab_url(self.url))
        self._http = http

    def _headers(self, extra=None):
        headers = {"Authorization": f"Token {self.token}"} if self.token else {}
        headers.update(extra or {})
        return headers

    def _require(self):
        if not self.url:
            raise SandboxRefused("SANDBOX_URL not set")
        if not lab_url(self.url):
            raise SandboxRefused("SANDBOX_URL must be a lab sandbox; public sandboxes are never used")

    def search_hash(self, value):
        self._require()
        digest = normalise_hash(value)
        if not digest or len(digest) != 64:
            raise SandboxRefused("not a SHA-256 hash")
        status, body = self._http("GET", f"{self.url}/apiv2/tasks/search/sha256/{digest}/", self._headers())
        tasks = body.get("data") or [] if status == 200 else []
        return {"status": "FOUND" if tasks else "NOT_FOUND", "task_ids": [t.get("id") for t in tasks][:10]}

    def submit_url(self, url):
        self._require()
        if not str(url).startswith(("http://", "https://")):
            raise SandboxRefused("only http(s) URLs can be detonated")
        body = urllib.parse.urlencode({"url": url}).encode("ascii")
        status, data = self._http("POST", f"{self.url}/apiv2/tasks/create/url/",
                                  self._headers({"Content-Type": "application/x-www-form-urlencoded"}), body)
        return {"status": "SUBMITTED" if status == 200 else "ERROR", "task_ids": (data.get("data") or {}).get("task_ids", [])}

    def submit_file(self, path):
        self._require()
        if not self.evidence_dir:
            raise SandboxRefused("SANDBOX_EVIDENCE_DIR not set")
        root = os.path.realpath(self.evidence_dir)
        real = os.path.realpath(path)
        if os.path.commonpath([root, real]) != root or not os.path.isfile(real):
            raise SandboxRefused("only files inside SANDBOX_EVIDENCE_DIR can be submitted")
        with open(real, "rb") as fh:
            content = fh.read(64 * 1024 * 1024 + 1)
        if len(content) > 64 * 1024 * 1024:
            raise SandboxRefused("file larger than 64 MB")
        body, ctype = _multipart("file", os.path.basename(real), content)
        status, data = self._http("POST", f"{self.url}/apiv2/tasks/create/file/", self._headers({"Content-Type": ctype}), body)
        return {"status": "SUBMITTED" if status == 200 else "ERROR", "task_ids": (data.get("data") or {}).get("task_ids", [])}

    def for_incident(self, event, phishing=None):
        """Automatic, safe-by-default sandbox steps for one incident. Never raises."""
        if not self.enabled:
            return {"status": "DISABLED"}
        out = {"status": "OK", "hash_lookups": [], "url_detonations": []}
        details = event.get("details") or {}
        try:
            for key in ("FileHash_SHA256", "Hashes", "AttachmentSha256"):
                digest = normalise_hash(details.get(key)) if details.get(key) else None
                if digest and len(digest) == 64:
                    out["hash_lookups"].append({"sha256": digest, **self.search_hash(digest)})
            if self.auto_urls:
                for url in details.get("Urls") or []:
                    out["url_detonations"].append(self.submit_url(url))
            elif details.get("Urls"):
                out["url_detonations"] = "not automatic (set SANDBOX_AUTO_DETONATE_URLS=true)"
        except Exception as exc:
            out = {"status": "ERROR", "message": f"{type(exc).__name__}: {exc}"}
        return out
