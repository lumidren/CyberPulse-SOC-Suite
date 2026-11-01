"""
Triage package per incident (roadmap F49): everything an analyst or IR firm needs to
start on an incident, in one zip with a SHA-256 manifest.

Contents:
  README.txt          what is inside and what is not
  incident.json       the incident record (third-party intel payloads stripped, per provider terms)
  telemetry.json      the triggering event, redacted (secrets, tokens) as stored
  timeline.json       pipeline and analyst timeline
  evidence.json       volatile evidence collected before any containment
  response.json       policy decision and every proposed/executed action
  case.json           the case the incident belongs to, if any
  tasks.md            the playbook checklist
  manifest.json       SHA-256 and size of every file above

Account names are masked when masking is on (PRIVACY_MASK_USERNAMES, default true).
Packages are built on request (``GET /api/incidents/<id>/triage-package``) and, if
``TRIAGE_PACKAGE_DIR`` is set, written there automatically for every new incident. That
directory holds incident data: keep it outside the repository and access-controlled.
"""

import hashlib
import io
import json
import os
import re
import zipfile
from datetime import datetime, timezone

from soar.enrichment import strip_provider_data
from soar.privacy import mask_identities, masking_enabled

FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)  # stable member timestamps so identical content hashes identically


def _json(obj):
    return json.dumps(obj, indent=2, sort_keys=True, default=str).encode("utf-8")


def package_files(incident, case=None, custody=None):
    """{filename: bytes} for the package, before zipping."""
    inc = strip_provider_data(incident)
    if masking_enabled():
        inc = mask_identities(inc)
        case = mask_identities(case) if case else case
    tasks = (inc.get("playbook") or {}).get("tasks") or []
    files = {
        "incident.json": _json(inc),
        "telemetry.json": _json(inc.get("telemetry")),
        "timeline.json": _json(inc.get("timeline")),
        "evidence.json": _json(inc.get("evidence_package")),
        "response.json": _json({"policy_decision": inc.get("policy_decision"),
                                "containment_action": inc.get("containment_action"),
                                "proposed_actions": inc.get("proposed_actions", [])}),
        "case.json": _json(case),
        "custody.json": _json(custody or []),
        "tasks.md": ("# Playbook tasks\n\n" + "".join(f"- [ ] {t['title']}\n" for t in tasks)).encode("utf-8"),
        "README.txt": (
            f"CyberPulse triage package for {inc.get('incident_id')}\n"
            f"Built {datetime.now(timezone.utc).isoformat()}\n\n"
            "Synthetic lab data unless incident.json says simulated=false.\n"
            "Third-party threat-intel payloads are removed (provider terms); account names are masked\n"
            "when PRIVACY_MASK_USERNAMES is on. Verify integrity with manifest.json (SHA-256 per file).\n"
            "This package contains telemetry, not disk or memory images.\n").encode("utf-8"),
    }
    files["manifest.json"] = _json({name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                                    for name, data in sorted(files.items())})
    return files


def build_zip(incident, case=None, custody=None):
    """(zip bytes, sha256 of the zip, manifest dict)."""
    files = package_files(incident, case, custody)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, files[name])
    data = buffer.getvalue()
    return data, hashlib.sha256(data).hexdigest(), json.loads(files["manifest.json"])


def verify_zip(data):
    """Re-hash every member against manifest.json. Returns a list of problems (empty = intact)."""
    problems = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        for name, entry in manifest.items():
            try:
                digest = hashlib.sha256(zf.read(name)).hexdigest()
            except KeyError:
                problems.append(f"{name}: missing")
                continue
            if digest != entry["sha256"]:
                problems.append(f"{name}: hash mismatch")
    return problems


def write_automatic(incident, case=None, directory=None):
    """Write the package to TRIAGE_PACKAGE_DIR if set. Never raises; returns a status dict."""
    directory = directory if directory is not None else os.environ.get("TRIAGE_PACKAGE_DIR", "")
    if not directory:
        return {"status": "DISABLED"}
    try:
        data, digest, _ = build_zip(incident, case)
        os.makedirs(directory, exist_ok=True)
        safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", str(incident.get("incident_id")))
        path = os.path.join(directory, f"{safe_id}.zip")
        with open(path, "wb") as fh:
            fh.write(data)
        return {"status": "WRITTEN", "file": os.path.basename(path), "sha256": digest}
    except Exception as exc:
        return {"status": "ERROR", "message": f"{type(exc).__name__}: {exc}"}
