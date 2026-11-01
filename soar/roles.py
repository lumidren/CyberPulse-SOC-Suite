"""
Role-based access (roadmap F61): lead, analyst, auditor.

Each role signs in with its own key. ``CYBERPULSE_API_KEY`` is the **lead** key (full
access, as before). Optional extra keys come from ``CYBERPULSE_ROLE_KEYS``, e.g.
``analyst:<key>,auditor:<key>``; each key must be at least 24 characters.

  lead     everything: approve or reject containment, change the policy mode, release the
           kill switch, change enrichment settings, push IoCs to MISP, decide appeals.
  analyst  triage: work cases, propose actions, roll back, run hunts, engage the kill
           switch (anyone may halt automation), but no approvals, policy or sharing changes.
  auditor  read only: every GET (and is itself audit-logged), no state changes at all.

Enforcement is on the server (``allowed``); the console only hides controls a role
cannot use. Roles are recorded in the audit trail with every request.
"""

import hmac
import os
import re

ROLES = ("lead", "analyst", "auditor")
MIN_KEY_LENGTH = 24

# POST paths only a lead may call (regex on the path)
LEAD_ONLY = [
    re.compile(r"^/api/approvals/[^/]+/(approve|reject)$"),
    re.compile(r"^/api/policy/config$"),
    re.compile(r"^/api/enrichment/(config|cache/clear)$"),
    re.compile(r"^/api/cases/[^/]+/misp/push$"),
    re.compile(r"^/api/appeals/[^/]+/decide$"),
]


def parse_role_keys(lead_key, environ=os.environ):
    """[(role, key)] with the lead key first; invalid entries are reported, not used."""
    keys, problems = [("lead", lead_key)], []
    for item in environ.get("CYBERPULSE_ROLE_KEYS", "").split(","):
        role, sep, key = item.strip().partition(":")
        if not sep:
            continue
        role = role.strip().lower()
        if role not in ROLES:
            problems.append(f"unknown role {role!r}")
        elif len(key.strip()) < MIN_KEY_LENGTH:
            problems.append(f"{role} key shorter than {MIN_KEY_LENGTH} characters")
        elif any(hmac.compare_digest(key.strip(), k) for _, k in keys):
            problems.append(f"{role} key reuses another role's key")
        else:
            keys.append((role, key.strip()))
    return keys, problems


def role_for_key(token, role_keys):
    """Role whose key matches (constant-time per key), or None."""
    token = (token or "").encode("utf-8")
    found = None
    for role, key in role_keys:
        if hmac.compare_digest(token, key.encode("utf-8")) and found is None:
            found = role
    return found


def allowed(role, method, path, body=None):
    """Whether `role` may make this request. GETs are open to every signed-in role."""
    if role == "lead":
        return True
    if method == "GET":
        return role in ("analyst", "auditor")
    if role == "auditor":
        return path == "/api/session/logout"
    if role == "analyst":
        if any(p.match(path) for p in LEAD_ONLY):
            return False
        if path == "/api/safety/kill-switch" and not bool((body or {}).get("engaged", True)):
            return False  # anyone may halt automation; only a lead may resume it
        return True
    return False
