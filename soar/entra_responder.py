"""
Live Microsoft Entra ID responder (roadmap F44) - off by default; simulated otherwise.

Implements ``REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA`` against Microsoft Graph:

  1. ``POST /users/{upn}/revokeSignInSessions`` - every refresh token and session cookie
     of the account is invalidated, so the attacker (and the user) must sign in again;
  2. MFA step-up: the account is added to ``ENTRA_STEPUP_GROUP_ID``, a group that *your*
     Conditional Access policy targets with "require MFA" (or "require password change").
     Graph cannot "force MFA" on its own; the CA policy does that. Without the group id,
     only step 1 runs.

Rollback removes the account from the step-up group. Revoked sessions cannot be
restored (the action is PARTIAL in the rollback playbooks).

Configuration (app registration with client credentials, application permissions
``User.RevokeSessions.All`` and ``GroupMember.ReadWrite.All``, admin-consented, nothing
broader): ``ENTRA_RESPONDER_ENABLED=true``, ``ENTRA_TENANT_ID``, ``ENTRA_CLIENT_ID``,
``ENTRA_CLIENT_SECRET``, optional ``ENTRA_STEPUP_GROUP_ID``.

The account's UPN goes only to Microsoft Graph for the tenant that already holds the
account, which is the system of record being acted on; nothing else is sent. The action
is TIER_3_IDENTITY, so it only ever runs after analyst approval, and protected accounts
are refused before it is reached.

Status: request sequence follows the Graph v1.0 documentation; tested with a stubbed
HTTP layer only, never against a tenant.
"""

import json
import os
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional, Tuple

from soar.command_builder import valid_upn

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"

Http = Callable[[str, str, Dict[str, str], Optional[bytes]], Tuple[int, Dict[str, Any]]]


def _http(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, Dict[str, Any]]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310 - fixed https Microsoft endpoints
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        return exc.code, {}


class EntraResponder:
    def __init__(self, environ: Any = os.environ, http: Http = _http) -> None:
        self.tenant = environ.get("ENTRA_TENANT_ID", "")
        self.client_id = environ.get("ENTRA_CLIENT_ID", "")
        self.secret = environ.get("ENTRA_CLIENT_SECRET", "")
        self.group_id = environ.get("ENTRA_STEPUP_GROUP_ID", "")
        self.enabled = (environ.get("ENTRA_RESPONDER_ENABLED", "false").lower() == "true"
                        and bool(self.tenant and self.client_id and self.secret))
        self._http = http

    def _token(self) -> str:
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.client_id,
                                       "client_secret": self.secret,
                                       "scope": "https://graph.microsoft.com/.default"}).encode("ascii")
        status, body = self._http("POST", LOGIN.format(tenant=urllib.parse.quote(self.tenant)),
                                  {"Content-Type": "application/x-www-form-urlencoded"}, form)
        if status != 200 or not body.get("access_token"):
            raise RuntimeError(f"token request failed (HTTP {status})")
        return str(body["access_token"])

    def _graph(self, token: str, method: str, path: str, payload: Optional[Dict[str, Any]] = None):
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        return self._http(method, GRAPH + path, headers, body)

    def contain(self, upn: str) -> Dict[str, Any]:
        """Revoke sessions and add to the step-up group. Raises on failure (the engine records it)."""
        user = urllib.parse.quote(valid_upn(upn), safe="@.")
        token = self._token()
        status, _ = self._graph(token, "POST", f"/users/{user}/revokeSignInSessions")
        if status not in (200, 204):
            raise RuntimeError(f"revokeSignInSessions failed (HTTP {status})")
        steps = ["sessions revoked"]
        if self.group_id:
            status, body = self._graph(token, "GET", f"/users/{user}?$select=id")
            if status != 200 or not body.get("id"):
                raise RuntimeError(f"user lookup failed (HTTP {status}); sessions were revoked")
            ref = {"@odata.id": f"{GRAPH}/directoryObjects/{body['id']}"}
            status, _ = self._graph(token, "POST", f"/groups/{urllib.parse.quote(self.group_id)}/members/$ref", ref)
            if status not in (200, 204, 400):  # 400: already a member
                raise RuntimeError(f"adding to step-up group failed (HTTP {status}); sessions were revoked")
            steps.append("added to MFA step-up group")
        return {"mode": "live", "steps": steps}

    def release(self, upn: str) -> Dict[str, Any]:
        """Rollback: remove from the step-up group (revoked sessions stay revoked)."""
        if not self.group_id:
            return {"mode": "live", "steps": ["no step-up group configured; nothing to undo"]}
        user = urllib.parse.quote(valid_upn(upn), safe="@.")
        token = self._token()
        status, body = self._graph(token, "GET", f"/users/{user}?$select=id")
        if status != 200 or not body.get("id"):
            raise RuntimeError(f"user lookup failed (HTTP {status})")
        status, _ = self._graph(token, "DELETE",
                                f"/groups/{urllib.parse.quote(self.group_id)}/members/{body['id']}/$ref")
        if status not in (200, 204, 404):
            raise RuntimeError(f"removing from step-up group failed (HTTP {status})")
        return {"mode": "live", "steps": ["removed from MFA step-up group"]}
