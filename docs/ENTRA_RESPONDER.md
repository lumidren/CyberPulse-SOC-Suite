# Entra ID Session Revocation and MFA Step-Up

Roadmap F44. **Off by default (simulated); needs your tenant. Tested with a stubbed
HTTP layer only, never against a tenant.**

`REVOKE_ENTRA_REFRESH_TOKENS_AND_FORCE_MFA` (TIER_3_IDENTITY, so always analyst-approved)
runs live against Microsoft Graph when configured (`soar/entra_responder.py`):

1. `POST /users/{upn}/revokeSignInSessions` invalidates every refresh token and session
   cookie of the account.
2. If `ENTRA_STEPUP_GROUP_ID` is set, the account is added to that group. Point a
   Conditional Access policy at the group with *Require multifactor authentication*
   (and, if you like, *Require password change*). Graph has no "force MFA" call of its
   own; your CA policy is what enforces the step-up.

Rollback removes the account from the step-up group. Revoked sessions cannot be
restored; the user signs in again. If a live step fails, the action is flagged for
manual review with the failing step named, so you know where to finish by hand.

## App registration (least privilege)

- Client-credentials app, application permissions **`User.RevokeSessions.All`** and
  **`GroupMember.ReadWrite.All`**, admin-consented. Nothing broader.
- Prefer a certificate or a short-lived secret kept in your secrets manager.
- `ENTRA_RESPONDER_ENABLED=true`, `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`,
  `ENTRA_CLIENT_SECRET`, optional `ENTRA_STEPUP_GROUP_ID`.

Protected accounts (break-glass, admins) are refused before this action is reached.
The account's UPN is sent only to Microsoft Graph for the tenant that already holds the
account; nothing else about the incident is sent.
