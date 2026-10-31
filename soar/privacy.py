"""
Identity Masking for Displayed Data (CyberPulse SOC Lab)

Usernames shown in the console, API responses and generated reports are
masked by default ("CORP\\j.doe" -> "CORP\\j***e") so screenshots and demos
never expose account names, synthetic or real. Detection, risk scoring and
containment always use the unmasked values server-side.

Disable with PRIVACY_MASK_USERNAMES=false when an analyst genuinely needs the
full names (e.g. working a real incident).
"""

import os

# Keys whose values are account names wherever they appear in a payload
USER_KEYS = {
    "user", "target_user", "TargetUserName", "SubjectUserName", "compromised_user",
    "username", "from_user", "to_user", "Principal",
}
UNMASKED = {"Unknown", "NT AUTHORITY\\SYSTEM", "SYSTEM", "", None}


def masking_enabled():
    return os.environ.get("PRIVACY_MASK_USERNAMES", "true").strip().lower() != "false"


def mask_username(value):
    """Keep domain prefix and first/last character of the account; mask the rest."""
    if not isinstance(value, str) or value in UNMASKED:
        return value
    domain, sep, account = value.rpartition("\\")
    if len(account) <= 2:
        masked = account[:1] + "*"
    else:
        masked = account[0] + "*" * min(len(account) - 2, 6) + account[-1]
    return f"{domain}{sep}{masked}"


def mask_identities(obj):
    """Return a copy of `obj` with every account name masked."""
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key in USER_KEYS and isinstance(value, str):
                out[key] = mask_username(value)
            elif key == "value" and obj.get("type") == "user-account":
                out[key] = mask_username(value)
            else:
                out[key] = mask_identities(value)
        return out
    if isinstance(obj, list):
        return [mask_identities(v) for v in obj]
    return obj
