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
import re
from typing import Any, Dict, Optional, Pattern, Set

# Keys whose values are account names wherever they appear in a payload
USER_KEYS = {
    "user", "target_user", "TargetUserName", "SubjectUserName", "compromised_user",
    "username", "from_user", "to_user", "Principal",
}
UNMASKED = {"Unknown", "NT AUTHORITY\\SYSTEM", "SYSTEM", "", None}
# Windows profile folders carry the account name: C:\Users\<account>\...
PROFILE_PATH = re.compile(r"(?i)(\b[a-z]:\\+users\\+)([^\\/\s\"'<>|]+)")
SHARED_PROFILES = {"public", "default", "default user", "all users"}
MIN_BARE_NAME = 3  # shorter bare names are too likely to match ordinary words


def masking_enabled() -> bool:
    return os.environ.get("PRIVACY_MASK_USERNAMES", "true").strip().lower() != "false"


def mask_username(value: Any) -> Any:
    """Keep domain prefix and first/last character of the account; mask the rest."""
    if not isinstance(value, str) or value in UNMASKED:
        return value
    domain, sep, account = value.rpartition("\\")
    if len(account) <= 2:
        masked = account[:1] + "*"
    else:
        masked = account[0] + "*" * min(len(account) - 2, 6) + account[-1]
    return f"{domain}{sep}{masked}"


def _collect_accounts(obj: Any, found: Set[str]) -> None:
    """Gather every account name the payload names in an account field."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str) and (key in USER_KEYS or (key == "value" and obj.get("type") == "user-account")):
                if value not in UNMASKED:
                    found.add(value)
            else:
                _collect_accounts(value, found)
    elif isinstance(obj, list):
        for v in obj:
            _collect_accounts(v, found)


def _replacements(accounts: Set[str]) -> Dict[str, str]:
    table = {}
    for account in accounts:
        table[account] = mask_username(account)
        bare = account.rpartition("\\")[2]
        if len(bare) >= MIN_BARE_NAME and bare not in UNMASKED:
            table[bare] = mask_username(bare)
    return table


def _mask_profile(match: "re.Match[str]") -> str:
    name = match.group(2)
    return match.group(0) if name.lower() in SHARED_PROFILES else match.group(1) + mask_username(name)


def mask_text(text: str, table: Dict[str, str], pattern: Optional[Pattern[str]]) -> str:
    """Mask known account names inside free text, ids and file paths."""
    if pattern is not None:
        text = pattern.sub(lambda m: table[m.group(0)], text)
    return PROFILE_PATH.sub(_mask_profile, text)


def _mask(obj: Any, table: Dict[str, str], pattern: Optional[Pattern[str]]) -> Any:
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if key in USER_KEYS and isinstance(value, str):
                out[key] = mask_username(value)
            elif key == "value" and obj.get("type") == "user-account":
                out[key] = mask_username(value)
            else:
                out[key] = _mask(value, table, pattern)
        return out
    if isinstance(obj, list):
        return [_mask(v, table, pattern) for v in obj]
    if isinstance(obj, str):
        return mask_text(obj, table, pattern)
    return obj


def mask_identities(obj: Any) -> Any:
    """Return a copy of `obj` with every account name masked.

    Account fields are masked directly. Any account name found in them is
    then also masked wherever else it appears: graph node ids and labels,
    profile paths (C:\\Users\\<account>\\...) and free text such as a
    recommended action. The same name always masks the same way, so graph
    edges still connect to their nodes.
    """
    accounts: Set[str] = set()
    _collect_accounts(obj, accounts)
    table = _replacements(accounts)
    pattern = None
    if table:
        names = sorted(table, key=len, reverse=True)  # longest first: "CORP\\x" before "x"
        pattern = re.compile(r"(?<![\w.])(?:" + "|".join(re.escape(n) for n in names) + r")(?![\w])")
    return _mask(obj, table, pattern)
