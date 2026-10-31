"""
Secret Redaction for Logged and Stored Telemetry (CyberPulse SOC Lab)

Command lines and free-text fields routinely contain credentials: passwords
passed to net.exe / runas / sqlcmd, API tokens in curl headers, connection
strings, user:password@host URLs. Those values are replaced with
"[REDACTED]" before an event is stored, rendered or logged, while the rest of
the command line (which detections and analysts need) is kept.
"""

import re

REDACTED = "[REDACTED]"

_RULES = [
    # -Password X / -pass X / --password=X / /p:X / /password:X  (Windows + POSIX style flags)
    (re.compile(r"(?i)((?:--?|/)(?:password|passwd|pwd|pass|p|secret|token|apikey|api-key)(?:[:=]|\s+))(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1" + REDACTED),
    # key=value pairs in connection strings / query strings
    (re.compile(r"(?i)\b((?:password|passwd|pwd|secret|token|api_?key|access_?key|client_?secret)\s*=\s*)(\"[^\"]*\"|'[^']*'|[^;&\s]+)"),
     r"\1" + REDACTED),
    # Authorization headers
    (re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)\S+"), r"\1" + REDACTED),
    # scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(@)"), r"\1" + REDACTED + r"\3"),
    # net use \\host\share <password> /user:x   and   net user <name> <password>
    (re.compile(r"(?i)(\bnet(?:\.exe)?\s+use\s+\S+\s+)(?!/)(\S+)"), r"\1" + REDACTED),
    (re.compile(r"(?i)(\bnet(?:\.exe)?\s+user\s+\S+\s+)(?!/)(\S+)"), r"\1" + REDACTED),
    # account:secret pairs that look like dumped credentials (secret has a letter and a digit,
    # no path separators, so registry paths, URLs and host:port are left alone)
    (re.compile(r"\b([A-Za-z][A-Za-z0-9_.-]{1,63}):(?![/\\])(?=[^\s:/\\]*\d)(?=[^\s:/\\]*[A-Za-z])[^\s:/\\]{6,}"),
     r"\1:" + REDACTED),
    # AWS access keys
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
]


def redact(text):
    """Return `text` with credential values replaced by [REDACTED]."""
    if not isinstance(text, str) or not text:
        return text
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter:
    """logging.Filter that redacts credentials from every formatted log message."""

    def filter(self, record):
        try:
            message = record.getMessage()
        except Exception:
            return True
        record.msg, record.args = redact(message), ()
        return True


def redact_deep(value):
    """Apply `redact` to every string in a nested structure."""
    if isinstance(value, dict):
        return {k: redact_deep(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_deep(v) for v in value]
    return redact(value)
