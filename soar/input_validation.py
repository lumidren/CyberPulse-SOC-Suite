"""
Input Validation & Sanitisation for Ingested Telemetry (CyberPulse SOC Lab)

Everything that arrives through the webhook receiver or the syslog listener is
untrusted. Fields are type- and format-checked against what the detection
pipeline expects, oversized or deeply nested payloads are refused, and
control characters are stripped from free-text values.
"""

import ipaddress
import re

from soar.redaction import redact
from datetime import datetime, timezone

MAX_DETAIL_KEYS = 100
MAX_DETAIL_DEPTH = 3
MAX_STRING_LEN = 4096
MAX_LIST_LEN = 100

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
USER_RE = re.compile(r"^[\w.@\\ $-]{1,128}$")
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
SOURCE_RE = re.compile(r"^[A-Za-z0-9:/._ -]{1,128}$")
TECHNIQUE_RE = re.compile(r"^(T\d{4}(\.\d{3})?|Unknown|BENIGN)$")
DETAIL_KEY_RE = re.compile(r"^[A-Za-z0-9_.|-]{1,64}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ValidationError(ValueError):
    def __init__(self, problems):
        super().__init__("; ".join(problems))
        self.problems = problems


def clean_text(value, max_len=MAX_STRING_LEN):
    """Strip control characters (keeping tab/newline) and bound the length."""
    return CONTROL_CHARS_RE.sub("", str(value))[:max_len]


def _clean_details(value, depth, problems, path="details"):
    if depth > MAX_DETAIL_DEPTH:
        problems.append(f"{path}: nested deeper than {MAX_DETAIL_DEPTH} levels")
        return None
    if isinstance(value, dict):
        if len(value) > MAX_DETAIL_KEYS:
            problems.append(f"{path}: more than {MAX_DETAIL_KEYS} keys")
            return None
        out = {}
        for key, item in value.items():
            if not isinstance(key, str) or not DETAIL_KEY_RE.match(key):
                problems.append(f"{path}: invalid key {str(key)[:40]!r}")
                continue
            out[key] = _clean_details(item, depth + 1, problems, f"{path}.{key}")
        return out
    if isinstance(value, list):
        if len(value) > MAX_LIST_LEN:
            problems.append(f"{path}: list longer than {MAX_LIST_LEN}")
            return None
        return [_clean_details(v, depth + 1, problems, f"{path}[]") for v in value]
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    return redact(clean_text(value))  # never store credentials found in command lines


def validate_event(payload):
    """Validate and sanitise an ingested event; returns the cleaned event or raises ValidationError."""
    problems = []
    if not isinstance(payload, dict):
        raise ValidationError(["event must be a JSON object"])

    for field in ("event_id", "computer_name", "source_ip"):
        if field not in payload:
            problems.append(f"Missing required field: {field}")
    if problems:
        raise ValidationError(problems)

    event_id = payload["event_id"]
    if isinstance(event_id, bool) or not (
            (isinstance(event_id, int) and 0 <= event_id <= 1_000_000)
            or (isinstance(event_id, str) and EVENT_ID_RE.match(event_id))):
        problems.append("event_id must be an integer 0-1000000 or a short identifier")

    host = payload["computer_name"]
    if not isinstance(host, str) or not HOSTNAME_RE.match(host):
        problems.append("computer_name must be a hostname (letters, digits, '.', '-', '_')")

    try:
        source_ip = str(ipaddress.ip_address(str(payload["source_ip"])))
    except ValueError:
        problems.append("source_ip must be a valid IPv4/IPv6 address")
        source_ip = None

    user = payload.get("user", "Unknown")
    if not isinstance(user, str) or not USER_RE.match(user):
        problems.append("user contains unsupported characters")

    event_source = payload.get("event_source", "webhook")
    if not isinstance(event_source, str) or not SOURCE_RE.match(event_source):
        problems.append("event_source contains unsupported characters")

    technique = payload.get("technique_id", "Unknown")
    if not isinstance(technique, str) or not TECHNIQUE_RE.match(technique):
        problems.append("technique_id must look like T1234 or T1234.001")

    timestamp = payload.get("timestamp")
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    else:
        try:
            datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except ValueError:
            problems.append("timestamp must be ISO 8601")

    details = payload.get("details", {})
    if not isinstance(details, dict):
        problems.append("details must be an object")
        details = {}
    details = _clean_details(details, 1, problems)

    if problems:
        raise ValidationError(problems)

    return {
        "event_id": event_id,
        "event_source": event_source,
        "technique_id": technique,
        "timestamp": str(timestamp),
        "computer_name": host,
        "user": user,
        "source_ip": source_ip,
        "details": details,
        "simulation": bool(payload.get("simulation", False)),
    }
