"""
Natural-language hunt queries translated to Sigma, SPL and KQL (roadmap F97).

"failed logons for user svc_backup from 203.0.113.0/24 in the last 24 hours" becomes a
Sigma detection, which ``soar.sigma_convert`` turns into Splunk SPL and Microsoft KQL. The
same rule also runs against the hunting event store, so the analyst sees how many stored
events it matches before pasting the query into a SIEM.

This is a **fixed phrase grammar**, not a language model: deterministic, offline and
testable. Words it does not recognise are returned in ``not_understood`` and ignored, so a
query that reads right but was only half understood is visible as such. ``EXAMPLES`` lists
the phrases it knows.
"""

import os
import re
from datetime import datetime, timedelta, timezone

import yaml

from soar.sigma_convert import convert
from soar.sigma_engine import LOGSOURCE_EVENT_IDS, SigmaRule, SigmaRuleError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_TEXT = 300

EXAMPLES = [
    "processes named mimikatz.exe on host WIN-WORKSTATION09",
    "powershell.exe with parent winword.exe containing -enc in the last 24 hours",
    "failed logons for user svc_backup from 203.0.113.0/24",
    "network connections to port 4444",
    "dns queries for domain example.org in the last 2 hours",
    "files written in path C:\\Users\\Public",
]

_VALUE = r'(?:"(?P<q>[^"]{1,200})"|(?P<v>[^\s"]{1,200}))'
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)"

# (pattern, logsource, base selection); first match wins, after filters have been removed
SUBJECTS = [
    (r"\bfailed (?:log ?ons?|logins?|sign-?ins?)\b", {"product": "windows", "service": "security"}, {"EventID": 4625}),
    (r"\bsuccessful (?:log ?ons?|logins?|sign-?ins?)\b", {"product": "windows", "service": "security"}, {"EventID": 4624}),
    (r"\bpowershell script(?: ?block)?s?\b|\bscript ?blocks?\b", {"product": "windows", "category": "ps_script"}, {}),
    (r"\bfiles? (?:written|created|dropped)\b|\bfile (?:writes|events|creations?)\b|\bfiles\b",
     {"product": "windows", "category": "file_event"}, {}),
    (r"\bregistry(?: changes| writes| keys?| values?)?\b", {"product": "windows", "category": "registry_set"}, {}),
    (r"\b(?:network )?connections?\b", {"product": "windows", "category": "network_connection"}, {}),
    (r"\bdns (?:quer(?:y|ies)|lookups?)\b", {"product": "windows", "category": "dns_query"}, {}),
    (r"\bprocess(?:es)?(?: creations?)?\b|\bexecutions?\b|\b(?:ran|launched|started|executed)\b",
     {"product": "windows", "category": "process_creation"}, {}),
]

# Field a free-text "containing X" applies to, per event type
TEXT_FIELD = {"file_event": "TargetFilename", "ps_script": "ScriptBlockText", "registry_set": "TargetObject",
              "dns_query": "QueryName"}
PATH_FIELD = {"file_event": "TargetFilename", "registry_set": "TargetObject"}

STOPWORDS = set("""show me find list get search hunt look for all any every the a an of that which who were was is are
and events event where please with in on at by from to""".split())

UNITS = {"m": ("minutes", "mins", "minute", "min"), "h": ("hours", "hrs", "hour", "hr"), "d": ("days", "day")}


class QueryNotUnderstood(ValueError):
    pass


def _value(match):
    return (match.group("q") or match.group("v") or "").strip()


def _exe(value):
    return value if "." in value.rsplit("\\", 1)[-1] else value + ".exe"


def parse(text):
    """Sigma doc, time window and what was and was not understood, for one query."""
    original = " ".join(str(text or "").split())[:MAX_TEXT]
    if not original:
        raise QueryNotUnderstood("type a question, e.g. " + EXAMPLES[0])
    rest = " " + original + " "
    understood, filters, window = [], [], None

    def take(pattern, handler):
        nonlocal rest
        while True:
            m = re.search(pattern, rest, re.IGNORECASE)
            if not m:
                return
            handler(m)
            understood.append(m.group(0).strip())
            rest = rest[:m.start()] + " " + rest[m.end():]

    def set_window(m):
        nonlocal window
        unit = next(k for k, names in UNITS.items() if m.group("u").lower() in names)
        window = (int(m.group("n") or 1), unit)

    def set_today(_m):
        nonlocal window
        window = (1, "d")

    take(r"\b(?:in|over|during|within) the (?:last|past)\s+(?P<n>\d{1,4})?\s*(?P<u>minutes?|mins?|hours?|hrs?|days?)\b", set_window)
    take(r"\btoday\b", set_today)
    take(r"\b(?:with parent|spawned by|launched by|started by|parent(?: process)?)\s+" + _VALUE,
         lambda m: filters.append(("parent", _value(m))))
    take(r"\b(?:containing|contains|that contains?|with (?:the )?(?:argument|text|string))\s+" + _VALUE,
         lambda m: filters.append(("text", _value(m))))
    take(r"\bon (?:host|computer|machine|device)\s+" + _VALUE, lambda m: filters.append(("host", _value(m))))
    take(r"\b(?:by|for|as|of) (?:user|account)\s+" + _VALUE, lambda m: filters.append(("user", _value(m))))
    take(r"\bfrom (?:ip\s+|address\s+)?" + _IP, lambda m: filters.append(("source_ip", m.group("ip"))))
    take(r"\bto (?:ip\s+|address\s+)?" + _IP, lambda m: filters.append(("destination_ip", m.group("ip"))))
    take(r"\b(?:to|on) port\s+(?P<port>\d{1,5})\b", lambda m: filters.append(("port", m.group("port"))))
    take(r"\b(?:for|to|of) domain\s+" + _VALUE, lambda m: filters.append(("domain", _value(m))))
    take(r"\b(?:in|under) (?:path|folder|directory|key)\s+" + _VALUE, lambda m: filters.append(("path", _value(m))))
    take(r"\b(?:named|called|image)\s+" + _VALUE, lambda m: filters.append(("process", _value(m))))
    take(r"(?<![\w\\.-])(?P<v>[\w.-]+\.exe)\b(?P<q>)", lambda m: filters.append(("process", m.group("v"))))

    logsource, base = {}, {}
    for pattern, source, selection in SUBJECTS:
        m = re.search(pattern, rest, re.IGNORECASE)
        if m:
            logsource, base = dict(source), dict(selection)
            understood.append(m.group(0).strip())
            rest = rest[:m.start()] + " " + rest[m.end():]
            break
    if not logsource and any(kind in ("process", "parent") for kind, _ in filters):
        logsource = {"product": "windows", "category": "process_creation"}

    category = logsource.get("category")
    logon = logsource.get("service") == "security"
    selection = dict(base)
    for kind, value in filters:
        if kind == "process":
            key, value = "Image|endswith", "\\" + _exe(value)
        elif kind == "parent":
            key, value = "ParentImage|endswith", "\\" + _exe(value)
        elif kind == "text":
            key = TEXT_FIELD.get(category, "CommandLine") + "|contains"
        elif kind == "host":
            key = "Computer"
        elif kind == "user":
            key = "TargetUserName" if logon else "User|contains"
        elif kind == "source_ip":
            key = "IpAddress|cidr" if "/" in value else "IpAddress"
        elif kind == "destination_ip":
            key = "DestinationIp|cidr" if "/" in value else "DestinationIp"
        elif kind == "port":
            key, value = "DestinationPort", int(value)
        elif kind == "domain":
            key = "QueryName|endswith"
        else:  # path
            key = PATH_FIELD.get(category, "Image") + "|startswith"
        if key in selection:
            existing = selection[key]
            selection[key] = (existing if isinstance(existing, list) else [existing]) + [value]
        else:
            selection[key] = value
    if not selection:
        ids = sorted(LOGSOURCE_EVENT_IDS.get((logsource.get("product"), category), set()))
        if not ids:
            raise QueryNotUnderstood("no event type or condition recognised; try e.g. " + EXAMPLES[0])
        selection = {"EventID": ids}

    leftover = [w for w in re.findall(r"[^\s,.?!]+", rest) if w.lower() not in STOPWORDS]
    # The title lands in an SPL ``` comment ``` and a KQL // comment: no backticks (newlines are already gone)
    doc = {"title": original.replace("`", "'"), "status": "experimental",
           "description": "Generated from a natural-language hunt query; review before use.",
           "logsource": logsource, "detection": {"selection": selection, "condition": "selection"}, "level": "low"}
    return {"query": original, "sigma": doc, "window": window, "understood": understood, "not_understood": leftover}


def _with_window(target, query, window):
    if not window:
        return query
    n, unit = window
    if target == "splunk":
        return query.replace("index=*", f"index=* earliest=-{n}{unit}", 1)
    return query.rstrip("\n") + f"\n| where TimeGenerated > ago({n}{unit})\n"


def translate(text, events=()):
    """Parse a question; return Sigma YAML, SPL, KQL and how many stored events it matches."""
    parsed = parse(text)
    try:
        rule = SigmaRule(os.path.join(ROOT, "hunts", "nl_query.yml"), parsed["sigma"], {"soc_rule_id": "Hunt"})
    except SigmaRuleError as exc:
        raise QueryNotUnderstood(str(exc)) from None
    cutoff = None
    if parsed["window"]:
        n, unit = parsed["window"]
        cutoff = datetime.now(timezone.utc) - timedelta(**{{"m": "minutes", "h": "hours", "d": "days"}[unit]: n})
    matched = [e for e in events if rule.matches(e)
               and (cutoff is None or datetime.fromisoformat(e.get("_seen_at", "1970-01-01T00:00:00+00:00")) >= cutoff)]
    return dict(parsed,
                sigma_yaml=yaml.safe_dump(parsed["sigma"], sort_keys=False, allow_unicode=True),
                splunk=_with_window("splunk", convert(rule, "splunk"), parsed["window"]),
                kql=_with_window("kql", convert(rule, "kql"), parsed["window"]),
                matches=len(matched),
                sample=[{"seen_at": e.get("_seen_at"), "rule": e.get("_rule"), "host": e.get("computer_name"),
                         "user": e.get("user"), "event_id": e.get("event_id")} for e in matched[-20:]][::-1])
