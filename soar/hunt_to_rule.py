"""
Hunt-to-detection workflow (roadmap F75): turn a hunting finding into a draft Sigma rule.

From a pivot (field = value) in the hunting workbench, ``draft_rule`` produces:

  * a rule in the project's metadata standard (rules/METADATA_STANDARD.md) with the
    logsource taken from the matching events, a selection on the pivoted field, the
    technique tag when the events carry one, and TODO markers where only a human can
    decide (title, description, false positives, level);
  * a samples file whose positive cases are the matching events (already redacted) and
    whose negative case is a placeholder the analyst must replace with a real near miss;
  * a checklist of what must happen before it can be committed.

The draft is checked by the same engine that will run it, but it is **never written** to
the repository or enabled: it goes through review like any other rule (CONTRIBUTING.md).
"""

import copy
import uuid
from datetime import date

import yaml

from soar.event_store import PIVOT_FIELDS, field_value
from soar.sigma_engine import LOGSOURCE_EVENT_IDS, LOGSOURCE_SOURCES, SigmaRule

# Pivot field -> Sigma field name the engine resolves (FIELD_ALIASES / details keys)
SIGMA_FIELD = {"host": "Computer", "source_ip": "IpAddress", "user": "User", "process": "Image",
               "parent_process": "ParentImage", "command_line": "CommandLine", "hash": "Hashes",
               "target_user": "TargetUserName", "destination": "query", "ja3": "ja3", "ja4": "ja4",
               "tls_server_name": "server_name"}
CHECKLIST = [
    "Replace every TODO (title, description, false positives, level) with specifics",
    "Narrow the selection: one field from one hunt is rarely enough to be precise",
    "Add at least one realistic negative sample (a benign near miss) and remove the placeholder",
    "Run the evasion and regression checks (scripts/evasion_report.py, scripts/regression_corpus.py)",
    "Add the SOAR mapping, version, detection fingerprint and RULE_CHANGELOG entry (CONTRIBUTING.md)",
    "Get it reviewed; drafts are never enabled automatically",
]


def _logsource_for(event):
    """Most specific logsource: a Windows category by event id (e.g. process_creation) beats a service."""
    source = event.get("event_source")
    try:
        numeric = int(event.get("event_id"))
    except (TypeError, ValueError):
        numeric = None
    if source in LOGSOURCE_SOURCES.get(("windows", "sysmon"), set()) | {"Security"}:
        for (product, category), ids in LOGSOURCE_EVENT_IDS.items():
            if numeric in ids:
                return {"product": product, "category": category}
    for (product, service), sources in LOGSOURCE_SOURCES.items():
        if source in sources:
            return {"product": product, "service": service}
    return None


def draft_rule(field, value, events, author="lumidren (CyberPulse SOC Suite)"):
    if field not in SIGMA_FIELD:
        return {"error": f"cannot draft a rule on {field!r}; use one of {sorted(SIGMA_FIELD)}"}
    matching = [e for e in events if str(field_value(e, field) or "").lower() == str(value).lower()]
    if not matching:
        return {"error": "no stored events match; pivot first"}
    logsources = [ls for ls in (_logsource_for(e) for e in matching) if ls]
    if not logsources:
        return {"error": "the matching events come from a source the engine has no logsource for"}
    logsource = max(logsources, key=logsources.count)
    techniques = sorted({str(e.get("technique_id")) for e in matching if str(e.get("technique_id", "")).startswith("T")})
    rule_id = str(uuid.uuid4())
    today = date.today().isoformat()
    doc = {
        "title": f"TODO: name what this detects ({SIGMA_FIELD[field]} {value})",
        "id": rule_id,
        "status": "experimental",
        "description": f"TODO: what this detects and why it matters. Drafted from a hunt on {field} = {value} "
                       f"({len(matching)} matching event(s)).",
        "references": [f"https://attack.mitre.org/techniques/{techniques[0].replace('.', '/')}/" if techniques
                       else "https://attack.mitre.org/"],
        "author": author,
        "date": today,
        "modified": today,
        "tags": [f"attack.{t.lower()}" for t in techniques] or ["attack.TODO-tactic", "attack.tTODO"],
        "logsource": logsource,
        "detection": {"selection": {SIGMA_FIELD[field]: value}, "condition": "selection"},
        "falsepositives": ["TODO: concrete benign cases (which tools, roles or schedules produce this?)"],
        "level": "medium",
    }
    # The draft must load and match its own positive samples with the real engine
    rule = SigmaRule(f"rules/sigma/draft_{rule_id[:8]}.yml", copy.deepcopy(doc), {})
    positives = [e for e in matching if rule.matches(e)][:5]
    samples = {
        "rule": f"draft_{rule_id[:8]}.yml",
        "positive": [{"name": f"Hunt finding {i + 1}", "event": {k: v for k, v in e.items() if not k.startswith("_")}}
                     for i, e in enumerate(positives)],
        "negative": [{"name": "TODO: a benign near miss", "event": {"event_id": "TODO"}}],
    }
    return {
        "rule_yaml": yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=110, indent=4),
        "samples_yaml": yaml.safe_dump(samples, sort_keys=False, allow_unicode=True, width=120),
        "matches_own_samples": len(positives),
        "matching_events": len(matching),
        "checklist": CHECKLIST,
        "note": "Draft only: not written to the repository and not enabled.",
    }


__all__ = ["draft_rule", "PIVOT_FIELDS"]
