"""
LLM-assisted triage summary (roadmap F96). Off by default; the analyst keeps the final say.

A Claude model drafts a short triage summary from a **pseudonymised** view of the incident.
The draft is advisory: it is stored on the incident as ``llm_summary`` with status ``DRAFT``
and does nothing until an analyst accepts it (optionally edited) or rejects it. It never
proposes, approves or runs a containment action, and its text is never parsed for
instructions.

What is sent (``build_payload``): the fields ``notifications.external_summary`` already
allows out of the network (rule, severity, technique, a keyed host pseudonym, a public
source IP or "internal"), the risk score and factor names, the policy decision, the
playbook name, the rule's own description and known false positives from its Sigma file,
and counts. Never host names, user names, internal IPs, command lines or raw logs. Before
sending, ``find_leaks`` checks the serialised payload for the incident's own identifiers
and for any private IPv4 address, and refuses on a hit.

Configuration (environment):

  LLM_TRIAGE_ENABLED   "true" to allow requests (default off)
  ANTHROPIC_API_KEY    API key; read by the official ``anthropic`` SDK
  LLM_TRIAGE_MODEL     model id, default ``claude-opus-5-5``
  LLM_TRIAGE_TIMEOUT   seconds per request, default 60

The SDK is an optional dependency (``pip install anthropic``) and is imported lazily.
"""

import ipaddress
import json
import os
import re
from datetime import datetime, timezone

import yaml

from soar.notifications import external_summary

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL = "claude-opus-5-5"
# Scalar fallbacks form: a declined request is retried server-side on the model Anthropic recommends
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 4000

SYSTEM_PROMPT = """You help a SOC analyst triage one alert from a detection lab. You see a pseudonymised
summary: host names, accounts and internal addresses have been removed on purpose; do not
guess them. Write a triage summary of at most 180 words in plain text with four short
labelled parts: What fired, Why it matters, What to check first, Possible benign causes.
Base every statement on the fields given; say "unknown" rather than inventing details.
Do not recommend approving or running containment: the analyst and the approval workflow
decide that. The summary is a draft the analyst will review."""


class LlmTriageDisabled(Exception):
    """Raised when LLM triage is not enabled or not configured."""


class PayloadRefused(Exception):
    """Raised when the payload would carry an internal identifier."""


def enabled(environ=os.environ):
    return environ.get("LLM_TRIAGE_ENABLED", "false").strip().lower() == "true"


def _rule_context(rule):
    """Description and known false positives from the rule's own Sigma file (repository content)."""
    path = os.path.normpath(os.path.join(ROOT, rule.get("sigma_file") or ""))
    if not rule.get("sigma_file") or not path.startswith(os.path.join(ROOT, "rules")) or not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    return {"description": str(doc.get("description", "")).strip(),
            "known_false_positives": [str(f) for f in doc.get("falsepositives") or []]}


def build_payload(incident):
    """The only incident data sent to the model."""
    risk = incident.get("risk_assessment") or {}
    rule = incident.get("rule") or {}
    payload = external_summary(incident)
    payload.update({
        "risk_score": risk.get("final_score"),
        "risk_level": risk.get("risk_level"),
        "risk_factors": risk.get("factors") or {},
        "intel_corroborated": bool((risk.get("reputation") or {}).get("corroborated")),
        "policy_decision": (incident.get("policy_decision") or {}).get("execution_intent"),
        "playbook": (incident.get("playbook") or {}).get("name"),
        "also_matched_rules": list(rule.get("also_matched") or []),
        "timeline_events": len(incident.get("timeline") or []),
        "observable_count": len(incident.get("observables") or []),
        "rule_context": _rule_context(rule),
    })
    return payload


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def find_leaks(text, incident):
    """Internal identifiers present in `text`: the incident's host, user, internal IPs, any private IPv4."""
    telemetry = incident.get("telemetry") or {}
    lowered = text.lower()
    leaks = []
    for field in ("computer_name", "target_host", "hostname", "user", "target_user"):
        value = str(telemetry.get(field) or "").strip()
        # Raw and JSON-escaped forms ("CORP\\user" is serialised with a doubled backslash)
        if len(value) >= 3 and any(form in lowered for form in (value.lower(), json.dumps(value.lower())[1:-1])):
            leaks.append(field)
    for candidate in _IPV4.findall(text):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        # Python counts the RFC 5737 documentation ranges as private; they are the lab's synthetic attackers
        if ip.is_private and not any(ip in net for net in _DOC_NETS):
            leaks.append(f"private address {ip}")
    return leaks


def _default_client():
    try:
        import anthropic
    except ImportError as exc:
        raise LlmTriageDisabled("the anthropic package is not installed (pip install anthropic)") from exc
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise LlmTriageDisabled("ANTHROPIC_API_KEY is not set")
    timeout = float(os.environ.get("LLM_TRIAGE_TIMEOUT", "60"))
    return anthropic.Anthropic(timeout=timeout, max_retries=2)


def draft_summary(incident, analyst, client=None, environ=os.environ, clock=None):
    """Ask the model for a draft and store it on the incident. Returns the llm_summary record."""
    if not enabled(environ):
        raise LlmTriageDisabled("LLM triage is disabled (set LLM_TRIAGE_ENABLED=true)")
    if not analyst:
        raise ValueError("an analyst name is required")
    payload = build_payload(incident)
    serialised = json.dumps(payload, sort_keys=True, default=str)
    leaks = find_leaks(serialised, incident)
    if leaks:
        raise PayloadRefused(f"payload would carry internal identifiers: {', '.join(sorted(set(leaks)))}")
    client = client or _default_client()
    model = environ.get("LLM_TRIAGE_MODEL", DEFAULT_MODEL)
    response = client.beta.messages.create(
        model=model,
        max_tokens=MAX_TOKENS,
        betas=[FALLBACK_BETA],
        fallbacks="default",
        output_config={"effort": "low"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": "Incident summary (JSON):\n" + serialised}],
    )
    now = (clock or (lambda: datetime.now(timezone.utc).isoformat()))()
    record = {"status": "DRAFT", "advisory": True, "requested_by": analyst, "requested_at": now,
              "model": getattr(response, "model", model), "stop_reason": response.stop_reason,
              "sent_fields": sorted(payload), "text": "", "reviewed_by": None, "reviewed_at": None}
    if response.stop_reason == "refusal":
        record.update(status="REFUSED", text="")
    else:
        record["text"] = "".join(b.text for b in response.content if getattr(b, "type", "") == "text").strip()
        if response.stop_reason == "max_tokens":
            record["truncated"] = True
    incident["llm_summary"] = record
    return record


def review_summary(incident, analyst, decision, text=None, clock=None):
    """The analyst's decision on a draft: accept (optionally edited) or reject. Returns the record."""
    record = incident.get("llm_summary")
    if not record or record.get("status") != "DRAFT":
        raise ValueError("there is no draft summary to review")
    if not analyst:
        raise ValueError("an analyst name is required")
    if decision not in ("accept", "reject"):
        raise ValueError("decision must be 'accept' or 'reject'")
    now = (clock or (lambda: datetime.now(timezone.utc).isoformat()))()
    record.update(reviewed_by=analyst, reviewed_at=now)
    if decision == "reject":
        record["status"] = "REJECTED"
        return record
    edited = text is not None and text.strip() != record["text"]
    if edited:
        record["original_text"] = record["text"]
        record["text"] = text.strip()[:4000]
    record.update(status="ACCEPTED", edited=edited)
    return record
