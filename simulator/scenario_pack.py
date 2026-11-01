"""
Red vs blue scenario pack (roadmap F99): load, validate and replay scenarios/*.yml.

A scenario is data only: ordered steps, each with the red team's move, the synthetic
events it leaves behind, and what blue is expected to see (``detected`` or a known
``missed``). Packs written by other people go through the same checks before anything is
replayed:

  * lab mode must be declared (``CYBERPULSE_LAB_MODE=true``);
  * every event's host must pass the simulator's lab guard (lab inventory inside the lab
    CIDRs, or an allowlisted lab cloud tenant);
  * every IPv4 address anywhere in an event must be inside the lab CIDRs or an RFC 5737
    documentation range, so no real third party is ever named;
  * credential-attack events may only name lab accounts and carry no password material.

Replay feeds the events to the detection engine only (``evaluate_detection``): no
incident is opened and no containment, notification or enrichment runs. Events are tagged
as simulated.
"""

import copy
import ipaddress
import os
import re

import yaml

from simulator.lab_guard import (TargetNotAllowed, lab_cidrs, require_lab_mode, tag_simulated,
                                 validate_credential_attack, validate_target)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PACK = os.path.join(ROOT, "scenarios")
EXPECT = ("detected", "missed")
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class ScenarioError(ValueError):
    """A scenario file is malformed or would step outside the lab."""


def _strings(value):
    if isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif value is not None:
        yield str(value)


def check_event(event, where):
    """Raise ScenarioError unless the event is synthetic lab telemetry."""
    if not isinstance(event, dict) or "event_id" not in event or "event_source" not in event:
        raise ScenarioError(f"{where}: an event needs event_id and event_source")
    nets = lab_cidrs()
    for text in _strings(event):
        for candidate in _IPV4.findall(text):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not any(ip in net for net in nets + _DOC_NETS):
                raise ScenarioError(f"{where}: {ip} is outside the lab CIDRs and RFC 5737 ranges")
    try:
        validate_target(event)
        validate_credential_attack(event)
    except TargetNotAllowed as exc:
        raise ScenarioError(f"{where}: {exc}") from None


def load(path):
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    name = os.path.basename(path)
    for key in ("id", "title", "summary", "steps"):
        if not doc.get(key):
            raise ScenarioError(f"{name}: missing {key}")
    if doc.get("synthetic") is not True:
        raise ScenarioError(f"{name}: scenarios must declare synthetic: true")
    seen = set()
    for step in doc["steps"]:
        sid = step.get("id")
        if not sid or sid in seen:
            raise ScenarioError(f"{name}: step ids must be present and unique ({sid!r})")
        seen.add(sid)
        blue = step.get("blue") or {}
        if blue.get("expect") not in EXPECT or not blue.get("rules"):
            raise ScenarioError(f"{name} {sid}: blue needs expect ({' or '.join(EXPECT)}) and rules")
        if not step.get("events"):
            raise ScenarioError(f"{name} {sid}: no events")
        for i, event in enumerate(step["events"]):
            check_event(event, f"{name} {sid} event {i + 1}")
    return doc


def load_pack(directory=DEFAULT_PACK):
    files = sorted(f for f in os.listdir(directory) if f.endswith(".yml"))
    scenarios = [load(os.path.join(directory, f)) for f in files]
    ids = [s["id"] for s in scenarios]
    if len(ids) != len(set(ids)):
        raise ScenarioError("scenario ids must be unique across the pack")
    return scenarios


def run(scenario, orchestrator_factory=None):
    """Replay one scenario through detection only; returns per-step results and the score."""
    require_lab_mode()
    if orchestrator_factory is None:
        from soar.soar_engine import SOAROrchestrator

        def orchestrator_factory():
            return SOAROrchestrator(policy_mode="DRY_RUN")
    orchestrator = orchestrator_factory()  # fresh state, so correlation windows do not leak between scenarios
    steps = []
    for step in scenario["steps"]:
        fired = []
        for event in step["events"]:
            hit = orchestrator.evaluate_detection(tag_simulated(copy.deepcopy(event)))
            if hit:
                fired += [hit["rule_id"]] + list(hit.get("also_matched") or [])
        fired = sorted(set(fired))
        detected = any(r in fired for r in step["blue"]["rules"])
        outcome = "detected" if detected else "missed"
        steps.append({"id": step["id"], "name": step["name"], "technique": step["technique"],
                      "expected": step["blue"]["expect"], "outcome": outcome, "fired": fired,
                      "as_expected": outcome == step["blue"]["expect"]})
    return {"id": scenario["id"], "title": scenario["title"], "difficulty": scenario.get("difficulty"),
            "steps": steps, "blue": sum(s["outcome"] == "detected" for s in steps),
            "red": sum(s["outcome"] == "missed" for s in steps)}
