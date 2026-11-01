"""
YAML response playbooks (roadmap F32): analysts change how an alert is handled
without touching Python.

Each file in playbooks/*.yml says which alerts it handles and what to do:

    name: credential-theft
    version: 1.0.0
    description: ...
    match:
      rules: [SOC-RULE-001]          # SOC rule ids, and/or
      techniques: [T1003]            # ATT&CK ids (a parent id also matches its sub-techniques)
    response:
      action: ISOLATE_HOST_AND_KILL_PROCESS   # containment to *propose*
      min_risk: 70                   # below this risk score: alert only, no containment
      require_approval: true         # force approval even where policy would auto-run
      notify: true
    tasks:                           # analyst checklist attached to the case
      - Confirm which process opened LSASS

A playbook can only make handling *more* conservative than the policy engine:
``action`` must be a known containment action, and there is no field that turns
on automatic execution, skips approval, or skips the evidence collected before
containment. Selection order: a rule-id match, then the most specific technique
match, then ``default.yml``. Two playbooks claiming the same rule id is a load error.
"""

import copy
import hashlib
import json
import os

import yaml

from soar.action_tiers import ACTION_TIERS
from soar.sigma_engine import ROOT, SigmaRuleError

DEFAULT_DIR = os.path.join(ROOT, "playbooks")
ALERT_ONLY_ACTION = "ENRICH_AND_ALERT_ANALYST"
ALLOWED_ACTIONS = set(ACTION_TIERS) | {ALERT_ONLY_ACTION}
TOP_LEVEL = {"name", "version", "description", "match", "response", "tasks"}
RESPONSE_KEYS = {"action", "min_risk", "require_approval", "notify"}
# Intents under which the containment engine does not run the action
NON_EXECUTING_INTENTS = {"DRY_RUN_SIMULATION", "PENDING_APPROVAL"}


class PlaybookError(SigmaRuleError):
    pass


class Playbook:
    def __init__(self, path, doc):
        self.path = path
        self.file = os.path.relpath(path, ROOT).replace("\\", "/")
        if not isinstance(doc, dict):
            raise PlaybookError(f"{self.file}: not a mapping")
        unknown = set(doc) - TOP_LEVEL
        if unknown:
            raise PlaybookError(f"{self.file}: unknown keys {sorted(unknown)}")
        for key in ("name", "version", "description"):
            if not doc.get(key):
                raise PlaybookError(f"{self.file}: missing {key}")
        self.doc = doc
        self.name = str(doc["name"])
        self.version = str(doc["version"])
        match = doc.get("match") or {}
        self.rules = {str(r) for r in match.get("rules") or []}
        self.techniques = {str(t).upper() for t in match.get("techniques") or []}
        response = doc.get("response") or {}
        unknown = set(response) - RESPONSE_KEYS
        if unknown:
            raise PlaybookError(f"{self.file}: unknown response keys {sorted(unknown)} "
                                "(playbooks cannot enable automation or skip approval)")
        self.action = response.get("action")
        if self.action is not None and self.action not in ALLOWED_ACTIONS:
            raise PlaybookError(f"{self.file}: unknown action {self.action!r}")
        self.min_risk = response.get("min_risk")
        if self.min_risk is not None and not (isinstance(self.min_risk, (int, float)) and 0 <= self.min_risk <= 100):
            raise PlaybookError(f"{self.file}: min_risk must be a number from 0 to 100")
        self.require_approval = bool(response.get("require_approval", False))
        self.notify = bool(response.get("notify", True))
        self.tasks = [str(t) for t in doc.get("tasks") or []]

    @property
    def is_default(self):
        return not self.rules and not self.techniques

    def technique_specificity(self, technique):
        """2 for an exact technique match, 1 for a parent match, 0 for none."""
        technique = (technique or "").upper()
        if technique in self.techniques:
            return 2
        if technique.split(".")[0] in self.techniques:
            return 1
        return 0

    def fingerprint(self):
        """SHA-256 over everything that changes behaviour (match, response, tasks); see playbooks/versions.yml."""
        payload = {k: self.doc.get(k) for k in ("match", "response", "tasks")}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()

    def summary(self):
        return {"name": self.name, "version": self.version, "file": self.file}


class PlaybookRegistry:
    def __init__(self, directory=DEFAULT_DIR):
        self.directory = directory
        self.playbooks = []
        if os.path.isdir(directory):
            for name in sorted(os.listdir(directory)):
                if name.endswith((".yml", ".yaml")):
                    with open(os.path.join(directory, name), encoding="utf-8") as fh:
                        self.playbooks.append(Playbook(os.path.join(directory, name), yaml.safe_load(fh)))
        claimed = {}
        for pb in self.playbooks:
            for rule in pb.rules:
                if rule in claimed:
                    raise PlaybookError(f"{rule} is claimed by both {claimed[rule]} and {pb.name}")
                claimed[rule] = pb.name
        defaults = [pb for pb in self.playbooks if pb.is_default]
        if len(defaults) > 1:
            raise PlaybookError("more than one default playbook (no match block)")
        self.default = defaults[0] if defaults else None

    def select(self, matched_rule):
        rule_id = matched_rule.get("rule_id")
        for pb in self.playbooks:
            if rule_id in pb.rules:
                return pb
        technique = matched_rule.get("mitre_id")
        best = max(self.playbooks, key=lambda pb: pb.technique_specificity(technique), default=None)
        if best is not None and best.technique_specificity(technique):
            return best
        return self.default

    @staticmethod
    def apply_to_rule(playbook, matched_rule):
        """Rule copy with the playbook's proposed action (before risk scoring and policy)."""
        rule = copy.deepcopy(matched_rule)
        if playbook and playbook.action:
            rule["action_recommended"] = playbook.action
        return rule

    @staticmethod
    def apply_to_decision(playbook, decision):
        """Make a policy decision more conservative per the playbook; never less."""
        if not playbook:
            return decision
        intent = decision.get("execution_intent")
        containment = decision.get("action") in ACTION_TIERS
        if playbook.min_risk is not None and containment and decision.get("risk_score", 0) < playbook.min_risk:
            decision["action"] = ALERT_ONLY_ACTION
            decision["execution_intent"] = "ALERT_ONLY"
            decision["playbook_note"] = f"risk {decision.get('risk_score')} below playbook min_risk {playbook.min_risk}"
        elif playbook.require_approval and containment and intent not in NON_EXECUTING_INTENTS:
            decision["execution_intent"] = "PENDING_APPROVAL"
            decision["approval_reason"] = f"playbook {playbook.name} requires analyst approval"
        decision["playbook"] = playbook.summary()
        return decision


def validate_draft(text, registry, rules):
    """Check a playbook draft (YAML text) as the loader would, without writing anything.

    Returns {"valid", "errors", "normalized_yaml", "routes"}; `routes` lists the SOC rule ids
    this draft would handle if it replaced the committed playbook of the same name."""
    try:
        doc = yaml.safe_load(text)
        draft = Playbook(os.path.join(registry.directory, "draft.yml"), doc)
    except (yaml.YAMLError, PlaybookError) as exc:
        return {"valid": False, "errors": [str(exc)], "warnings": [], "normalized_yaml": None, "routes": []}
    others = [pb for pb in registry.playbooks if pb.name != draft.name]
    errors = [f"{rule} is already claimed by {pb.name}" for pb in others for rule in sorted(draft.rules & pb.rules)]
    if draft.is_default and any(pb.is_default for pb in others):
        errors.append("another playbook is already the default (no match block)")
    trial = PlaybookRegistry.__new__(PlaybookRegistry)
    trial.directory, trial.playbooks = registry.directory, others + [draft]
    trial.default = draft if draft.is_default else registry.default
    routes = sorted({r["rule_id"] for r in rules if trial.select(r) is draft})
    warnings = [f"technique {t} is also matched by {pb.name}; on a tie the playbook loaded first wins"
                for pb in others for t in sorted(draft.techniques & pb.techniques)]
    return {"valid": not errors, "errors": errors, "warnings": warnings,
            "normalized_yaml": yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), "routes": routes}


CASES_PATH = os.path.join(DEFAULT_DIR, "tests", "cases.yml")
VERSIONS_PATH = os.path.join(DEFAULT_DIR, "meta", "versions.yml")


def pb_for_test(**doc):
    """Build an in-memory playbook (tests and the editor's previews)."""
    base = {"name": "test", "version": "1.0.0", "description": "test"}
    base.update(doc)
    return Playbook(os.path.join(DEFAULT_DIR, "test.yml"), base)


def run_case(registry, case):
    """Apply the playbook layer to one test case; returns a list of failure messages (empty = pass)."""
    playbook = registry.select(case["rule"])
    rule = PlaybookRegistry.apply_to_rule(playbook, case["rule"])
    decision = dict(case["decision"], action=rule["action_recommended"]) if playbook and playbook.action else dict(case["decision"])
    decision = PlaybookRegistry.apply_to_decision(playbook, decision)
    actual = {"playbook": playbook.name if playbook else None, "action": decision.get("action"),
              "execution_intent": decision.get("execution_intent"), "tasks": len(playbook.tasks) if playbook else 0}
    failures = []
    for key, want in (case.get("expect") or {}).items():
        if key == "min_tasks":
            if actual["tasks"] < want:
                failures.append(f"tasks: want at least {want}, got {actual['tasks']}")
        elif actual.get(key) != want:
            failures.append(f"{key}: want {want!r}, got {actual.get(key)!r}")
    return failures


def run_cases(registry=None, path=CASES_PATH):
    registry = registry or PlaybookRegistry()
    with open(path, encoding="utf-8") as fh:
        cases = (yaml.safe_load(fh) or {}).get("cases") or []
    return [(case["name"], run_case(registry, case)) for case in cases]


def version_problems(registry=None, path=VERSIONS_PATH):
    """Playbooks whose behaviour changed without a version bump in playbooks/meta/versions.yml."""
    registry = registry or PlaybookRegistry()
    with open(path, encoding="utf-8") as fh:
        recorded = (yaml.safe_load(fh) or {}).get("playbooks") or {}
    problems = []
    for pb in registry.playbooks:
        entry = recorded.get(pb.name)
        if not entry:
            problems.append(f"{pb.name}: missing from meta/versions.yml")
        elif str(entry.get("version")) != pb.version:
            problems.append(f"{pb.name}: version {pb.version} in the playbook, {entry.get('version')} recorded")
        elif entry.get("sha256") != pb.fingerprint():
            problems.append(f"{pb.name}: behaviour changed; bump version, update meta/versions.yml and CHANGELOG.md")
    return problems


if __name__ == "__main__":
    import sys

    if "--test" not in sys.argv:
        sys.exit("usage: python -m soar.playbooks --test")
    results = run_cases()
    for name, failures in results:
        print(("PASS " if not failures else "FAIL ") + name)
        for f in failures:
            print("     " + f)
    problems = version_problems()
    for p in problems:
        print("VERSION " + p)
    sys.exit(1 if problems or any(f for _, f in results) else 0)
