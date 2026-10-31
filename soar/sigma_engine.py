"""
Sigma Detection Engine (CyberPulse SOC Lab)

Detection-as-code: the rules in rules/sigma/*.yml *are* the detection logic.
This module loads them, compiles their `detection` blocks and evaluates lab
events against them, so a rule change in Git changes what the pipeline
detects (and the rule tests in CI catch regressions).

Supported Sigma features (a documented subset of the Sigma 2.0 spec):
* selections as maps (AND across fields), lists of maps (OR) and keyword lists
* value lists (OR; AND with |all), null (field absent), wildcards * and ?
* modifiers: contains, startswith, endswith, all, re, cidr, exists,
  gt, gte, lt, lte
* conditions: and, or, not, parentheses, "1 of sel*", "all of sel*",
  "1 of them", "all of them"
* case-insensitive string matching (Sigma default); |re is case-sensitive

Not supported here (by design): deprecated aggregation conditions
("| count() > n"); use Sigma correlation rules instead (see
soar/sigma_correlation.py). A rule using an unsupported feature fails to load
loudly rather than silently matching nothing.
"""

import fnmatch
import ipaddress
import os
import re

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES_DIR = os.path.join(ROOT, "rules", "sigma")
DEFAULT_MAPPING = os.path.join(ROOT, "rules", "soar_mapping.yml")

LEVEL_TO_SEVERITY = {"informational": "LOW", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Logsource -> constraint on lab events (pySigma would call this a processing pipeline)
LOGSOURCE_EVENT_IDS = {
    ("windows", "process_creation"): {1, 4688},
    ("windows", "process_access"): {10},
    ("windows", "file_event"): {11},
    ("windows", "driver_load"): {6},
    ("windows", "image_load"): {7},
    ("windows", "network_connection"): {3},
    ("windows", "registry_set"): {13},
    ("windows", "registry_event"): {12, 13, 14},
    ("windows", "dns_query"): {22},
    ("windows", "ps_script"): {4104},
    ("windows", "wmi_event"): {19, 20, 21},
}
LOGSOURCE_SOURCES = {
    ("windows", "security"): {"Security"},
    ("windows", "sysmon"): {"Microsoft-Windows-Sysmon/Operational", "sysmon"},
    ("windows", "system"): {"System"},
    ("aws", "cloudtrail"): {"aws:cloudtrail"},
    ("azure", "signinlogs"): {"azure:signinlogs"},
    ("azure", "auditlogs"): {"azure:auditlogs"},
    ("zeek", "dns"): {"zeek:dns"},
    ("zeek", "conn"): {"zeek:conn"},
    ("zeek", "ssl"): {"zeek:ssl"},
    ("zeek", "http"): {"zeek:http"},
}

# Sigma/vendor field names -> where the lab event keeps the value
FIELD_ALIASES = {
    "EventID": "event_id",
    "Computer": "computer_name",
    "IpAddress": "source_ip",
    "SourceIp": "source_ip",
    "sourceIPAddress": "source_ip",
    "IPAddress": "source_ip",
    "requestParameters.roleArn": "roleArn",
    "User": "user",
}


class SigmaRuleError(ValueError):
    """A rule uses syntax this engine does not support, or is malformed."""


# ----------------------------------------------------------------- value matching
def _event_value(event, field):
    details = event.get("details", {}) or {}
    if field in details:
        return details[field], True
    alias = FIELD_ALIASES.get(field)
    for key in (alias, field):
        if key and key in event:
            return event[key], True
        if key and key in details:
            return details[key], True
    return None, False


def _glob_to_regex(pattern):
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE | re.DOTALL)


def _match_one(actual, expected, modifiers):
    if expected is None:
        return actual is None
    if actual is None:
        return False
    if "re" in modifiers:
        return re.search(str(expected), str(actual)) is not None
    if "cidr" in modifiers:
        try:
            return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            return False
    for op in ("gt", "gte", "lt", "lte"):
        if op in modifiers:
            try:
                a, e = float(actual), float(expected)
            except (TypeError, ValueError):
                return False
            return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]
    a, e = str(actual), str(expected)
    if isinstance(actual, bool):
        a = a.lower()
    if "contains" in modifiers:
        pattern = "*" + e + "*"
    elif "startswith" in modifiers:
        pattern = e + "*"
    elif "endswith" in modifiers:
        pattern = "*" + e
    else:
        pattern = e
    if "*" in pattern or "?" in pattern:
        return _glob_to_regex(pattern).match(a) is not None
    return a.lower() == pattern.lower()


def _match_field(event, spec, expected):
    field, *modifiers = spec.split("|")
    known = {"contains", "startswith", "endswith", "all", "re", "cidr", "exists", "gt", "gte", "lt", "lte"}
    unknown = set(modifiers) - known
    if unknown:
        raise SigmaRuleError(f"unsupported modifier(s) {sorted(unknown)} on {field}")
    actual, present = _event_value(event, field)
    if "exists" in modifiers:
        return present == bool(expected)
    values = expected if isinstance(expected, list) else [expected]
    if "all" in modifiers:
        return all(_match_one(actual, v, modifiers) for v in values)
    return any(_match_one(actual, v, modifiers) for v in values)


def _match_selection(event, selection):
    if isinstance(selection, dict):
        return all(_match_field(event, spec, value) for spec, value in selection.items())
    if isinstance(selection, list):
        if all(isinstance(item, dict) for item in selection):
            return any(_match_selection(event, item) for item in selection)
        # keyword list: any keyword appears in any value of the event
        haystack = " ".join(str(v) for v in list((event.get("details") or {}).values()) + list(event.values())).lower()
        return any(str(k).lower().strip("*") in haystack for k in selection)
    raise SigmaRuleError(f"unsupported selection type {type(selection).__name__}")


# ----------------------------------------------------------------- condition parser
_TOKEN_RE = re.compile(r"\s*(\(|\)|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+)\s*", re.I)


def _tokenize(condition):
    if "|" in condition:
        raise SigmaRuleError("aggregation conditions ('| count()') are not supported; use a correlation rule")
    pos, tokens = 0, []
    while pos < len(condition):
        m = _TOKEN_RE.match(condition, pos)
        if not m or m.end() == pos:
            raise SigmaRuleError(f"cannot parse condition near: {condition[pos:pos + 20]!r}")
        tokens.append(m.group(1).lower() if m.group(1).lower() in ("and", "or", "not", "1 of", "all of") else m.group(1))
        pos = m.end()
    return tokens


class _Parser:
    """Recursive descent: or_expr := and_expr ('or' and_expr)*; and_expr := unary ('and' unary)*."""

    def __init__(self, tokens, selections):
        self.tokens, self.pos, self.selections = tokens, 0, selections

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self):
        node = self.or_expr()
        if self.peek() is not None:
            raise SigmaRuleError(f"unexpected token {self.peek()!r}")
        return node

    def or_expr(self):
        node = self.and_expr()
        while self.peek() == "or":
            self.take()
            node = ("or", node, self.and_expr())
        return node

    def and_expr(self):
        node = self.unary()
        while self.peek() == "and":
            self.take()
            node = ("and", node, self.unary())
        return node

    def unary(self):
        tok = self.take()
        if tok == "not":
            return ("not", self.unary())
        if tok == "(":
            node = self.or_expr()
            if self.take() != ")":
                raise SigmaRuleError("unbalanced parentheses")
            return node
        if tok in ("1 of", "all of"):
            target = self.take()
            names = list(self.selections) if target == "them" else [n for n in self.selections if fnmatch.fnmatch(n, target)]
            if not names:
                raise SigmaRuleError(f"'{tok} {target}' matches no selection")
            return ("any" if tok == "1 of" else "all", names)
        if tok is None or tok in ("and", "or", ")"):
            raise SigmaRuleError("incomplete condition")
        if tok not in self.selections:
            raise SigmaRuleError(f"condition references unknown selection {tok!r}")
        return ("sel", tok)


def _evaluate(node, event, selections):
    kind = node[0]
    if kind == "sel":
        return _match_selection(event, selections[node[1]])
    if kind == "not":
        return not _evaluate(node[1], event, selections)
    if kind == "and":
        return _evaluate(node[1], event, selections) and _evaluate(node[2], event, selections)
    if kind == "or":
        return _evaluate(node[1], event, selections) or _evaluate(node[2], event, selections)
    if kind == "any":
        return any(_match_selection(event, selections[n]) for n in node[1])
    if kind == "all":
        return all(_match_selection(event, selections[n]) for n in node[1])
    raise SigmaRuleError(f"bad node {kind}")


# ----------------------------------------------------------------- rules
class SigmaRule:
    def __init__(self, path, doc, soar):
        self.path = path
        self.file = os.path.relpath(path, ROOT).replace("\\", "/")
        self.doc = doc
        self.id = doc.get("id")
        self.title = doc.get("title")
        self.level = str(doc.get("level", "medium")).lower()
        self.tags = doc.get("tags", []) or []
        self.logsource = doc.get("logsource", {}) or {}
        detection = dict(doc.get("detection") or {})
        condition = detection.pop("condition", None)
        detection.pop("timeframe", None)
        if not condition:
            raise SigmaRuleError(f"{self.file}: missing detection.condition")
        conditions = condition if isinstance(condition, list) else [condition]
        self.selections = detection
        try:
            self.conditions = [_Parser(_tokenize(c), detection).parse() for c in conditions]
        except SigmaRuleError as exc:
            raise SigmaRuleError(f"{self.file}: {exc}") from None
        self.soar = soar or {}

    @property
    def technique_ids(self):
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"^attack\.t\d{4}", str(t))]

    def _logsource_allows(self, event):
        product = self.logsource.get("product")
        category, service = self.logsource.get("category"), self.logsource.get("service")
        if category:
            ids = LOGSOURCE_EVENT_IDS.get((product, category))
            if ids is None:
                return False
            try:
                if int(event.get("event_id")) not in ids:
                    return False
            except (TypeError, ValueError):
                return False
        if service:
            sources = LOGSOURCE_SOURCES.get((product, service))
            if sources is None or event.get("event_source") not in sources:
                return False
        return True

    def matches(self, event):
        if not self._logsource_allows(event):
            return False
        return any(_evaluate(c, event, self.selections) for c in self.conditions)

    def as_matched_rule(self):
        severity = self.soar.get("severity") or LEVEL_TO_SEVERITY.get(self.level, "MEDIUM")
        techniques = self.technique_ids
        return {
            "rule_id": self.soar.get("soc_rule_id", self.id),
            "rule_name": self.soar.get("name", self.title),
            "severity": severity,
            "mitre_id": self.soar.get("mitre_id") or (techniques[0] if techniques else "Unknown"),
            "action_recommended": self.soar.get("action_recommended", "ENRICH_AND_ALERT_ANALYST"),
            "sigma_id": self.id,
            "sigma_file": self.file,
        }


class SigmaEngine:
    def __init__(self, rules_dir=DEFAULT_RULES_DIR, mapping_path=DEFAULT_MAPPING):
        self.rules_dir = rules_dir
        self.mapping = {}
        if mapping_path and os.path.exists(mapping_path):
            with open(mapping_path, encoding="utf-8") as fh:
                self.mapping = (yaml.safe_load(fh) or {}).get("rules", {})
        self.rules = self._load()

    def _load(self):
        rules = []
        for name in sorted(os.listdir(self.rules_dir)):
            if not name.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(self.rules_dir, name)
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            if not isinstance(doc, dict) or "detection" not in doc:
                continue  # correlation rules and non-rule YAML are handled elsewhere
            rules.append(SigmaRule(path, doc, self.mapping.get(doc.get("id"))))
        return rules

    def match_all(self, event):
        return [r for r in self.rules if r.matches(event)]

    def evaluate(self, event):
        """Best match (highest severity, then rule id) as the pipeline's matched_rule, or None."""
        hits = self.match_all(event)
        if not hits:
            return None
        hits.sort(key=lambda r: (-SEVERITY_ORDER.get(r.as_matched_rule()["severity"], 0), str(r.as_matched_rule()["rule_id"])))
        best = hits[0].as_matched_rule()
        best["also_matched"] = [h.as_matched_rule()["rule_id"] for h in hits[1:]]
        return best
