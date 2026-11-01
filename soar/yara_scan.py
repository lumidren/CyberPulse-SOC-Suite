"""
YARA scanning of collected evidence (roadmap F70).

Scans files with the rules in rules/yara/*.yar. Uses ``yara-python`` (libyara) when it is
installed, which supports the full language. Without it, a small built-in matcher handles
the subset the shipped rules use, and refuses anything else rather than guessing:

  * text strings with the ``ascii``, ``wide`` and ``nocase`` modifiers;
  * hex strings without jumps or wildcards, e.g. ``{ 4D 5A 90 00 }``;
  * conditions ``any of them``, ``all of them``, ``N of them``, ``N of ($prefix*)``,
    and single ``$name`` terms joined by ``and`` / ``or``.

Only files inside ``SANDBOX_EVIDENCE_DIR`` (where collected samples are dropped) can be
scanned through the API, so it cannot be used to read other files on the host. Files are
read up to 64 MB. Scanning never executes anything.
"""

import glob
import os
import re

from soar.sigma_engine import ROOT

RULE_DIR = os.path.join(ROOT, "rules", "yara")
MAX_BYTES = 64 * 1024 * 1024
RULE_RE = re.compile(r"rule\s+(\w+)\s*(?::[^{]*)?\{(.*?)\n\}", re.S)
SECTION_RE = re.compile(r"(meta|strings|condition)\s*:(.*?)(?=\n\s*(?:meta|strings|condition)\s*:|\Z)", re.S)
STRING_RE = re.compile(r'(\$\w*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"((?:\s+\w+)*)|\{([0-9A-Fa-f\s]+)\})')
META_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


class YaraUnsupported(ValueError):
    pass


def _variants(text, modifiers):
    raw = text.encode("latin-1", errors="replace").decode("unicode_escape").encode("latin-1", errors="replace")
    forms = []
    if "wide" not in modifiers or "ascii" in modifiers:
        forms.append(raw)
    if "wide" in modifiers:
        forms.append(b"".join(bytes([b, 0]) for b in raw))
    return forms


class BuiltinRule:
    def __init__(self, name, body):
        self.name = name
        sections = {k: v for k, v in SECTION_RE.findall(body)}
        self.meta = dict(META_RE.findall(sections.get("meta", "")))
        self.strings = {}
        for ident, text, modifiers, hexbytes in STRING_RE.findall(sections.get("strings", "")):
            mods = set(modifiers.split())
            unsupported = mods - {"ascii", "wide", "nocase"}
            if unsupported:
                raise YaraUnsupported(f"{name}: modifiers {sorted(unsupported)} need yara-python")
            if hexbytes:
                self.strings[ident] = ([bytes.fromhex(hexbytes.replace(" ", "").replace("\n", ""))], False)
            else:
                self.strings[ident] = (_variants(text, mods), "nocase" in mods)
        self.condition = " ".join(sections.get("condition", "").split())
        self._check_condition()

    def _check_condition(self):
        c = self.condition
        if re.fullmatch(r"(any|all|\d+) of (them|\(\$\w*\*?\))", c):
            return
        if re.fullmatch(r"\$\w+( (and|or) \$\w+)*", c):
            return
        raise YaraUnsupported(f"{self.name}: condition '{c}' needs yara-python")

    def _hits(self, data):
        lowered = data.lower()
        hits = set()
        for ident, (forms, nocase) in self.strings.items():
            haystack = lowered if nocase else data
            if any((f.lower() if nocase else f) in haystack for f in forms):
                hits.add(ident)
        return hits

    def matches(self, data):
        hits = self._hits(data)
        c = self.condition
        m = re.fullmatch(r"(any|all|\d+) of (them|\(\$(\w*)(\*?)\))", c)
        if m:
            quantity, _, prefix, star = m.groups()
            pool = [s for s in self.strings if m.group(2) == "them" or (s.startswith(f"${prefix}") if star else s == f"${prefix}")]
            needed = len(pool) if quantity == "all" else (1 if quantity == "any" else int(quantity))
            return sum(1 for s in pool if s in hits) >= needed, sorted(hits)
        terms = c.split()
        result = terms[0] in hits
        for op, term in zip(terms[1::2], terms[2::2], strict=True):
            result = (result and term in hits) if op == "and" else (result or term in hits)
        return result, sorted(hits)


def load_rules(directory=RULE_DIR):
    """('yara-python', compiled) or ('builtin', [BuiltinRule])."""
    paths = sorted(glob.glob(os.path.join(directory, "*.yar")))
    try:
        import yara  # type: ignore[import-not-found]
        return "yara-python", yara.compile(filepaths={os.path.basename(p): p for p in paths})
    except ImportError:
        rules = []
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                text = re.sub(r"/\*.*?\*/", "", fh.read(), flags=re.S)
            rules += [BuiltinRule(name, body) for name, body in RULE_RE.findall(text)]
        return "builtin", rules


def scan_bytes(data, engine=None):
    engine = engine or load_rules()
    kind, rules = engine
    if kind == "yara-python":
        return [{"rule": m.rule, "meta": m.meta, "strings": sorted({s.identifier for s in m.strings})}
                for m in rules.match(data=data)]
    out = []
    for rule in rules:
        matched, hits = rule.matches(data)
        if matched:
            out.append({"rule": rule.name, "meta": rule.meta, "strings": hits})
    return out


def scan_evidence_file(path, evidence_dir=None, engine=None):
    evidence_dir = evidence_dir if evidence_dir is not None else os.environ.get("SANDBOX_EVIDENCE_DIR", "")
    if not evidence_dir:
        return {"status": "DISABLED", "message": "set SANDBOX_EVIDENCE_DIR to scan collected files"}
    root, real = os.path.realpath(evidence_dir), os.path.realpath(os.path.join(evidence_dir, path))
    if os.path.commonpath([root, real]) != root or not os.path.isfile(real):
        return {"status": "REFUSED", "message": "only files inside SANDBOX_EVIDENCE_DIR can be scanned"}
    with open(real, "rb") as fh:
        data = fh.read(MAX_BYTES)
    engine = engine or load_rules()
    return {"status": "OK", "engine": engine[0], "file": os.path.relpath(real, root), "bytes": len(data),
            "matches": scan_bytes(data, engine)}
