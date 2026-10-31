"""
Rule versioning helpers (roadmap F7).

A rule's *detection fingerprint* is a SHA-256 over its logsource and detection
block in canonical JSON. rules/soar_mapping.yml stores the fingerprint next to
the rule's version; if the logic changes without a version bump (and a
rules/RULE_CHANGELOG.md entry), tests/test_rule_versioning.py fails.
"""

import hashlib
import json


def detection_fingerprint(rule_doc):
    payload = {"logsource": rule_doc.get("logsource"), "detection": rule_doc.get("detection")}
    canonical = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
