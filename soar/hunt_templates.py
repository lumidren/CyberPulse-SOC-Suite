"""
Hypothesis-driven hunt templates mapped to ATT&CK (roadmap F67).

Each file in hunts/templates/*.yml states a hypothesis, the ATT&CK techniques it tests,
the data it needs, ordered steps (``stack``, ``search`` or ``pivot`` over the hunting
event store), the usual benign explanations and what to do next. Running a template only
reads data; it never alerts or acts.
"""

import os
import re

import yaml

from soar import views
from soar.sigma_engine import ROOT

TEMPLATE_DIR = os.path.join(ROOT, "hunts", "templates")
STEP_TYPES = {"stack", "search", "pivot"}
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def load_templates(directory=TEMPLATE_DIR):
    templates = {}
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".yml"):
            continue
        with open(os.path.join(directory, name), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        doc["id"] = name[:-4]
        problems = validate(doc)
        if problems:
            raise ValueError(f"{name}: {problems}")
        templates[doc["id"]] = doc
    return templates


def validate(doc):
    problems = [f"missing {k}" for k in ("name", "hypothesis", "attack", "steps", "benign", "next_steps") if not doc.get(k)]
    problems += [f"bad technique {t}" for t in doc.get("attack") or [] if not TECHNIQUE_RE.match(str(t))]
    problems += [f"bad step type {s.get('type')}" for s in doc.get("steps") or [] if s.get("type") not in STEP_TYPES]
    return problems


def run_template(orchestrator, template):
    results = []
    for step in template["steps"]:
        if step["type"] == "stack":
            out = views.stack(orchestrator, step["field"], step.get("where_field"), step.get("where_value"))
            finding = f"{out.get('tail', 0)} long-tail value(s) of {out.get('distinct', 0)}"
        elif step["type"] == "search":
            out = views.search(orchestrator, step["query"])
            finding = f"{out.get('total', 0)} match(es)"
        else:
            out = views.pivot(orchestrator, step["field"], step["value"])
            finding = f"{out.get('events', 0)} event(s)"
        results.append({"step": step, "finding": finding, "result": out})
    return {"template": {k: v for k, v in template.items() if k != "steps"}, "steps": results}
