"""
Plugin Registry for Enrichers and Responders (CyberPulse SOC Lab)

New enrichment sources and containment actions can be added without editing
the core engine:

    from soar.plugins import register_enricher, register_responder

    @register_enricher("my_feed")
    def my_feed(event):                      # -> dict merged into intel["plugins"]["my_feed"]
        return {"verdict": "clean"}

    @register_responder("QUARANTINE_EMAIL")
    def quarantine(action_record):           # fills execution fields of the record
        action_record["execution_log"] = "..."

Safety properties:
* Plugins are imported only from the repository's `plugins` package and only
  when listed in CYBERPULSE_PLUGINS (comma-separated module names). Arbitrary
  file paths or packages are refused.
* Responder plugins run inside ResilientContainmentEngine._apply_action, i.e.
  after the kill switch, protected-asset/account, rate-limit and approval
  gates. Their action types get the strictest blast-radius tier unless listed
  in soar/action_tiers.py, so they always need analyst approval.
* A failing enricher is isolated: its error is recorded, the pipeline goes on.
"""

import importlib
import logging
import os
import re

logger = logging.getLogger("cyberpulse.plugins")

ENRICHERS = {}
RESPONDERS = {}
_MODULE_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def register_enricher(name):
    def decorator(fn):
        ENRICHERS[name] = fn
        return fn
    return decorator


def register_responder(action_type):
    def decorator(fn):
        RESPONDERS[action_type] = fn
        return fn
    return decorator


def load_plugins(names=None):
    """Import the listed modules from the `plugins` package. Returns the loaded module names."""
    raw = names if names is not None else os.environ.get("CYBERPULSE_PLUGINS", "")
    loaded = []
    for name in [n.strip() for n in raw.split(",") if n.strip()]:
        if not _MODULE_RE.match(name):
            logger.warning("Refusing plugin %r: only module names inside the 'plugins' package are allowed", name)
            continue
        importlib.import_module(f"plugins.{name}")
        loaded.append(name)
    return loaded


def run_enrichers(event):
    """Run every registered enricher; failures are recorded, never raised."""
    results = {}
    for name, fn in ENRICHERS.items():
        try:
            results[name] = fn(event)
        except Exception as exc:
            logger.exception("Enricher plugin %s failed", name)
            results[name] = {"status": "ERROR", "error": str(exc)}
    return results
