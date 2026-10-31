"""
Structured Logging & Prometheus Metrics (CyberPulse SOC Lab)

* JsonLogFormatter: one JSON object per log line (LOG_FORMAT=json) so logs can
  be shipped to a SIEM without regex parsing.
* render_prometheus(): Prometheus text exposition (version 0.0.4) for
  GET /metrics. Latency figures are lab-measured, in-process timings.
"""

import json
import logging
from collections import Counter
from datetime import datetime, timezone

LATENCY_BUCKETS_MS = (0.01, 0.05, 0.1, 0.5, 1, 5, 10, 50, 100, 500, 1000)


class JsonLogFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**labels):
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items()) + "}" if labels else ""


def render_prometheus(orchestrator):
    lines = []

    def metric(name, kind, help_text, samples):
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lines.append(f"{name}{_labels(**labels)} {value}")

    incidents = orchestrator.dfir_engine.incident_list
    by_rule_status = Counter((i.get("rule", {}).get("rule_id", "unknown"), i.get("status", "unknown")) for i in incidents)
    metric("cyberpulse_incidents", "gauge", "Incidents currently held, by rule and status.",
           [({"rule": r, "status": s}, n) for (r, s), n in sorted(by_rule_status.items())] or [({}, 0)])

    actions = orchestrator.containment_engine.action_registry.values()
    by_action = Counter((a["action_type"], a["status"]) for a in actions)
    metric("cyberpulse_containment_actions", "gauge", "Containment action records, by action and status.",
           [({"action": a, "status": s}, n) for (a, s), n in sorted(by_action.items())] or [({}, 0)])

    safety = orchestrator.containment_engine.safety
    metric("cyberpulse_pending_approvals", "gauge", "Containment actions waiting for an analyst.",
           [({}, len(orchestrator.containment_engine.pending_approvals()))])
    metric("cyberpulse_kill_switch_engaged", "gauge", "1 while the global automation kill switch is engaged.",
           [({}, 1 if safety.is_halted() else 0)])
    metric("cyberpulse_containment_executions_last_hour", "gauge", "Executed containment actions in the rolling hour.",
           [({}, safety.executions_last_hour())])

    latencies = orchestrator.metrics_engine.total_pipeline_latencies
    lines.append("# HELP cyberpulse_pipeline_latency_ms Lab-measured in-process pipeline latency (emulated traffic).")
    lines.append("# TYPE cyberpulse_pipeline_latency_ms histogram")
    for bound in LATENCY_BUCKETS_MS:
        lines.append(f'cyberpulse_pipeline_latency_ms_bucket{{le="{bound}"}} {sum(1 for v in latencies if v <= bound)}')
    lines.append(f'cyberpulse_pipeline_latency_ms_bucket{{le="+Inf"}} {len(latencies)}')
    lines.append(f"cyberpulse_pipeline_latency_ms_sum {round(sum(latencies), 6)}")
    lines.append(f"cyberpulse_pipeline_latency_ms_count {len(latencies)}")
    return "\n".join(lines) + "\n"
