#!/usr/bin/env python3
"""
Reproducible in-process pipeline benchmark for the CyberPulse SOC Lab.

Runs every scripted attack generator N times through the SOAR pipeline (in
DRY_RUN mode, so no responder state changes) and prints per-stage latency
percentiles. These are lab measurements on emulated telemetry: detection runs
against synthetic events, enrichment reads a local cache, and responders are
simulated, so the numbers say nothing about production SOC latency.

Usage:
    python scripts/benchmark_pipeline.py [--runs 20] [--json]
"""

import argparse
import json
import os
import platform
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from simulator.attack_simulator import SCRIPTED_GENERATORS  # noqa: E402
from soar.metrics_engine import calculate_percentile  # noqa: E402
from soar.soar_engine import SOAROrchestrator  # noqa: E402


def run_benchmark(runs):
    orchestrator = SOAROrchestrator(policy_mode="DRY_RUN")
    stages = {"detection_ms": [], "enrichment_ms": [], "containment_ms": [], "total_ms": []}
    detected = 0
    attempted = 0

    for _ in range(runs):
        for _name, generator in SCRIPTED_GENERATORS:
            attempted += 1
            incident = orchestrator.process_event(generator())
            if not incident:
                continue
            detected += 1
            t = incident["pipeline_timing"]
            stages["detection_ms"].append(t["stage1_detection_ms"])
            stages["enrichment_ms"].append(t["stage2_threat_intel_ms"])
            stages["containment_ms"].append(t["stage3_containment_ms"])
            stages["total_ms"].append(t["total_pipeline_latency_ms"])

    # Report microseconds: in-process stages are far below a millisecond.
    summary = {
        stage.replace("_ms", "_us"): {
            "p50": calculate_percentile([v * 1000 for v in values], 50),
            "p95": calculate_percentile([v * 1000 for v in values], 95),
            "max": round(max(values) * 1000, 2) if values else None,
        }
        for stage, values in stages.items()
    }
    return {
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "basis": "Lab-measured, in-process, emulated telemetry, simulated responders (DRY_RUN)",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "runs_per_generator": runs,
        "events_attempted": attempted,
        "events_detected": detected,
        "latency_us": summary,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--runs", type=int, default=20, help="runs per attack generator")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    args = parser.parse_args()

    result = run_benchmark(args.runs)
    if args.json:
        print(json.dumps(result, indent=2))
        return

    print(f"CyberPulse lab pipeline benchmark ({result['basis']})")
    print(f"  {result['platform']} / Python {result['python']} / {result['measured_at']}")
    print(f"  events detected: {result['events_detected']}/{result['events_attempted']}")
    for stage, stats in result["latency_us"].items():
        print(f"  {stage:<15} p50={stats['p50']:>8} us   p95={stats['p95']:>8} us   max={stats['max']} us")


if __name__ == "__main__":
    main()
