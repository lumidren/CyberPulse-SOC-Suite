"""
Beaconing detection over Zeek conn logs (roadmap F73).

Implants that phone home on a timer produce connections from one host to one destination
at near-constant intervals. Sigma cannot express "regular timing", so this is an analytic
over the hunting event store: group zeek:conn events by (source, destination, port),
compute the gaps between connections, and flag series that are long enough and regular
enough. Jitter-heavy implants and very slow beacons slip past by design of the thresholds;
results are hunting leads, not alerts.

Defaults (override per call): at least 8 connections, mean gap of at least 10 s, and a
coefficient of variation (stdev / mean of the gaps) below 0.15.
"""

import statistics
from datetime import datetime


def _ts(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def find_beacons(events, min_connections=8, min_interval_sec=10.0, max_cv=0.15, allow_destinations=()):
    series = {}
    for event in events:
        if event.get("event_source") != "zeek:conn":
            continue
        details = event.get("details") or {}
        t = _ts(event.get("timestamp"))
        dst = details.get("id.resp_h")
        if t is None or not dst or dst in allow_destinations:
            continue
        series.setdefault((event.get("source_ip"), dst, details.get("id.resp_p")), []).append(t)
    beacons = []
    for (src, dst, port), times in series.items():
        times.sort()
        if len(times) < min_connections:
            continue
        gaps = [b - a for a, b in zip(times, times[1:], strict=False) if b > a]
        if len(gaps) < min_connections - 1:
            continue
        mean = statistics.fmean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else float("inf")
        if mean >= min_interval_sec and cv <= max_cv:
            beacons.append({"source_ip": src, "destination": dst, "port": port, "connections": len(times),
                            "mean_interval_sec": round(mean, 2), "jitter_cv": round(cv, 3),
                            "first_seen": datetime.fromtimestamp(times[0]).isoformat(),
                            "last_seen": datetime.fromtimestamp(times[-1]).isoformat()})
    return sorted(beacons, key=lambda b: (b["jitter_cv"], -b["connections"]))
