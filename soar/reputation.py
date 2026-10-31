"""
Multi-Source Reputation Consensus (CyberPulse SOC Lab)

Turns every reputation signal for an indicator into one explainable result.
No single source decides on its own: the threat-intel factor counts at full
weight only when at least MIN_CORROBORATING_SOURCES independent sources flag
the indicator; a lone source is counted at half weight and the result is
marked uncorroborated.

Signals:
* lab fixture (synthetic): its two simulated provider fields are treated as two
  separate simulated signals, mirroring how the fixture models two providers.
* live VirusTotal / AbuseIPDB verdicts, when external enrichment is enabled.
"""

from typing import Any, Dict, List, Optional


FIXTURE_TIMESTAMP = "static lab fixture (synthetic, no lookup time)"
MIN_CORROBORATING_SOURCES = 2
UNCORROBORATED_WEIGHT = 0.5

# A source "flags" an indicator at or above these levels
VT_FLAG_ENGINES = 3
ABUSE_FLAG_CONFIDENCE = 50


def _signals(intel: Dict[str, Any]) -> List[Dict[str, Any]]:
    signals = []
    fixture = intel.get("ip_reputation", {}) or {}
    vt = fixture.get("virustotal_positives") or 0
    abuse = fixture.get("abuse_score") or 0
    if vt or abuse:
        signals.append({"source": "lab-fixture:vt-style (synthetic)", "score": min(100.0, vt / 72.0 * 100.0),
                        "flags": vt >= VT_FLAG_ENGINES, "observed_at": FIXTURE_TIMESTAMP})
        signals.append({"source": "lab-fixture:abuse-style (synthetic)", "score": float(abuse),
                        "flags": abuse >= ABUSE_FLAG_CONFIDENCE, "observed_at": FIXTURE_TIMESTAMP})
    for part in (intel.get("external") or {}).values():
        if not isinstance(part, dict):
            continue
        for v in part.get("verdicts", []):
            if v.get("status"):  # unavailable / rate-limited / refused: not a signal
                continue
            if v.get("source") == "VirusTotal" and v.get("malicious") is not None:
                engines = v["malicious"]
                signals.append({"source": "VirusTotal", "score": min(100.0, engines / 72.0 * 100.0 * 2),
                                "flags": engines >= VT_FLAG_ENGINES, "observed_at": v.get("fetched_at"),
                                "cached": part.get("cached", False), "attribution": v.get("attribution")})
            elif v.get("source") == "AbuseIPDB" and v.get("abuse_confidence") is not None:
                signals.append({"source": "AbuseIPDB", "score": float(v["abuse_confidence"]),
                                "flags": v["abuse_confidence"] >= ABUSE_FLAG_CONFIDENCE, "observed_at": v.get("fetched_at"),
                                "cached": part.get("cached", False), "attribution": v.get("attribution")})
    return signals


def consensus(intel: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return {'score', 'raw_score', 'sources', 'flagging_sources', 'corroborated'}."""
    signals = _signals(intel or {})
    flagging = [s for s in signals if s["flags"]]
    # Mean of the sources that flag the indicator (F42 extends this to weighted consensus)
    raw = sum(s["score"] for s in flagging) / len(flagging) if flagging else 0.0
    corroborated = len(flagging) >= MIN_CORROBORATING_SOURCES
    score = raw if corroborated else raw * UNCORROBORATED_WEIGHT
    return {
        "score": round(score, 1),
        "raw_score": round(raw, 1),
        "sources": signals,
        "flagging_sources": [s["source"] for s in flagging],
        "corroborated": corroborated,
    }
