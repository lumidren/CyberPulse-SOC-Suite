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
* live VirusTotal / AbuseIPDB / OTX / URLhaus / GreyNoise verdicts, when external
  enrichment is enabled.

Weighted consensus (roadmap F42): each source has a weight (how much its verdict is
trusted; REPUTATION_WEIGHTS overrides the defaults, e.g. "AlienVault OTX=0.4"). The raw
score is the weighted mean of the flagging sources. ``agreement`` is the share of the
total weight of all reporting sources that flags the indicator, so one flag among several
"clean" answers is diluted. A corroborated result scores raw x agreement; an
uncorroborated one (fewer than two flagging sources) scores raw x UNCORROBORATED_WEIGHT.
When every reporting source flags (as with the lab fixture), agreement is 1 and the score
equals the unweighted result.
"""

import os
from typing import Any, Dict, List, Optional


FIXTURE_TIMESTAMP = "static lab fixture (synthetic, no lookup time)"
MIN_CORROBORATING_SOURCES = 2
UNCORROBORATED_WEIGHT = 0.5

DEFAULT_WEIGHTS = {
    "VirusTotal": 1.0, "AbuseIPDB": 1.0, "URLhaus": 1.0,
    "GreyNoise": 0.8,       # strong on scanners, silent on targeted infrastructure
    "AlienVault OTX": 0.6,  # community pulses: broad, noisier
}
FIXTURE_WEIGHT = 1.0


def weights() -> Dict[str, float]:
    """Source weights, with REPUTATION_WEIGHTS="Name=0.5,Other=1" overriding the defaults."""
    out = dict(DEFAULT_WEIGHTS)
    for item in os.environ.get("REPUTATION_WEIGHTS", "").split(","):
        name, sep, value = item.partition("=")
        if sep:
            try:
                out[name.strip()] = max(0.0, float(value))
            except ValueError:
                continue
    return out


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
            elif v.get("score") is not None and "flags" in v:
                # OTX, URLhaus, GreyNoise (soar/intel_providers.py); context-only providers carry no score
                signals.append({"source": v["source"], "score": float(v["score"]), "flags": bool(v["flags"]),
                                "observed_at": v.get("fetched_at"), "cached": part.get("cached", False),
                                "attribution": v.get("attribution")})
    return signals


def consensus(intel: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return {'score', 'raw_score', 'sources', 'flagging_sources', 'corroborated'}."""
    signals = _signals(intel or {})
    table = weights()
    for s in signals:
        s["weight"] = FIXTURE_WEIGHT if s["source"].startswith("lab-fixture") else table.get(s["source"], 1.0)
    flagging = [s for s in signals if s["flags"] and s["weight"] > 0]
    flag_weight = sum(s["weight"] for s in flagging)
    total_weight = sum(s["weight"] for s in signals)
    raw = sum(s["score"] * s["weight"] for s in flagging) / flag_weight if flag_weight else 0.0
    agreement = flag_weight / total_weight if total_weight else 0.0
    corroborated = len(flagging) >= MIN_CORROBORATING_SOURCES
    score = raw * agreement if corroborated else raw * UNCORROBORATED_WEIGHT
    return {
        "score": round(score, 1),
        "raw_score": round(raw, 1),
        "agreement": round(agreement, 3),
        "sources": signals,
        "flagging_sources": [s["source"] for s in flagging],
        "corroborated": corroborated,
    }
