"""
GUARDIAN anomaly alerts as an ingest source (roadmap F39).

GUARDIAN (the companion anomaly-detection project) is expected to POST alerts to
``/api/ingest/guardian``, HMAC-signed exactly like ``/api/ingest`` (INGEST_HMAC_SECRET).
Each alert is converted to a pipeline event (event_source ``guardian:anomaly``),
validated like any other ingested event, and evaluated by the Sigma rules; the
shipped rule (``guardian_high_score_anomaly.yml``) alerts on scores of 0.8 or more.

Expected alert format (GUARDIAN's real schema has not been checked here; adjust
``guardian_to_event`` if it differs):

    {"alert_id": "g-123", "detected_at": "2026-11-01T10:00:00Z",
     "entity": {"type": "user" | "host" | "ip", "id": "j.doe", "host": "WIN-WS09", "ip": "10.0.2.15"},
     "anomaly_type": "rare_logon_time", "score": 0.91, "model": "iforest-v3",
     "mitre_technique": "T1078", "summary": "..."}

An anomaly score is a statistical signal, not proof: the rule only alerts, and its
playbook routing gives an analyst the decision.
"""

import re

GUARDIAN_EVENT_ID = 9950
GUARDIAN_SOURCE = "guardian:anomaly"
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class GuardianFormatError(ValueError):
    pass


def guardian_to_event(alert):
    if not isinstance(alert, dict):
        raise GuardianFormatError("GUARDIAN alert must be a JSON object")
    entity = alert.get("entity") or {}
    try:
        score = float(alert.get("score"))
    except (TypeError, ValueError) as exc:
        raise GuardianFormatError("score must be a number between 0 and 1") from exc
    if not 0.0 <= score <= 1.0:
        raise GuardianFormatError("score must be a number between 0 and 1")
    if not alert.get("alert_id") or not alert.get("anomaly_type"):
        raise GuardianFormatError("alert_id and anomaly_type are required")
    technique = str(alert.get("mitre_technique") or "")
    event = {
        "event_id": GUARDIAN_EVENT_ID,
        "event_source": GUARDIAN_SOURCE,
        "timestamp": alert.get("detected_at"),
        "computer_name": entity.get("host") or (entity.get("id") if entity.get("type") == "host" else "unknown"),
        "source_ip": entity.get("ip") or (entity.get("id") if entity.get("type") == "ip" else "0.0.0.0"),
        "user": entity.get("id") if entity.get("type") == "user" else entity.get("user"),
        "technique_id": technique if TECHNIQUE_RE.match(technique) else "Unknown",
        "technique_name": f"GUARDIAN anomaly: {alert['anomaly_type']}",
        "details": {
            "GuardianAlertId": str(alert["alert_id"]),
            "AnomalyType": str(alert["anomaly_type"]),
            "AnomalyScore": score,
            "Model": str(alert.get("model", "")),
            "Summary": str(alert.get("summary", ""))[:500],
        },
    }
    return {k: v for k, v in event.items() if v is not None}
