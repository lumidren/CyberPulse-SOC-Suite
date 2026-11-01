"""
Zeek and Suricata as network sensors (roadmap F72).

Converts sensor JSON records into pipeline events so the Sigma rules can run on network
telemetry:

  * Zeek ``conn``, ``dns``, ``ssl`` and ``http`` logs (JSON output, ``LogAscii::use_json=T``)
    -> ``event_source: zeek:<log>``, fields keep Zeek's own names (``query``, ``id.resp_h``,
    ``server_name``, ``ja3``, ``user_agent``...);
  * Suricata EVE ``alert`` records -> ``event_source: suricata:alert`` with the signature,
    category, severity and flow endpoints.

Records arrive in batches at ``POST /api/ingest/network`` (HMAC-signed like ``/api/ingest``):
``{"sensor": "zeek", "log": "dns", "records": [...]}``, at most MAX_BATCH records. Each
converted event is validated and minimised like any other ingested event, so only
allowlisted fields are kept. Payloads (HTTP bodies, packet data) are never ingested.
"""

from datetime import datetime, timezone

MAX_BATCH = 500
ZEEK_LOGS = {"conn", "dns", "ssl", "http"}
ZEEK_EVENT_IDS = {"conn": 9970, "dns": 9971, "ssl": 9972, "http": 9973}
SURICATA_EVENT_ID = 9980
ZEEK_FIELDS = {
    "conn": ("proto", "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "id.resp_p"),
    "dns": ("query", "qtype_name", "rcode_name", "answers", "id.resp_p"),
    "ssl": ("server_name", "version", "ja3", "ja3s", "ja4", "validation_status", "id.resp_p"),
    "http": ("method", "host", "uri", "user_agent", "status_code", "resp_mime_types", "id.resp_p"),
}


class SensorFormatError(ValueError):
    pass


def _ts(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    return str(value) if value else datetime.now(timezone.utc).isoformat()


def zeek_to_event(log, record):
    if log not in ZEEK_LOGS:
        raise SensorFormatError(f"unsupported Zeek log {log!r}; use one of {sorted(ZEEK_LOGS)}")
    if not isinstance(record, dict) or not record.get("id.orig_h"):
        raise SensorFormatError("Zeek record needs id.orig_h (JSON log output)")
    details = {k: record[k] for k in ZEEK_FIELDS[log] if k in record}
    details["id.resp_h"] = record.get("id.resp_h")
    details["uid"] = record.get("uid")
    return {
        "event_id": ZEEK_EVENT_IDS[log], "event_source": f"zeek:{log}", "timestamp": _ts(record.get("ts")),
        "computer_name": record.get("_sensor_host") or record.get("id.orig_h"), "source_ip": record["id.orig_h"],
        "details": details,
    }


def suricata_to_event(record):
    if not isinstance(record, dict) or record.get("event_type") != "alert" or "alert" not in record:
        raise SensorFormatError("only Suricata EVE records with event_type 'alert' are ingested")
    alert = record["alert"]
    return {
        "event_id": SURICATA_EVENT_ID, "event_source": "suricata:alert", "timestamp": _ts(record.get("timestamp")),
        "computer_name": record.get("host") or record.get("src_ip"), "source_ip": record.get("src_ip"),
        "details": {"SignatureId": alert.get("signature_id"), "Signature": alert.get("signature"),
                    "Category": alert.get("category"), "Severity": alert.get("severity"),
                    "DestinationIp": record.get("dest_ip"), "DestinationPort": record.get("dest_port"),
                    "Protocol": record.get("proto")},
    }


def convert_batch(payload):
    """List of pipeline events from a sensor batch, or SensorFormatError."""
    if not isinstance(payload, dict):
        raise SensorFormatError("body must be a JSON object")
    records = payload.get("records")
    if not isinstance(records, list) or not records:
        raise SensorFormatError("records must be a non-empty list")
    if len(records) > MAX_BATCH:
        raise SensorFormatError(f"at most {MAX_BATCH} records per batch")
    sensor = payload.get("sensor")
    if sensor == "zeek":
        return [zeek_to_event(payload.get("log"), r) for r in records]
    if sensor == "suricata":
        return [suricata_to_event(r) for r in records]
    raise SensorFormatError("sensor must be zeek or suricata")
