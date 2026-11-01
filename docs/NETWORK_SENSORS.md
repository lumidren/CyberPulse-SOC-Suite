# Network Sensors: Zeek and Suricata

Roadmap F72. CyberPulse ingests network telemetry from your own Zeek and Suricata sensors
(`soar/network_sensors.py`); it does not run a sensor itself.

**Sending data.** Batch JSON records to `POST /api/ingest/network`, HMAC-signed exactly like
`/api/ingest` (`INGEST_HMAC_SECRET`, see `scripts/send_signed_event.py`), at most 500 per
batch:

```json
{"sensor": "zeek", "log": "dns", "records": [ { "ts": 1793500000.5, "id.orig_h": "10.0.2.15", "query": "..." } ]}
{"sensor": "suricata", "records": [ { "event_type": "alert", "src_ip": "...", "alert": { "severity": 1 } } ]}
```

- Zeek: `conn`, `dns`, `ssl`, `http` logs in JSON (`redef LogAscii::use_json = T;`).
- Suricata: EVE records with `event_type: alert` only.
- A log shipper (Vector, Filebeat, Fluent Bit) that batches and signs requests is the usual
  path; any such configuration is yours to build and has not been tested here.

Only metadata fields on the ingest allowlist are kept (no HTTP bodies, no packet payloads),
and each record is validated like any other event. The response lists accepted and rejected
records and any incidents raised.

**Detections:** `SOC-RULE-051` (Suricata severity-1 alert) and `SOC-RULE-052` (Windows
executable fetched over HTTP by a script client or from a raw IP), plus DNS tunnelling,
beaconing and TLS-fingerprint detections (F73, F74). All are alert-only.

**Not verified:** no live Zeek or Suricata sensor has been connected; rules are tested on
synthetic records only.
