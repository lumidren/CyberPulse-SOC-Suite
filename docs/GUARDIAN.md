# GUARDIAN Anomaly Alerts

Roadmap F39. **Stub: GUARDIAN's real alert schema has not been checked; the expected
format is documented in `soar/guardian.py`.**

GUARDIAN POSTs each anomaly to `POST /api/ingest/guardian`, HMAC-signed exactly like
`/api/ingest` (`INGEST_HMAC_SECRET`, `X-CyberPulse-Timestamp`, `X-CyberPulse-Signature`;
see `scripts/send_signed_event.py`). The alert is converted to a pipeline event
(`event_source: guardian:anomaly`, event id 9950), validated like any ingested event,
and run through the Sigma rules.

The shipped rule `SOC-RULE-049` (`rules/sigma/guardian_high_score_anomaly.yml`) alerts
on `AnomalyScore >= 0.8`. An anomaly score is a statistical signal, not proof, so the
rule only alerts (`ENRICH_AND_ALERT_ANALYST`); nothing is contained on a model's say-so.
The response says whether an incident was raised.

This is the route for detections threshold rules miss, such as low-and-slow password
spraying spread over days (see [coverage/GAPS.md](coverage/GAPS.md)).
