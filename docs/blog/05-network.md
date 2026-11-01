# 5. Looking at the network: DNS tunnelling and TLS fingerprints

> Part of the series *How I built the detections*. Drafted with an AI assistant from this repository's commit history; every number is copied from a generated report linked in the post. All data is synthetic.

Every early detection was host or cloud telemetry. Zeek and Suricata now feed signed batches into
the same pipeline ([NETWORK_SENSORS.md](../NETWORK_SENSORS.md)).

**DNS tunnelling.** Two angles: SOC-RULE-054 looks at a single query (a label of 40+ characters of
encoding alphabet), SOC-RULE-053 looks at volume (50+ unique subdomains of one domain from one host
in 5 minutes). CDNs and anti-virus services do both legitimately; they belong in exceptions.

**Beaconing.** Implants calling home on a timer leave near-constant gaps between connections.
Sigma cannot express "regular", so beaconing is a hunting analytic over Zeek conn logs: 8+
connections with a coefficient of variation under 0.15. It produces leads, not alerts.

**TLS fingerprints.** SOC-RULE-055 matches JA3/JA4 client fingerprints on a blocklist. I did not
ship a "known bad" list I could not verify; the values in the rule are marked synthetic
placeholders and a script loads a list you trust, bumping the rule version as it does. A
fingerprint identifies a TLS library, not a program, so hunting for rare fingerprints is often more
useful than any blocklist.

**What is not verified.** No live sensor has been connected; all network rules are tested on
synthetic records.
