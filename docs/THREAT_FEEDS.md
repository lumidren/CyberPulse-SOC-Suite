# Threat Feeds (CIPHER)

Roadmap F38. **Stub: off until configured; the CIPHER project's real output format has not
been checked against this parser.**

A feed is downloaded in bulk and matched locally, so checking an event against it sends
nothing about the event anywhere. Matches appear on each incident under
`threat_intel.feed_matches` (type, value, source, confidence, first seen).
`GET /api/feeds` shows whether a feed is configured, when it was loaded, how many
indicators it holds and the last error.

| Setting | Meaning |
| :--- | :--- |
| `CIPHER_FEED_URL` | https URL of the feed; re-fetched every `CIPHER_FEED_REFRESH_SEC` (default 3600) with `If-None-Match` |
| `CIPHER_FEED_TOKEN` | optional Bearer token for the feed URL |
| `CIPHER_FEED_FILE` | local feed file, loaded at start and on each refresh |

Formats:

- **JSON** (what CyberPulse expects from CIPHER):
  `{"indicators": [{"type": "ipv4", "value": "8.8.8.8", "confidence": 80, "source": "cipher", "first_seen": "..."}]}`
- **STIX 2.1 bundle**: `indicator` objects with `[ipv4-addr:value = '...']`,
  `[ipv6-addr:value = '...']` or `[file:hashes.'SHA-256' = '...']` patterns.

Only globally routable IPs and SHA-256 hashes are kept; private and documentation ranges,
domains and other types are counted as ignored. Feeds over 20 MB are refused. Respect the
feed provider's licence and redistribution terms; CyberPulse does not re-share feed data
(MISP export, F37, only shares indicators seen in your own incidents).
