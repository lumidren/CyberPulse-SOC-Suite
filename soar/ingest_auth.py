"""
HMAC Authentication for the CyberPulse Webhook Receiver (POST /api/ingest)

Senders sign each request:

    X-CyberPulse-Timestamp: <unix seconds>
    X-CyberPulse-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>

The receiver rejects missing/invalid signatures, timestamps outside a 5-minute
window, and replays of a signature already seen inside that window. The
shared secret comes from INGEST_HMAC_SECRET; without it the receiver stays
disabled.
"""

import hashlib
import hmac
import threading
import time

SIGNATURE_HEADER = "X-CyberPulse-Signature"
TIMESTAMP_HEADER = "X-CyberPulse-Timestamp"
MAX_SKEW_SEC = 300


def sign_payload(secret, body, timestamp=None):
    """Return (timestamp, signature header value) for `body` (bytes or str)."""
    ts = str(int(timestamp if timestamp is not None else time.time()))
    raw = body.encode("utf-8") if isinstance(body, str) else body
    digest = hmac.new(secret.encode("utf-8"), ts.encode("ascii") + b"." + raw, hashlib.sha256).hexdigest()
    return ts, f"sha256={digest}"


class IngestVerifier:
    def __init__(self, secret, clock=time.time, max_skew_sec=MAX_SKEW_SEC):
        self.secret = secret
        self.clock = clock
        self.max_skew_sec = max_skew_sec
        self._seen = {}  # signature -> first-seen time (replay cache)
        self._lock = threading.Lock()

    @property
    def enabled(self):
        return bool(self.secret)

    def verify(self, timestamp, signature, raw_body):
        """Return (ok, reason)."""
        if not self.enabled:
            return False, "Webhook receiver disabled: set INGEST_HMAC_SECRET."
        if not timestamp or not signature:
            return False, f"Missing {TIMESTAMP_HEADER} or {SIGNATURE_HEADER} header."
        try:
            ts = int(timestamp)
        except ValueError:
            return False, "Invalid timestamp."
        now = self.clock()
        if abs(now - ts) > self.max_skew_sec:
            return False, "Timestamp outside the allowed window (possible replay or clock skew)."
        _, expected = sign_payload(self.secret, raw_body, ts)
        if not hmac.compare_digest(expected, signature.strip()):
            return False, "Signature mismatch."
        with self._lock:
            for sig, seen in list(self._seen.items()):
                if now - seen > self.max_skew_sec:
                    del self._seen[sig]
            if signature in self._seen:
                return False, "Replayed request."
            self._seen[signature] = now
        return True, ""
