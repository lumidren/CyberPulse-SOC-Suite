#!/usr/bin/env python3
"""
Send an HMAC-signed event to the CyberPulse webhook receiver (POST /api/ingest).

    INGEST_HMAC_SECRET=... python scripts/send_signed_event.py event.json \
        [--url http://127.0.0.1:5000/api/ingest]

Only send synthetic lab events or telemetry you are authorised to forward.
"""

import argparse
import os
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soar.ingest_auth import SIGNATURE_HEADER, TIMESTAMP_HEADER, sign_payload  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="POST an HMAC-signed event to /api/ingest")
    parser.add_argument("event_file", help="path to a JSON event")
    parser.add_argument("--url", default="http://127.0.0.1:5000/api/ingest")
    args = parser.parse_args()

    secret = os.environ.get("INGEST_HMAC_SECRET")
    if not secret:
        sys.exit("Set INGEST_HMAC_SECRET to the server's shared secret.")
    with open(args.event_file, "rb") as fh:
        body = fh.read()
    ts, signature = sign_payload(secret, body)
    req = urllib.request.Request(args.url, data=body, method="POST", headers={
        "Content-Type": "application/json", TIMESTAMP_HEADER: ts, SIGNATURE_HEADER: signature})
    with urllib.request.urlopen(req, timeout=10) as resp:
        print(resp.status, resp.read().decode("utf-8")[:500])


if __name__ == "__main__":
    main()
