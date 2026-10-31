"""
Dashboard Session Store for the CyberPulse SOC Lab

Analysts log in once with the API key; the server then issues an opaque,
random session token in an HttpOnly, SameSite=Strict cookie so the key never
has to live in browser JavaScript or storage. Sessions are in-memory and
expire after a fixed TTL.
"""

import secrets
import threading
import time


class SessionStore:
    def __init__(self, ttl_sec=8 * 3600, clock=time.time):
        self.ttl_sec = ttl_sec
        self.clock = clock
        self._sessions = {}
        self._lock = threading.Lock()

    def create(self, principal):
        """Start a session; returns (token, csrf_token)."""
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = {
                "principal": principal,
                "csrf_token": csrf,
                "created_at": self.clock(),
                "expires_at": self.clock() + self.ttl_sec,
            }
        return token, csrf

    def get(self, token):
        """Return the live session for `token`, or None (expired sessions are dropped)."""
        if not token:
            return None
        with self._lock:
            session = self._sessions.get(token)
            if session and session["expires_at"] <= self.clock():
                del self._sessions[token]
                return None
            return session

    def destroy(self, token):
        with self._lock:
            self._sessions.pop(token, None)
