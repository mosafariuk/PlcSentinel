#!/usr/bin/env python3
"""
PlcSentinel - Per-source resource caps shared by the DPI gateways.

An inline proxy opens one backend connection per client session, so without a
cap a single host could exhaust the controller's connection table through the
gateway. The request-rate cap bounds how hard one host can drive the
controller's scan cycle. Both are availability controls (MITRE ATT&CK for ICS
T0814) and apply in enforce and monitor mode alike.
"""

import time
import threading
from collections import Counter
from typing import Dict, Tuple


class SourceLimiter:
    def __init__(self, max_sessions: int = 8, max_requests_per_sec: int = 200):
        self.max_sessions = max_sessions
        self.max_rps = max_requests_per_sec
        self._lock = threading.Lock()
        self._sessions: Counter = Counter()
        # ip -> (second, requests seen in that second)
        # shortcut: one entry per source ever seen; prune if the gateway ever faces large source churn
        self._window: Dict[str, Tuple[int, int]] = {}

    def open_session(self, ip: str) -> bool:
        """Reserve a session slot for ip; False when the cap is already reached."""
        with self._lock:
            if self._sessions[ip] >= self.max_sessions:
                return False
            self._sessions[ip] += 1
            return True

    def close_session(self, ip: str) -> None:
        with self._lock:
            self._sessions[ip] -= 1
            if self._sessions[ip] <= 0:
                del self._sessions[ip]

    def allow_request(self, ip: str) -> bool:
        """Count one request from ip; False once this second's budget is spent."""
        now = int(time.monotonic())
        with self._lock:
            sec, n = self._window.get(ip, (now, 0))
            if sec != now:
                sec, n = now, 0
            n += 1
            self._window[ip] = (sec, n)
            return n <= self.max_rps
