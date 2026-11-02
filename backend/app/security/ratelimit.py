"""In-process sliding-window rate limiting.

Limits are enforced for login (per IP and per account), invitations, scan
creation, exports and general API traffic.  The limiter is intentionally simple
and single-process; a multi-worker deployment must move counters to a shared
store (documented limitation in docs/SECURITY_REQUIREMENTS.md).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Tuple

MAX_KEYS = 20_000


class RateLimiter:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, window: float, current: float) -> None:
        bucket = self._events[key]
        while bucket and bucket[0] <= current - window:
            bucket.popleft()
        if not bucket:
            self._events.pop(key, None)

    def hit(self, key: str, limit: int, window_seconds: float) -> Tuple[bool, int]:
        """Record an attempt. Returns (allowed, retry_after_seconds)."""
        if limit <= 0:
            return True, 0
        current = self._clock()
        with self._lock:
            if len(self._events) > MAX_KEYS:
                for existing in list(self._events.keys())[:1000]:
                    self._prune(existing, window_seconds, current)
            self._prune(key, window_seconds, current)
            bucket = self._events[key]
            if len(bucket) >= limit:
                retry_after = max(1, int(window_seconds - (current - bucket[0])) + 1)
                return False, retry_after
            bucket.append(current)
            return True, 0

    def peek(self, key: str, limit: int, window_seconds: float) -> Tuple[int, int]:
        current = self._clock()
        with self._lock:
            self._prune(key, window_seconds, current)
            used = len(self._events.get(key, ()))
        remaining = max(0, limit - used)
        reset = window_seconds
        return remaining, int(reset)

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


limiter = RateLimiter()

# (limit, window seconds) per category.
POLICY: Dict[str, Tuple[int, float]] = {
    "login_ip": (20, 300),
    "login_account": (10, 300),
    "invite": (20, 3600),
    "scan_create": (30, 3600),
    "export": (60, 3600),
    "api": (600, 60),
    "scan_status_poll": (600, 60),
}


def enforce(key: str, category: str) -> Tuple[bool, int]:
    limit, window = POLICY[category]
    return limiter.hit(f"{category}:{key}", limit, window)


def retry_after_headers(seconds: int) -> Dict[str, str]:
    return {"Retry-After": str(max(1, seconds))}
