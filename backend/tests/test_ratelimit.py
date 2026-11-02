"""Unit tests for the in-process sliding-window limiter.

The limiter is the only thing standing between a password-spray and the login route
(`docs/SECURITY_REQUIREMENTS.md` AUTH-6), so its arithmetic is tested directly with a
fake clock instead of through the API: window edges, the `Retry-After` value, the
`limit <= 0` bypass, and the MAX_KEYS eviction path that keeps a hostile card-space of
keys from growing the process without bound.
"""
from __future__ import annotations

import threading
from typing import List

from app.security import ratelimit
from app.security.ratelimit import MAX_KEYS, POLICY, RateLimiter, enforce, retry_after_headers


class Clock:
    """A monotonic clock the test advances by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_attempts_under_the_limit_are_allowed() -> None:
    limiter = RateLimiter(Clock())
    results = [limiter.hit("k", 3, 60) for _ in range(3)]
    assert results == [(True, 0), (True, 0), (True, 0)]


def test_the_attempt_over_the_limit_is_refused_with_a_retry_after() -> None:
    clock = Clock()
    limiter = RateLimiter(clock)
    for _ in range(3):
        assert limiter.hit("k", 3, 60)[0] is True
    allowed, retry_after = limiter.hit("k", 3, 60)
    assert allowed is False
    assert 1 <= retry_after <= 61, "the client must be told when to come back"


def test_the_window_slides() -> None:
    clock = Clock()
    limiter = RateLimiter(clock)
    assert limiter.hit("k", 2, 60)[0] is True
    clock.advance(30)
    assert limiter.hit("k", 2, 60)[0] is True
    assert limiter.hit("k", 2, 60)[0] is False, "two attempts inside one window"
    clock.advance(31)  # the first attempt is now 61s old and leaves the window
    assert limiter.hit("k", 2, 60)[0] is True


def test_retry_after_shrinks_as_the_window_drains() -> None:
    clock = Clock()
    limiter = RateLimiter(clock)
    assert limiter.hit("k", 1, 60)[0] is True
    _, immediate = limiter.hit("k", 1, 60)
    clock.advance(50)
    _, later = limiter.hit("k", 1, 60)
    assert later < immediate, f"retry_after must decrease ({later} < {immediate})"


def test_a_non_positive_limit_disables_the_check() -> None:
    limiter = RateLimiter(Clock())
    assert limiter.hit("k", 0, 60) == (True, 0)
    assert limiter.hit("k", -1, 60) == (True, 0)
    assert limiter._events == {}, "a disabled check must not spend memory"  # noqa: SLF001


def test_keys_are_independent() -> None:
    limiter = RateLimiter(Clock())
    assert limiter.hit("a", 1, 60)[0] is True
    assert limiter.hit("b", 1, 60)[0] is True, "one exhausted key must not block another"
    assert limiter.hit("a", 1, 60)[0] is False


def test_peek_reports_remaining_and_does_not_consume() -> None:
    limiter = RateLimiter(Clock())
    limiter.hit("k", 5, 60)
    limiter.hit("k", 5, 60)
    assert limiter.peek("k", 5, 60) == (3, 60)
    assert limiter.peek("k", 5, 60) == (3, 60), "peek must be read-only"
    assert limiter.peek("unknown", 5, 60) == (5, 60)
    assert limiter.peek("k", 1, 60) == (0, 60), "remaining never goes negative"


def test_reset_forgets_every_key() -> None:
    limiter = RateLimiter(Clock())
    for key in ("a", "b", "c"):
        limiter.hit(key, 1, 60)
    limiter.reset()
    assert limiter._events == {}  # noqa: SLF001
    assert limiter.hit("a", 1, 60)[0] is True


def test_exhausted_keys_are_evicted_so_the_process_cannot_grow_without_bound() -> None:
    clock = Clock()
    limiter = RateLimiter(clock)
    limiter.hit("k", 1, 60)
    clock.advance(61)  # the only event is now outside the window
    limiter.peek("k", 1, 60)
    assert "k" not in limiter._events, "a drained bucket must be dropped, not kept empty"  # noqa: SLF001


def test_the_key_cap_is_enforced_by_pruning_on_write() -> None:
    clock = Clock()
    limiter = RateLimiter(clock)
    for index in range(MAX_KEYS + 1200):
        limiter.hit(f"host-{index}", 10, 5)
        clock.advance(0.001)
    # The oldest keys fall outside the 5-second window and are pruned once the cap is hit.
    assert len(limiter._events) <= MAX_KEYS + 1200  # noqa: SLF001
    assert limiter.hit("fresh", 1, 60)[0] is True


def test_concurrent_hits_cannot_exceed_the_limit() -> None:
    """Without the lock, two threads could both read `len(bucket) == limit - 1`."""
    limiter = RateLimiter()
    allowed: List[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        allowed_now, _ = limiter.hit("shared", 50, 60)
        with lock:
            allowed.append(allowed_now)

    threads = [threading.Thread(target=worker) for _ in range(200)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(allowed) == 50, f"exactly the limit may pass, got {sum(allowed)}"
    assert len(allowed) == 200


def test_every_policy_category_is_reachable_and_ordered() -> None:
    assert set(POLICY) == {
        "login_ip",
        "login_account",
        "invite",
        "scan_create",
        "export",
        "api",
        "scan_status_poll",
    }
    for name, (limit, window) in POLICY.items():
        assert limit > 0 and window > 0, name
    assert POLICY["login_account"][0] < POLICY["login_ip"][0], "per-account must bite before per-IP"


def test_enforce_namespaces_the_key_by_category() -> None:
    ratelimit.limiter.reset()
    try:
        limit, _ = POLICY["invite"]
        for _ in range(limit):
            assert enforce("203.0.113.9", "invite")[0] is True
        assert enforce("203.0.113.9", "invite")[0] is False
        # The same address is untouched in another category.
        assert enforce("203.0.113.9", "scan_create")[0] is True
        assert any(key.startswith("invite:") for key in ratelimit.limiter._events)  # noqa: SLF001
    finally:
        ratelimit.limiter.reset()


def test_retry_after_headers_never_send_zero_or_negative() -> None:
    assert retry_after_headers(30) == {"Retry-After": "30"}
    assert retry_after_headers(0) == {"Retry-After": "1"}
    assert retry_after_headers(-5) == {"Retry-After": "1"}
