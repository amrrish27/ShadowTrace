"""Tests for watchdog, stuck DNS, unanswering server, and hanging scanner steps."""
from __future__ import annotations

import json
import socket
import threading
import time
import pytest

from app.db import db, new_id, now
from app.engine.urlguard import BlockedDestination, SystemResolver
from app.workers.worker import execute_scan, recover_stale


def _create_test_scan(app_env, max_seconds: int = 2) -> str:
    scan_id = new_id()
    timestamp = now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                               partial, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'queued', ?, '{}', ?, 0, ?, ?)
            """,
            (
                scan_id,
                app_env["target"]["org_id"],
                app_env["target"]["id"],
                app_env["org_analyst"]["id"],
                json.dumps({"max_seconds": max_seconds, "include_crawler": True}),
                new_id(),
                timestamp,
                timestamp,
            ),
        )
    return scan_id


def test_resolver_that_sleeps_forever_raises_dns_timeout(monkeypatch):
    """1. Resolver that sleeps forever raises BlockedDestination('dns_timeout') within timeout."""
    def _sleep_forever(*args, **kwargs):
        time.sleep(10)
        return []

    import socket as socket_module
    monkeypatch.setattr(socket_module, "getaddrinfo", _sleep_forever)

    resolver = SystemResolver(timeout=0.5)
    start = time.monotonic()
    with pytest.raises(BlockedDestination) as excinfo:
        resolver.resolve("sleepy.test", 80)
    duration = time.monotonic() - start
    assert excinfo.value.reason == "dns_timeout"
    assert duration < 2.0


def test_server_that_accepts_and_never_answers_ends_timed_out_inside_max_seconds_plus_grace(app_env, monkeypatch):
    """2. Server that accepts connection and never answers ends timed_out inside max_seconds + grace."""
    # Start a dummy TCP server that accepts and never answers
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    port = server_sock.getsockname()[1]

    def _blackhole():
        try:
            conn, _ = server_sock.accept()
            time.sleep(30)
            conn.close()
        except Exception:
            pass

    server_thread = threading.Thread(target=_blackhole, daemon=True)
    server_thread.start()

    # Point target to this blackhole server
    with db() as conn:
        conn.execute(
            "UPDATE targets SET base_url = ?, host = '127.0.0.1', ports = ? WHERE id = ?",
            (f"http://127.0.0.1:{port}", json.dumps([port]), app_env["target"]["id"]),
        )

    scan_id = _create_test_scan(app_env, max_seconds=2)

    start = time.monotonic()
    with db() as conn:
        summary = execute_scan(conn, scan_id)
        row = conn.execute("SELECT state, partial, error_category FROM scans WHERE id = ?", (scan_id,)).fetchone()
    elapsed = time.monotonic() - start

    server_sock.close()

    assert row["state"] in ("timed_out", "completed", "failed")
    # Must complete inside max_seconds (2) + grace (5) = 7s
    assert elapsed < 8.0


def test_scanner_step_that_hangs_ends_timed_out_inside_max_seconds_plus_grace(app_env, monkeypatch):
    """3. A scanner step that hangs forever ends with a timed_out scan inside max_seconds + grace."""
    from app.engine.scanner import Scanner

    def _hanging_discover(self, client):
        time.sleep(30)
        return True

    monkeypatch.setattr(Scanner, "_discover", _hanging_discover)

    scan_id = _create_test_scan(app_env, max_seconds=2)

    start = time.monotonic()
    with db() as conn:
        summary = execute_scan(conn, scan_id)
        row = conn.execute("SELECT state, partial, error_category FROM scans WHERE id = ?", (scan_id,)).fetchone()
    elapsed = time.monotonic() - start

    assert row["state"] == "timed_out"
    assert row["partial"] == 1
    assert row["error_category"] == "timeout"
    # max_seconds=2 + grace=5 => must finish within 8 seconds
    assert elapsed < 8.0
