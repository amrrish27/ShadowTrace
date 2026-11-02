"""The worker's operational paths: claim, heartbeat, recovery and `main()`.

`test_lifecycle_service.py` covers the state machine through the service layer and
`test_scan_integration.py` covers a real scan end to end. What is left — and what this
module pins down — is the glue that only runs in the worker process:

* the kill switch stops `claim_next` *and* `main()`, so `--once` cannot spin;
* a claim takes the lease, records `worker.claimed`, and cannot be taken twice;
* the heartbeat renews the lease and propagates cancellation;
* `recover_stale` fails an abandoned scan with its partial results and an audit row;
* a scan whose target disappeared fails loudly instead of silently "completing".
"""
from __future__ import annotations

import contextlib
import json
import sys
import threading
import time
from typing import Dict

import pytest

from app.config import get_settings, reset_settings_cache
from app.db import db, new_id, now
from app.workers import worker as worker_module
from app.workers.worker import (
    Heartbeat,
    _load_context,
    record_event,
    record_progress,
    claim_next,
    execute_scan,
    main,
    recover_stale,
)


def _scan(env, *, state: str = "queued", lease: int | None = None,
          target_id: str | None = None) -> str:
    scan_id = new_id()
    timestamp = now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                               partial, created_at, updated_at, lease_expires_at)
            VALUES (?, ?, ?, ?, ?, '{}', '{}', ?, 0, ?, ?, ?)
            """,
            (
                scan_id,
                env["target"]["org_id"],
                target_id or env["target"]["id"],
                env["org_analyst"]["id"],
                state,
                new_id(),
                timestamp,
                timestamp,
                lease,
            ),
        )
    return scan_id


def _row(scan_id: str):
    with db() as conn:
        return conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def _events(scan_id: str) -> list:
    with db() as conn:
        return conn.execute(
            "SELECT kind, level, message FROM scan_events WHERE scan_id = ? ORDER BY ts", (scan_id,)
        ).fetchall()


# --------------------------------------------------------------------------- claim


def test_the_kill_switch_stops_the_claim(app_env, monkeypatch) -> None:
    scan_id = _scan(app_env)
    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    reset_settings_cache()
    with db() as conn:
        assert claim_next(conn, "worker-test", 60) is None
    assert _row(scan_id)["state"] == "queued", "a disabled scanner must not take work"


def test_claiming_takes_the_lease_and_records_it(app_env) -> None:
    scan_id = _scan(app_env)
    with db() as conn:
        assert claim_next(conn, "worker-abc", 120) == scan_id
    row = _row(scan_id)
    assert row["state"] == "running"
    assert row["worker_id"] == "worker-abc"
    assert row["lease_expires_at"] and row["lease_expires_at"] > row["started_at"]
    kinds = [event["kind"] for event in _events(scan_id)]
    assert kinds == ["worker.claimed"]


def test_the_same_scan_is_never_claimed_twice(app_env) -> None:
    """Two pollers racing on one row: exactly one wins, the loser gets None."""
    scan_id = _scan(app_env)
    with db() as conn:
        first = claim_next(conn, "worker-a", 60)
    with db() as conn:
        second = claim_next(conn, "worker-b", 60)
    assert (first, second) == (scan_id, None)
    assert _row(scan_id)["worker_id"] == "worker-a"


def test_claim_returns_none_on_an_empty_queue(app_env) -> None:
    with db() as conn:
        assert claim_next(conn, "worker-idle", 60) is None


def test_claim_is_fifo(app_env) -> None:
    older = _scan(app_env)
    newer = _scan(app_env)
    with db() as conn:
        conn.execute("UPDATE scans SET created_at = created_at - 30 WHERE id = ?", (older,))
        conn.commit()
    with db() as conn:
        assert claim_next(conn, "worker-fifo", 60) == older
    with db() as conn:
        assert claim_next(conn, "worker-fifo", 60) == newer


# ----------------------------------------------------------------------- heartbeat


def test_heartbeat_renews_the_lease_until_it_is_stopped(app_env) -> None:
    scan_id = _scan(app_env, state="running", lease=now() - 1)
    before = _row(scan_id)["lease_expires_at"]
    cancel_event = threading.Event()
    beat = Heartbeat(scan_id, 300, cancel_event)
    beat.start()
    try:
        deadline = time.time() + 6
        while time.time() < deadline and _row(scan_id)["lease_expires_at"] == before:
            time.sleep(0.1)
    finally:
        beat.stop()
        beat.join(timeout=3)
    assert _row(scan_id)["lease_expires_at"] > before, "the lease must be pushed forward"
    assert not cancel_event.is_set()
    assert not beat.is_alive()


def test_heartbeat_propagates_cancellation(app_env) -> None:
    scan_id = _scan(app_env, state="running", lease=now())
    with db() as conn:
        conn.execute("UPDATE scans SET cancel_requested = 1 WHERE id = ?", (scan_id,))
    cancel_event = threading.Event()
    beat = Heartbeat(scan_id, 300, cancel_event)
    beat.start()
    try:
        assert cancel_event.wait(timeout=6), "the heartbeat must turn a request into a signal"
    finally:
        beat.stop()
        beat.join(timeout=3)


def test_heartbeat_stops_when_the_scan_row_disappears(app_env) -> None:
    scan_id = _scan(app_env, state="running", lease=now())
    beat = Heartbeat(scan_id, 300, threading.Event())
    beat.start()
    with db() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    beat.join(timeout=6)
    assert not beat.is_alive(), "a deleted scan must end the heartbeat thread"


# ------------------------------------------------------- shared-database behaviour


def test_an_event_is_committed_before_the_scan_moves_on(app_env) -> None:
    """The API shares the SQLite file with the worker.

    While a scan runs, the worker writes events and counters. If those writes were left
    uncommitted, the worker would hold the write lock for the whole scan: the API then
    fails with `database is locked` (observed live against a slow target). Every write
    must be its own short transaction and must be visible to the API immediately.
    """
    scan_id = _scan(app_env, state="running")
    with contextlib.ExitStack() as stack:
        worker_conn = stack.enter_context(db())
        record_event(worker_conn, scan_id, "crawl.error", "first failure", "warning")
        assert not worker_conn.in_transaction, "an event must not leave a write transaction open"

        started = time.monotonic()
        with db() as api_conn:  # a second connection, standing in for the API process
            api_conn.execute("UPDATE scans SET updated_at = ? WHERE id = ?", (now(), scan_id))
            api_conn.commit()
            visible = api_conn.execute(
                "SELECT kind, level FROM scan_events WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        elapsed = time.monotonic() - started
    assert elapsed < 5, f"the API write blocked for {elapsed:.1f}s"
    assert [(row["kind"], row["level"]) for row in visible] == [("crawl.error", "warning")]


def test_progress_counters_are_committed_and_readable_immediately(app_env) -> None:
    scan_id = _scan(app_env, state="running")
    with contextlib.ExitStack() as stack:
        worker_conn = stack.enter_context(db())
        record_progress(worker_conn, scan_id, {"pages_fetched": 3})
        assert not worker_conn.in_transaction, "progress must not hold the write lock"
        with db() as api_conn:
            row = api_conn.execute("SELECT counters FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert json_counters(row) == {"pages_fetched": 3}


def test_record_event_sanitises_what_it_stores(app_env) -> None:
    scan_id = _scan(app_env, state="running")
    with db() as conn:
        record_event(conn, scan_id, "k" * 80, "m" * 900, level="critical")
        record_event(conn, scan_id, "crawl.note", "short", level="error")
        rows = conn.execute(
            "SELECT kind, level, message FROM scan_events WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    assert [row["kind"] for row in rows] == ["k" * 40, "crawl.note"]
    assert [row["level"] for row in rows] == ["info", "error"], "an unknown level falls back to info"
    assert len(rows[0]["message"]) == 500


# ----------------------------------------------------------------------- recovery


def test_recover_stale_fails_an_expired_lease_and_keeps_partial_results(app_env) -> None:
    scan_id = _scan(app_env, state="running", lease=now() - 120)
    with db() as conn:
        conn.execute("UPDATE scans SET counters = '{\"pages_fetched\":3}' WHERE id = ?", (scan_id,))
        assert recover_stale(conn) == 1
    row = _row(scan_id)
    assert row["state"] == "failed"
    assert int(row["partial"]) == 1
    assert row["error_category"] == "internal"
    assert "stopped responding" in row["error_message"]
    assert json_counters(row) == {"pages_fetched": 3}, "observed work must be preserved"
    assert [event["kind"] for event in _events(scan_id)] == ["worker.lost"]
    with db() as conn:
        audit_kinds = [r["action"] for r in conn.execute(
            "SELECT action FROM audit_log WHERE object_id = ?", (scan_id,)
        ).fetchall()]
    assert audit_kinds == ["scan.worker_lost"]


def json_counters(row) -> Dict[str, object]:
    return json.loads(row["counters"] or "{}")


def test_recover_stale_leaves_a_live_lease_alone(app_env) -> None:
    scan_id = _scan(app_env, state="running", lease=now() + 600)
    with db() as conn:
        assert recover_stale(conn) == 0
    assert _row(scan_id)["state"] == "running"


def test_recover_stale_also_covers_a_cancelling_scan(app_env) -> None:
    scan_id = _scan(app_env, state="cancelling", lease=now() - 5)
    with db() as conn:
        assert recover_stale(conn) == 1
    assert _row(scan_id)["state"] == "failed"


def test_recover_stale_times_out_scan_that_exceeded_wall_clock_limit(app_env) -> None:
    scan_id = _scan(app_env, state="running", lease=now() + 600)
    current_time = now()
    with db() as conn:
        conn.execute(
            "UPDATE scans SET started_at = ?, config = ? WHERE id = ?",
            (current_time - 350, json.dumps({"max_seconds": 300}), scan_id),
        )
        assert recover_stale(conn) >= 1
    row = _row(scan_id)
    assert row["state"] == "timed_out"
    assert int(row["partial"]) == 1
    assert row["error_category"] == "timeout"


def test_recover_stale_force_cancels_stuck_cancelling_scan(app_env) -> None:
    scan_id = _scan(app_env, state="cancelling", lease=now() + 600)
    current_time = now()
    with db() as conn:
        conn.execute(
            "UPDATE scans SET updated_at = ? WHERE id = ?",
            (current_time - 20, scan_id),
        )
        assert recover_stale(conn) >= 1
    row = _row(scan_id)
    assert row["state"] == "cancelled"
    assert int(row["partial"]) == 1


# ------------------------------------------------------------------ execute_scan guards


def test_execute_scan_refuses_an_unknown_scan(app_env) -> None:
    with db() as conn:
        with pytest.raises(RuntimeError):
            execute_scan(conn, "no-such-scan")


def test_execute_scan_refuses_a_scan_whose_target_vanished(app_env) -> None:
    """A dangling target must fail the scan loudly, not let it 'complete' with zero work.

    The foreign key forbids deleting the target behind a live scan, so the row is edited
    in memory the way a corrupted database would present it.
    """
    scan_id = _scan(app_env)
    with db() as conn:
        scan = dict(conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone())
    scan["target_id"] = "missing-target"
    with db() as conn:
        with pytest.raises(RuntimeError, match="target missing"):
            _load_context(conn, scan)


# ----------------------------------------------------------------------------- main()


def test_main_once_exits_immediately_when_scanning_is_disabled(app_env, monkeypatch) -> None:
    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    reset_settings_cache()
    monkeypatch.setattr(sys, "argv", ["worker", "--once"])
    started = time.monotonic()
    main()  # must return rather than sleep through the kill switch
    assert time.monotonic() - started < 5


def test_main_recover_flag_fails_expired_leases_and_returns(app_env, monkeypatch) -> None:
    scan_id = _scan(app_env, state="running", lease=now() - 60)
    monkeypatch.setattr(sys, "argv", ["worker", "--recover"])
    main()
    assert _row(scan_id)["state"] == "failed"


def test_main_claims_and_runs_a_specific_scan(app_env, monkeypatch) -> None:
    """`--scan-id` runs one scan without polling; the lab target is not running, so the
    scan must end `completed` with `partial = 1` and zero fetched pages, not silently
    'successful'."""
    scan_id = _scan(app_env)
    monkeypatch.setattr(sys, "argv", ["worker", "--scan-id", scan_id])
    main()
    row = _row(scan_id)
    assert row["state"] == "completed"
    assert int(row["partial"]) == 1
    counters = json_counters(row)
    assert counters["pages_fetched"] == 0
    assert counters["requests_failed"] >= 1, "a failed fetch must be counted, not hidden"
    kinds = [event["kind"] for event in _events(scan_id)]
    assert "scan.target_unreachable" in kinds


def test_the_worker_module_is_runnable(app_env) -> None:
    """`python -m app.workers.worker` is the documented entry point (compose and README)."""
    assert worker_module.__name__ == "app.workers.worker"
    assert callable(getattr(worker_module, "main", None))
    assert get_settings().worker_poll_seconds >= 0.2
