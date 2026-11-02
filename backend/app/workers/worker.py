"""Scan worker.

Claims queued scans from the database with a lease, runs the scanner with a
heartbeat, honours cancellation within five seconds, keeps partial results when a
worker or the scan times out, and never runs while the global kill switch is off.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import signal
import sqlite3
import threading
import time
import uuid
from typing import Dict, Optional, cast

from ..config import get_settings
from ..db import db, now
from ..engine.parsers import parse_yaml_or_json
from ..engine.scanner import Scanner, ScanSummary, ScanTimeout
from ..engine.safe_http import VERSION, ScanCancelled
from ..security import audit
from ..services import scans as scan_service

log = logging.getLogger("shadowtrace.worker")
# ST_WORKER_NAME allows operators to set a human-readable worker identity.
# When absent, a random six-hex-character suffix ensures uniqueness without
# embedding the hostname (which leaks infrastructure details in the API).
WORKER_ID = os.environ.get("ST_WORKER_NAME") or f"worker-{secrets.token_hex(3)}"
WORKER_STARTED_AT = now()


def claim_next(conn: sqlite3.Connection, worker_id: str, lease_seconds: int) -> Optional[str]:
    settings = get_settings()
    if not settings.scanning_enabled:
        return None
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            """
            SELECT id FROM scans
            WHERE state = 'queued'
            ORDER BY created_at LIMIT 1
            """
        ).fetchone()
        if row is None:
            conn.rollback()
            return None
        timestamp = now()
        updated = conn.execute(
            """
            UPDATE scans SET state = 'running', worker_id = ?, heartbeat_at = ?, lease_expires_at = ?,
                             started_at = COALESCE(started_at, ?), updated_at = ?
            WHERE id = ? AND state = 'queued'
            """,
            (worker_id, timestamp, timestamp + lease_seconds, timestamp, timestamp, row["id"]),
        ).rowcount
        if updated != 1:
            conn.rollback()
            return None
        scan_id = str(row["id"])
        conn.execute(
            "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, 'info', 'worker.claimed', ?)",
            (scan_id, timestamp, f"Claimed by worker {worker_id[:60]}"),
        )
        conn.execute("COMMIT")
        return scan_id
    except Exception:
        conn.rollback()
        raise


class Heartbeat(threading.Thread):
    def __init__(self, scan_id: str, lease_seconds: int, cancel_event: threading.Event) -> None:
        super().__init__(daemon=True)
        self.scan_id = scan_id
        self.lease_seconds = lease_seconds
        self.cancel_event = cancel_event
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.wait(2.0):
            try:
                with db() as conn:
                    timestamp = now()
                    row = conn.execute("SELECT cancel_requested FROM scans WHERE id = ?", (self.scan_id,)).fetchone()
                    if row is None:
                        return
                    if int(row["cancel_requested"]) == 1:
                        self.cancel_event.set()
                    conn.execute(
                        "UPDATE scans SET heartbeat_at = ?, lease_expires_at = ? WHERE id = ?",
                        (timestamp, timestamp + self.lease_seconds, self.scan_id),
                    )
            except Exception:  # pragma: no cover - heartbeat must never kill a scan
                log.exception("heartbeat_failed scan_id=%s", self.scan_id)

    def stop(self) -> None:
        self.stop_event.set()


def record_heartbeat(conn: sqlite3.Connection, worker_id: str, *, scans_run: int = 0, version: str = "") -> None:
    """Upsert this worker's row in `worker_heartbeats` (added by migration 0004).

    The heartbeat is what lets the Settings page say "2 workers alive, 1 idle 40s" instead
    of guessing from scan rows. It is committed immediately: the row is useful even if the
    process dies on the next line.
    """
    timestamp = now()
    conn.execute(
        """
        INSERT INTO worker_heartbeats (worker_id, hostname, pid, started_at, last_seen_at, scans_run, version)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(worker_id) DO UPDATE SET
            last_seen_at = excluded.last_seen_at,
            scans_run = excluded.scans_run,
            version = excluded.version
        """,
        (
            worker_id,
            os.environ.get("COMPUTERNAME") or os.environ.get("HOSTNAME") or "unknown",
            os.getpid(),
            WORKER_STARTED_AT,
            timestamp,
            scans_run,
            version or VERSION,
        ),
    )
    conn.commit()


def _load_context(conn: sqlite3.Connection, scan: sqlite3.Row) -> Dict[str, object]:
    target = conn.execute("SELECT * FROM targets WHERE id = ?", (scan["target_id"],)).fetchone()
    if target is None:
        raise RuntimeError("target missing")
    baseline_document = None
    baseline_label = ""
    if scan["baseline_id"]:
        baseline = conn.execute("SELECT * FROM baselines WHERE id = ?", (scan["baseline_id"],)).fetchone()
        if baseline is not None:
            baseline_document = parse_yaml_or_json(str(baseline["spec"]))
            baseline_label = str(baseline["source_ref"] or baseline["source"])[:200]
    config = json.loads(scan["config"] or "{}")
    har_text = None
    har_name = ""
    har_id = config.get("har_import_id")
    if har_id:
        har_row = conn.execute("SELECT name, entries FROM har_imports WHERE id = ?", (har_id,)).fetchone()
        if har_row is not None:
            har_name = str(har_row["name"])
            har_text = json.dumps({"log": {"version": "1.2", "entries": json.loads(har_row["entries"])}})
    return {
        "scan": dict(scan),
        "target": dict(target),
        "baseline_document": baseline_document,
        "baseline_label": baseline_label,
        "har_text": har_text,
        "har_name": har_name,
    }


def record_event(conn: sqlite3.Connection, scan_id: str, kind: str, message: str, level: str = "info") -> None:
    """Append a scan event and commit it immediately.

    The worker shares one SQLite file with the API. A connection that leaves an INSERT
    uncommitted holds the write lock for the whole scan, so every API write (session
    touch, audit row, a new scan) waits out `busy_timeout` and then fails with
    "database is locked". Events are small and frequent, so each one is its own
    transaction: the lock is held for microseconds, and progress survives a crash.
    """
    level = level if level in {"debug", "info", "warning", "error"} else "info"
    conn.execute(
        "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, ?, ?, ?)",
        (scan_id, now(), level, kind[:40], message[:500]),
    )
    conn.commit()


def record_progress(conn: sqlite3.Connection, scan_id: str, counters: Dict[str, object]) -> None:
    """Persist the live counters, committing so the UI sees them while the scan runs."""
    conn.execute(
        "UPDATE scans SET counters = ?, updated_at = ? WHERE id = ?",
        (json.dumps(counters, separators=(",", ":")), now(), scan_id),
    )
    conn.commit()


def _safe_transition(conn: sqlite3.Connection, **kwargs) -> None:
    try:
        scan_service.transition(conn, **kwargs)
    except Exception:
        conn.rollback()
        log.exception("transition_failed scan_id=%s", kwargs.get("scan_id"))


def execute_scan(conn: sqlite3.Connection, scan_id: str, worker_id: str = WORKER_ID) -> ScanSummary:
    settings = get_settings()
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        raise RuntimeError("scan not found")
    if str(scan["state"]) == "queued":
        timestamp = now()
        conn.execute(
            """
            UPDATE scans SET state = 'running', worker_id = ?, heartbeat_at = ?, lease_expires_at = ?,
                             started_at = COALESCE(started_at, ?), updated_at = ?
            WHERE id = ? AND state = 'queued'
            """,
            (worker_id, timestamp, timestamp + settings.worker_lease_seconds, timestamp, timestamp, scan_id),
        )
        conn.commit()
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    context = _load_context(conn, scan)
    cancel_event = threading.Event()
    heartbeat = Heartbeat(scan_id, settings.worker_lease_seconds, cancel_event)
    heartbeat.start()
    def _record_event(kind: str, message: str, level: str = "info") -> None:
        record_event(conn, scan_id, kind, message, level)

    def _record_progress(counters: Dict[str, object]) -> None:
        record_progress(conn, scan_id, counters)

    summary = ScanSummary()
    started = time.monotonic()
    config = json.loads(scan["config"] or "{}")
    max_seconds = float(config.get("max_seconds", 300))
    grace_period = 5.0
    timeout_deadline = max_seconds + grace_period

    scanner = Scanner(
        conn,
        settings,
        scan=cast(Dict[str, object], context["scan"]),
        target=cast(Dict[str, object], context["target"]),
        baseline_document=context["baseline_document"],
        baseline_label=str(context["baseline_label"]),
        har_text=cast(Optional[str], context["har_text"]),
        har_name=str(context["har_name"]),
        event=_record_event,
        cancel_check=cancel_event.is_set,
        progress=_record_progress,
    )

    worker_result: Dict[str, object] = {"summary": summary, "error": None, "done": False}

    def _scanner_target() -> None:
        try:
            worker_result["summary"] = scanner.run()
        except Exception as ex:
            worker_result["error"] = ex
        finally:
            worker_result["done"] = True

    scanner_thread = threading.Thread(target=_scanner_target, daemon=True, name=f"scanner-{scan_id[:8]}")
    scanner_thread.start()

    timed_out = False
    cancelled_by_watchdog = False
    cancel_requested_at = 0.0

    while True:
        scanner_thread.join(timeout=0.5)
        if hasattr(scanner, "_progress"):
            try:
                scanner._progress()
            except Exception:
                pass
        if not scanner_thread.is_alive():
            break
        now_mono = time.monotonic()
        if (now_mono - started) >= timeout_deadline:
            timed_out = True
            cancel_event.set()
            break
        # Force-finish cancel if scan has not reacted to cancel_requested after grace period
        if cancel_event.is_set():
            if not cancelled_by_watchdog:
                cancel_requested_at = now_mono
                cancelled_by_watchdog = True
            elif (now_mono - cancel_requested_at) >= 5.0:
                # Cancel grace period expired; abandon stuck scanner thread
                break

    try:
        if timed_out:
            scanner.summary.partial = True
            if hasattr(scanner, "_progress"):
                try:
                    scanner._progress()
                except Exception:
                    pass
            if scanner.summary.phase == "queued":
                scanner.summary.phase = "discover"
            record_event(conn, scan_id, "scan.timeout", f"Watchdog: scan exceeded hard wall-clock limit ({int(max_seconds)}s)", "warning")
            _safe_transition(
                conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running", "cancelling"],
                to_state="timed_out", partial=True, error_category="timeout", error_message="Scan exceeded hard wall-clock time limit.",
            )
            summary = scanner.summary
            conn.execute(
                "UPDATE scans SET counters = ?, updated_at = ? WHERE id = ?",
                (json.dumps(summary.as_counters(), separators=(",", ":")), now(), scan_id),
            )
            conn.commit()
            return summary

        if cancelled_by_watchdog and scanner_thread.is_alive():
            scanner.summary.partial = True
            scanner.summary.cancelled = True
            if hasattr(scanner, "_progress"):
                try:
                    scanner._progress()
                except Exception:
                    pass
            if scanner.summary.phase == "queued":
                scanner.summary.phase = "discover"
            record_event(conn, scan_id, "scan.cancelled", "Watchdog: cancellation forced after grace period", "warning")
            _safe_transition(
                conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running", "cancelling"],
                to_state="cancelled", partial=True,
            )
            summary = scanner.summary
            conn.execute(
                "UPDATE scans SET counters = ?, updated_at = ? WHERE id = ?",
                (json.dumps(summary.as_counters(), separators=(",", ":")), now(), scan_id),
            )
            conn.commit()
            return summary

        if worker_result["error"]:
            raise worker_result["error"]

        summary = cast(ScanSummary, worker_result["summary"])
        conn.execute(
            "UPDATE scans SET counters = ?, updated_at = ? WHERE id = ?",
            (json.dumps(summary.as_counters(), separators=(",", ":")), now(), scan_id),
        )
        conn.commit()
        elapsed = time.monotonic() - started
        current = conn.execute("SELECT state FROM scans WHERE id = ?", (scan_id,)).fetchone()["state"]
        if summary.cancelled or current == "cancelling":
            _safe_transition(
                conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running", "cancelling"],
                to_state="cancelled", partial=True,
            )
        elif elapsed >= max_seconds:
            _safe_transition(
                conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running"],
                to_state="timed_out", partial=True, error_category="timeout", error_message="Scan time limit reached.",
            )
        else:
            _safe_transition(
                conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running"],
                to_state="completed", partial=summary.partial, error_category=None,
            )
        conn.execute(
            "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, 'info', 'scan.finished', ?)",
            (scan_id, now(), f"Scan finished with {summary.findings} findings and {summary.endpoints_found} endpoints"),
        )
        conn.commit()
        return summary
    except ScanTimeout:
        _safe_transition(
            conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running"],
            to_state="timed_out", partial=True, error_category="timeout", error_message="Scan time limit reached.",
        )
        conn.commit()
        return summary
    except ScanCancelled:
        _safe_transition(
            conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running", "cancelling"],
            to_state="cancelled", partial=True,
        )
        conn.commit()
        return summary
    except Exception as exc:  # pragma: no cover - defensive
        log.exception("scan_failed scan_id=%s", scan_id)
        _safe_transition(
            conn, scan_id=scan_id, org_id=str(scan["org_id"]), from_states=["running", "cancelling"],
            to_state="failed", partial=True, error_category="internal",
            error_message="The scan stopped because of an internal error.",
        )
        conn.execute(
            "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, 'error', 'scan.error', ?)",
            (scan_id, now(), type(exc).__name__[:120]),
        )
        conn.commit()
        return summary
    finally:
        heartbeat.stop()


def recover_stale(conn: sqlite3.Connection) -> int:
    """Fail scans whose worker lease expired or that exceeded max_seconds + grace, keeping partial results."""
    timestamp = now()
    recovered_count = 0

    # 1. Lease expired (worker crashed / lost)
    rows = conn.execute(
        "SELECT id, org_id FROM scans WHERE state IN ('running','cancelling') AND (lease_expires_at IS NULL OR lease_expires_at < ?)",
        (timestamp,),
    ).fetchall()
    for row in rows:
        conn.execute(
            """
            UPDATE scans SET state = 'failed', partial = 1, error_category = 'internal',
                             error_message = 'The worker running this scan stopped responding.',
                             finished_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (timestamp, timestamp, row["id"]),
        )
        conn.execute(
            "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, 'error', 'worker.lost', ?)",
            (row["id"], timestamp, "Worker lease expired; scan marked failed with partial results kept"),
        )
        audit.record(
            conn, action="scan.worker_lost", org_id=str(row["org_id"]), actor_type="system",
            object_type="scan", object_id=str(row["id"]),
        )
        recovered_count += 1

    # 2. Wall-clock limit exceeded (running longer than max_seconds + grace, even if heartbeat is alive)
    running_rows = conn.execute(
        "SELECT id, org_id, config, started_at FROM scans WHERE state = 'running' AND started_at IS NOT NULL",
    ).fetchall()
    for row in running_rows:
        cfg = json.loads(row["config"] or "{}")
        max_sec = float(cfg.get("max_seconds", 300))
        grace = 10.0
        started_at = int(row["started_at"])
        if (timestamp - started_at) > (max_sec + grace):
            conn.execute(
                """
                UPDATE scans SET state = 'timed_out', partial = 1, error_category = 'timeout',
                                 error_message = 'Scan exceeded wall-clock limit; timed out by recovery watchdog.',
                                 finished_at = ?, updated_at = ?
                WHERE id = ? AND state = 'running'
                """,
                (timestamp, timestamp, row["id"]),
            )
            conn.execute(
                "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, 'warning', 'scan.timeout', ?)",
                (row["id"], timestamp, f"Recovery watchdog: scan ran for {timestamp - started_at}s (limit {int(max_sec)}s); timed out"),
            )
            audit.record(
                conn, action="scan.timeout", org_id=str(row["org_id"]), actor_type="system",
                object_type="scan", object_id=str(row["id"]),
            )
            recovered_count += 1

    # 3. Cancelling scans stuck in cancelling for longer than grace (force-finish)
    cancelling_rows = conn.execute(
        "SELECT id, org_id, updated_at FROM scans WHERE state = 'cancelling'",
    ).fetchall()
    for row in cancelling_rows:
        updated_at = int(row["updated_at"] or timestamp)
        if (timestamp - updated_at) > 10.0:
            conn.execute(
                """
                UPDATE scans SET state = 'cancelled', partial = 1,
                                 finished_at = ?, updated_at = ?
                WHERE id = ? AND state = 'cancelling'
                """,
                (timestamp, timestamp, row["id"]),
            )
            conn.execute(
                "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, 'warning', 'scan.cancelled', ?)",
                (row["id"], timestamp, "Recovery watchdog: cancellation forced after grace period"),
            )
            audit.record(
                conn, action="scan.cancelled", org_id=str(row["org_id"]), actor_type="system",
                object_type="scan", object_id=str(row["id"]),
            )
            recovered_count += 1

    conn.commit()
    return recovered_count


def _startup_diagnostics(settings) -> None:
    log.info(
        "worker_starting id=%s env=%s database=%s allowlist=%s scanning=%s lab_url=%s",
        WORKER_ID,
        settings.env,
        settings.database_path,
        [f"{host}:{port}" for host, port in settings.private_allowlist] or "none",
        settings.scanning_enabled,
        f"http://{settings.lab_host}:{settings.lab_port}" if settings.lab_enabled else "disabled",
    )
    if not settings.scanning_enabled:
        log.warning("worker_scanning_disabled the worker will idle until ST_SCANNING_ENABLED=1")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="ShadowTrace scan worker")
    parser.add_argument("--once", action="store_true", help="run at most one scan then exit")
    parser.add_argument("--recover", action="store_true", help="fail scans with an expired lease, then exit")
    parser.add_argument("--scan-id", default="", help="execute a specific queued scan")
    args = parser.parse_args(argv)
    settings = get_settings()
    logging.basicConfig(level=settings.log_level)
    _startup_diagnostics(settings)
    with db() as conn:
        record_heartbeat(conn, WORKER_ID)
        recovered = recover_stale(conn)
        if recovered:
            log.info("recovered_stale_scans count=%s", recovered)
    if args.recover:
        return
    if args.scan_id:
        with db() as conn:
            execute_scan(conn, args.scan_id)
        return
    scans_run = 0

    def _shutdown(signum, _frame) -> None:  # pragma: no cover - signal path
        log.info("worker_stopping signal=%s scans_run=%s", signum, scans_run)
        raise SystemExit(0)

    for signal_name in ("SIGTERM", "SIGINT"):
        if hasattr(signal, signal_name):  # SIGTERM is absent on some Windows shells
            try:
                signal.signal(getattr(signal, signal_name), _shutdown)
            except (OSError, ValueError):  # pragma: no cover - not the main thread
                pass

    while True:
        scan_id: Optional[str] = None
        if not get_settings().scanning_enabled:
            if args.once:
                return  # a disabled scanner must not turn `--once` into an infinite wait
            with db() as conn:
                record_heartbeat(conn, WORKER_ID, scans_run=scans_run)
            time.sleep(2)
            continue
        with db() as conn:
            record_heartbeat(conn, WORKER_ID, scans_run=scans_run)
            scan_id = claim_next(conn, WORKER_ID, settings.worker_lease_seconds)
            if scan_id is None:
                pass
            else:
                log.info("scan_claimed scan_id=%s", scan_id)
                execute_scan(conn, scan_id)
                scans_run += 1
                log.info("scan_finished scan_id=%s", scan_id)
                # A worker that just finished a scan may have left the lease of a crashed
                # peer behind; sweep it so the UI never shows a job stuck in "running".
                recovered = recover_stale(conn)
                if recovered:
                    log.info("recovered_stale_scans count=%s", recovered)
        if args.once:
            return
        if scan_id is None:
            time.sleep(max(0.2, settings.worker_poll_seconds))


if __name__ == "__main__":
    main()
