"""Scan lifecycle services, worker recovery and the admin CLI."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.db import db, new_id, now
from app.security.errors import ApiError
from app.services import scans as scan_service
from app.workers.worker import claim_next, recover_stale

BACKEND = Path(__file__).resolve().parent.parent
PASSWORD = "Correct-Horse-Battery-9!"


def _insert_scan(env, *, state: str, created_at: int | None = None, key: str | None = None) -> str:
    scan_id = new_id()
    timestamp = created_at or now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                               partial, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, '{}', '{}', ?, 0, ?, ?)
            """,
            (
                scan_id,
                env["target"]["org_id"],
                env["target"]["id"],
                env["org_analyst"]["id"],
                state,
                key or new_id(),
                timestamp,
                timestamp,
            ),
        )
    return scan_id


def _insert_endpoint(env, scan_id: str, method: str, path: str, status: int) -> None:
    """Attach an endpoint to a scan, reusing the row when the same path recurs."""
    endpoint_id = new_id()
    timestamp = now()
    with db() as conn:
        existing = conn.execute(
            "SELECT id FROM endpoints WHERE org_id = ? AND target_id = ? AND method = ? AND path_template = ?",
            (env["target"]["org_id"], env["target"]["id"], method, path),
        ).fetchone()
        if existing is not None:
            conn.execute(
                """INSERT INTO scan_endpoints (scan_id, endpoint_id, validation_status, classification, response_status)
                   VALUES (?, ?, 'live', 'shadow', ?)
                   ON CONFLICT(scan_id, endpoint_id) DO UPDATE SET response_status = excluded.response_status""",
                (scan_id, existing["id"], status),
            )
            conn.execute("UPDATE endpoints SET response_status = ? WHERE id = ?", (status, existing["id"]))
            return
        conn.execute(
            """
            INSERT INTO endpoints (id, org_id, target_id, host, method, path_template, query_template,
                                   classification, validation_status, response_status, fingerprint,
                                   first_seen_at, last_seen_at, first_seen_scan, last_seen_scan, origin)
            VALUES (?, ?, ?, '127.0.0.1', ?, ?, '', 'shadow', 'live', ?, ?, ?, ?, ?, ?, 'http://127.0.0.1:8099')
            """,
            (
                endpoint_id,
                env["target"]["org_id"],
                env["target"]["id"],
                method,
                path,
                status,
                f"{method}|127.0.0.1|{path}|",
                timestamp,
                timestamp,
                scan_id,
                scan_id,
            ),
        )
        conn.execute(
            "INSERT INTO scan_endpoints (scan_id, endpoint_id, validation_status, classification, response_status) VALUES (?, ?, 'live', 'shadow', ?)",
            (scan_id, endpoint_id, status),
        )


# ------------------------------------------------------------ services


def test_cancel_queued_scan_is_immediate(app_env):
    scan_id = _insert_scan(app_env, state="queued")
    with db() as conn:
        state = scan_service.request_cancel(
            conn, scan_id=scan_id, org_id=app_env["target"]["org_id"], user_id=app_env["org_analyst"]["id"]
        )
        assert state == "cancelled"
        row = conn.execute("SELECT state, cancel_requested, partial FROM scans WHERE id = ?", (scan_id,)).fetchone()
        assert row["state"] == "cancelled"
        assert row["cancel_requested"] == 1
        actions = [r["action"] for r in conn.execute("SELECT action FROM audit_log WHERE object_id = ?", (scan_id,))]
        assert "scan.cancelled" in actions


def test_cancel_running_scan_moves_to_cancelling(app_env):
    scan_id = _insert_scan(app_env, state="running")
    with db() as conn:
        assert scan_service.request_cancel(
            conn, scan_id=scan_id, org_id=app_env["target"]["org_id"], user_id=app_env["org_analyst"]["id"]
        ) == "cancelling"


def test_cancel_finished_scan_is_a_noop_and_unknown_scan_is_404(app_env):
    done = _insert_scan(app_env, state="completed")
    with db() as conn:
        assert scan_service.request_cancel(
            conn, scan_id=done, org_id=app_env["target"]["org_id"], user_id=app_env["org_analyst"]["id"]
        ) == "completed"
        with pytest.raises(ApiError) as missing:
            scan_service.request_cancel(conn, scan_id="nope", org_id=app_env["target"]["org_id"], user_id="x")
        assert missing.value.status_code == 404


def test_delete_requires_terminal_state_and_admin(app_env):
    active = _insert_scan(app_env, state="running")
    finished = _insert_scan(app_env, state="completed")
    with db() as conn:
        with pytest.raises(ApiError) as conflict:
            scan_service.delete_scan(
                conn, scan_id=active, org_id=app_env["target"]["org_id"], user_id="x", is_admin=True
            )
        assert conflict.value.status_code == 409
        with pytest.raises(ApiError) as forbidden:
            scan_service.delete_scan(
                conn, scan_id=finished, org_id=app_env["target"]["org_id"], user_id="x", is_admin=False
            )
        assert forbidden.value.status_code == 403
        scan_service.delete_scan(
            conn, scan_id=finished, org_id=app_env["target"]["org_id"], user_id="x", is_admin=True
        )
        assert conn.execute("SELECT 1 FROM scans WHERE id = ?", (finished,)).fetchone() is None


def test_compare_with_previous_reports_new_removed_and_changed(app_env):
    org_id = app_env["target"]["org_id"]
    previous_id = _insert_scan(app_env, state="completed", created_at=now() - 600)
    current_id = _insert_scan(app_env, state="completed", created_at=now())
    _insert_endpoint(app_env, previous_id, "GET", "/api/v1/kept", 200)
    _insert_endpoint(app_env, previous_id, "GET", "/api/v1/removed", 200)
    _insert_endpoint(app_env, current_id, "GET", "/api/v1/kept", 401)
    _insert_endpoint(app_env, current_id, "GET", "/api/v1/added", 200)
    with db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (current_id,)).fetchone()
        diff = scan_service.compare_with_previous(conn, scan, org_id)
    assert diff["previous_scan_id"] == previous_id
    assert [entry["path"] for entry in diff["new"]] == ["/api/v1/added"]
    assert [entry["path"] for entry in diff["removed"]] == ["/api/v1/removed"]
    assert diff["changed"][0]["path"] == "/api/v1/kept"
    assert diff["changed"][0]["previous_status"] == 200
    assert diff["changed"][0]["status"] == 401


def test_compare_without_previous_scan_is_empty(app_env):
    only = _insert_scan(app_env, state="completed")
    with db() as conn:
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (only,)).fetchone()
        diff = scan_service.compare_with_previous(conn, scan, app_env["target"]["org_id"])
    assert diff == {
        "previous_scan_id": None,
        "new": [],
        "removed": [],
        "changed": [],
        "findings_new": [],
        "findings_resolved": [],
    }


def test_expire_stale_scan_marks_failed_with_partial_results(app_env):
    from app.config import get_settings

    scan_id = _insert_scan(app_env, state="running")
    with db() as conn:
        scan_service.expire_stale_scan(conn, scan_id, get_settings(), "lease expired")
        row = conn.execute("SELECT state, partial, error_category, error_message FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert row["state"] == "failed"
    assert row["partial"] == 1
    assert row["error_category"] == "internal"
    assert "lease expired" in row["error_message"]
    # A second call on a terminal scan is a no-op.
    with db() as conn:
        scan_service.expire_stale_scan(conn, scan_id, get_settings(), "again")
        assert conn.execute("SELECT error_message FROM scans WHERE id = ?", (scan_id,)).fetchone()["error_message"] == row["error_message"]


# -------------------------------------------------------------- worker


def test_recover_stale_fails_abandoned_scans(app_env):
    stale = _insert_scan(app_env, state="running")
    with db() as conn:
        conn.execute("UPDATE scans SET lease_expires_at = ? WHERE id = ?", (now() - 3600, stale))
        recovered = recover_stale(conn)
        assert recovered >= 1
        row = conn.execute("SELECT state, partial, error_message FROM scans WHERE id = ?", (stale,)).fetchone()
        assert row["state"] == "failed"
        assert row["partial"] == 1
        assert "stopped responding" in row["error_message"]
        events = [r["kind"] for r in conn.execute("SELECT kind FROM scan_events WHERE scan_id = ?", (stale,))]
        assert "worker.lost" in events
        actions = [r["action"] for r in conn.execute("SELECT action FROM audit_log WHERE object_id = ?", (stale,))]
        assert "scan.worker_lost" in actions


def test_claim_next_takes_the_oldest_queued_scan(app_env):
    first = _insert_scan(app_env, state="queued", created_at=now() - 300)
    _insert_scan(app_env, state="queued", created_at=now())
    with db() as conn:
        claimed = claim_next(conn, "worker-test", 30)
        assert claimed == first
        row = conn.execute("SELECT state, worker_id, lease_expires_at FROM scans WHERE id = ?", (first,)).fetchone()
        assert row["state"] == "running"
        assert row["worker_id"] == "worker-test"
        assert row["lease_expires_at"] > now()
        # Nothing else is claimable twice.
        assert claim_next(conn, "worker-test", 30) != first


def test_claim_next_returns_none_when_nothing_is_queued(app_env):
    with db() as conn:
        assert claim_next(conn, "worker-test", 30) is None


# ----------------------------------------------------------------- CLI


def test_cli_create_admin(tmp_path, monkeypatch):
    env = {
        **{k: v for k, v in __import__("os").environ.items() if not k.startswith("ST_")},
        "ST_ENV": "test",
        "ST_DATABASE_PATH": str(tmp_path / "cli.db"),
        "ST_ALLOWED_HOSTS": "localhost",
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "create-admin",
            "--email",
            "cli-admin@example.test",
            "--name",
            "CLI Admin",
            "--org",
            "CLI Org",
            "--password",
            PASSWORD,
        ],
        cwd=str(BACKEND),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "created admin cli-admin@example.test" in result.stdout
    # Re-running is refused, and the audit trail records the creation once.
    again = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "create-admin",
            "--email",
            "cli-admin@example.test",
            "--name",
            "CLI Admin",
            "--org",
            "CLI Org",
            "--password",
            PASSWORD,
        ],
        cwd=str(BACKEND),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert again.returncode == 2
    assert "already exists" in again.stderr
    weak = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "create-admin",
            "--email",
            "second@example.test",
            "--name",
            "Second",
            "--org",
            "CLI Org",
            "--password",
            "password",
        ],
        cwd=str(BACKEND),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert weak.returncode == 2
    assert "password" in weak.stderr.lower()


def test_cli_rejects_missing_password_in_non_interactive_mode(tmp_path):
    env = {
        **{k: v for k, v in __import__("os").environ.items() if not k.startswith("ST_")},
        "ST_ENV": "test",
        "ST_DATABASE_PATH": str(tmp_path / "cli2.db"),
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "app.cli",
            "create-admin",
            "--email",
            "nopass@example.test",
            "--name",
            "No Pass",
            "--org",
            "CLI Org",
        ],
        cwd=str(BACKEND),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode != 0
    assert "Provide --password or ST_ADMIN_PASSWORD" in (result.stderr + result.stdout)


def test_cli_init_and_recover(tmp_path):
    env = {
        **{k: v for k, v in __import__("os").environ.items() if not k.startswith("ST_")},
        "ST_ENV": "test",
        "ST_DATABASE_PATH": str(tmp_path / "cli3.db"),
    }
    init = subprocess.run(
        [sys.executable, "-m", "app.cli", "init"], cwd=str(BACKEND), env=env, capture_output=True, text=True, timeout=120
    )
    assert init.returncode == 0, init.stderr
    recover = subprocess.run(
        [sys.executable, "-m", "app.cli", "recover"], cwd=str(BACKEND), env=env, capture_output=True, text=True, timeout=120
    )
    assert recover.returncode == 0, recover.stderr
    assert (tmp_path / "cli3.db").exists()


def test_cli_run_scan_requires_a_real_scan(tmp_path):
    env = {
        **{k: v for k, v in __import__("os").environ.items() if not k.startswith("ST_")},
        "ST_ENV": "test",
        "ST_DATABASE_PATH": str(tmp_path / "cli4.db"),
    }
    subprocess.run([sys.executable, "-m", "app.cli", "init"], cwd=str(BACKEND), env=env, check=True, timeout=120)
    missing = subprocess.run(
        [sys.executable, "-m", "app.cli", "run-scan", "--scan-id", "does-not-exist"],
        cwd=str(BACKEND),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert missing.returncode != 0
    assert "scan not found" in (missing.stderr + missing.stdout)


def test_json_helpers_roundtrip(analyst_client):
    """Scan config/counters are stored as compact JSON and read back safely."""
    client, headers, env = analyst_client
    created = client.post(
        "/api/v1/scans",
        json={"target_id": env["target"]["id"], "attestation": "Lifecycle service test attestation."},
        headers={**headers, "Idempotency-Key": "lifecycle-key-0001"},
    )
    assert created.status_code == 201
    payload = created.json()["scan"]
    assert json.loads(json.dumps(payload["config"]))["active_validation"] in {True, False}
    assert isinstance(payload["counters"], dict)
