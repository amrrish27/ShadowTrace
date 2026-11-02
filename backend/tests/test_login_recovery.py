"""Regression tests for the round-9 login defects.

Each test pins one confirmed finding from the audit (``AUDIT-shadowtrace-login-2026-10-27.md``):

* BUG-01 -- the documented bootstrap password (the one with ``!`` in it) must actually
  authenticate after bootstrap. It could not on Windows, because ``start.cmd`` enabled
  delayed expansion and the ``!`` was consumed before the API ever saw the value. The
  script-level guard lives in ``scripts/check_windows_scripts.py``; this file proves the
  server side of the same promise.
* BUG-02 -- a lab that fails to start must not stop the API.
* BUG-03 -- readiness must be process-scoped: a worker heartbeat from an earlier run must
  not satisfy the probe.
* BUG-04 -- an administrator can be recovered offline, audited, with sessions revoked.
* BUG-05 -- a password with leading or trailing whitespace must work, because the bootstrap
  path and the CLI hash it verbatim.
* BUG-07 -- a rate-limited login leaves an audit row.
* BUG-09 -- an adopted process is only "the lab" when it identifies itself.
* SEC-01 -- the key that used to be printed in start.cmd is refused in production.
"""
from __future__ import annotations

import importlib.util
import sqlite3
import time
from pathlib import Path

import pytest

from app.config import reset_settings_cache
from app.db import init_db
from app.security.ratelimit import limiter

#: Exactly the value in start.cmd / start.sh / README.md. The trailing '!' is the point:
#: it is the character cmd.exe used to swallow.
DOCUMENTED_PASSWORD = "Bootstrap-Admin-Pass-9!"


def _fresh_database(monkeypatch, tmp_path, filename: str, password: str, email: str = "admin@example.test"):
    """Point the settings at a new database and bootstrap it, like a first start.cmd run."""
    monkeypatch.setenv("ST_ENV", "test")
    monkeypatch.setenv("ST_DATABASE_PATH", str(tmp_path / filename))
    monkeypatch.setenv("ST_SECRET_KEY", "k" * 48)
    monkeypatch.setenv("ST_ALLOWED_HOSTS", "testserver,localhost,127.0.0.1")
    monkeypatch.setenv("ST_CORS_ORIGINS", "http://testserver")
    monkeypatch.setenv("ST_COOKIE_SECURE", "false")
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", "")
    monkeypatch.setenv("ST_SCANNING_ENABLED", "true")
    monkeypatch.setenv("ST_BOOTSTRAP_ADMIN_EMAIL", email)
    monkeypatch.setenv("ST_BOOTSTRAP_ADMIN_PASSWORD", password)
    monkeypatch.setenv("ST_BOOTSTRAP_ORG_NAME", "Bootstrap Org")
    monkeypatch.delenv("SCANNING_ENABLED", raising=False)
    reset_settings_cache()

    from app.main import bootstrap_admin_if_configured

    init_db()
    bootstrap_admin_if_configured()
    limiter.reset()


@pytest.fixture()
def bootstrapped(monkeypatch, tmp_path):
    """A TestClient whose database was created by *bootstrap*, not by the seed fixture."""
    from fastapi.testclient import TestClient

    from app.main import app

    _fresh_database(monkeypatch, tmp_path, "bootstrap.db", DOCUMENTED_PASSWORD)
    with TestClient(app) as client:
        yield client
    reset_settings_cache()


def test_the_documented_bootstrap_password_authenticates(bootstrapped):
    """BUG-01: the credential an operator is shown must be the credential the API hashed."""
    response = bootstrapped.post(
        "/api/v1/auth/login", json={"email": "admin@example.test", "password": DOCUMENTED_PASSWORD}
    )
    assert response.status_code == 200, response.text
    assert response.json()["user"]["role"] == "admin"


def test_the_truncated_password_is_not_a_second_credential(bootstrapped):
    """The 22-character form (what cmd.exe used to store) must not work either.

    It must not *also* be valid: two valid credentials for one account would be worse than
    the original bug, because the weaker one is the one printed on screen.
    """
    response = bootstrapped.post(
        "/api/v1/auth/login", json={"email": "admin@example.test", "password": DOCUMENTED_PASSWORD[:-1]}
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


def test_login_email_is_trimmed_and_lowercased(bootstrapped):
    response = bootstrapped.post(
        "/api/v1/auth/login", json={"email": "  ADMIN@Example.TEST  ", "password": DOCUMENTED_PASSWORD}
    )
    assert response.status_code == 200, response.text


def test_login_accepts_a_password_with_edge_whitespace(monkeypatch, tmp_path):
    """BUG-05: stored verbatim implies compared verbatim."""
    from fastapi.testclient import TestClient

    from app.main import app

    password = "  Padded-Password-9!  "
    _fresh_database(monkeypatch, tmp_path, "padded.db", password, email="padded@example.test")
    with TestClient(app) as client:
        assert client.post(
            "/api/v1/auth/login", json={"email": "padded@example.test", "password": password}
        ).status_code == 200
        assert client.post(
            "/api/v1/auth/login", json={"email": "padded@example.test", "password": password.strip()}
        ).status_code == 401
    reset_settings_cache()


def test_change_password_accepts_a_whitespace_padded_current_password(monkeypatch, tmp_path):
    """BUG-05 made `current_password` unverifiable, so the password could never be changed."""
    from fastapi.testclient import TestClient

    from app.main import app

    password = "  Padded-Password-9!  "
    _fresh_database(monkeypatch, tmp_path, "padded2.db", password, email="padded@example.test")
    with TestClient(app) as client:
        assert client.post(
            "/api/v1/auth/login", json={"email": "padded@example.test", "password": password}
        ).status_code == 200
        csrf = client.cookies.get("st_csrf") or ""
        changed = client.post(
            "/api/v1/auth/change-password",
            headers={"X-CSRF-Token": csrf},
            json={"current_password": password, "new_password": "Replacement-Pass-9!"},
        )
        assert changed.status_code == 200, changed.text
    reset_settings_cache()


def test_a_rate_limited_login_is_audited(client, app_env):
    """BUG-07: a 429 used to leave no trace, so "never tried" and "locked out" looked alike."""
    from app.db import db
    from app.security.ratelimit import POLICY

    limit, _window = POLICY["login_account"]
    for _ in range(limit):
        client.post("/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": "wrong-password-1"})
    blocked = client.post(
        "/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": "whatever-it-is-9!"}
    )
    assert blocked.status_code == 429
    limiter.reset()

    with db() as conn:
        row = conn.execute(
            "SELECT details FROM audit_log WHERE action = 'auth.login_rate_limited' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None, "a refused login must be auditable"
    details = str(row["details"])
    assert "viewer@org.example.test" in details
    assert "whatever-it-is-9!" not in details
    assert "password" not in details.lower()


def test_a_lab_that_fails_to_start_does_not_stop_the_api(monkeypatch, tmp_path):
    """BUG-02: the demo convenience must not be able to take the product down."""
    from fastapi.testclient import TestClient

    from app.main import app
    from app.services import lab as lab_service

    monkeypatch.setenv("ST_ENV", "test")
    monkeypatch.setenv("ST_DATABASE_PATH", str(tmp_path / "labfail.db"))
    monkeypatch.setenv("ST_SECRET_KEY", "k" * 48)
    monkeypatch.setenv("ST_ALLOWED_HOSTS", "testserver,localhost,127.0.0.1")
    monkeypatch.setenv("ST_CORS_ORIGINS", "http://testserver")
    monkeypatch.setenv("ST_COOKIE_SECURE", "false")
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", "127.0.0.1:8099")
    monkeypatch.setenv("ST_LAB_ENABLED", "true")
    monkeypatch.setenv("ST_LAB_AUTOSTART", "true")
    monkeypatch.setenv("ST_BOOTSTRAP_ADMIN_EMAIL", "")
    monkeypatch.setenv("ST_BOOTSTRAP_ADMIN_PASSWORD", "")
    reset_settings_cache()

    supervisor = lab_service.get_supervisor()

    def _boom() -> dict:
        raise lab_service.LabUnavailable("the lab did not become healthy within the start timeout")

    monkeypatch.setattr(supervisor, "start", _boom)
    monkeypatch.setattr(supervisor, "stop", lambda **kwargs: {})

    init_db()
    with TestClient(app) as failure_client:
        health = failure_client.get("/api/v1/health")
        assert health.status_code == 200, "the API must serve even when the lab cannot start"
        assert health.json()["status"] == "ok"
    reset_settings_cache()


def test_a_foreign_health_payload_is_not_the_lab(monkeypatch):
    """BUG-09: any local process can answer {"status": "ok"}; only ShadowLab says so."""
    from app.services.lab import LAB_MARKER, LabSupervisor

    supervisor = LabSupervisor()
    monkeypatch.setattr(supervisor, "_pid", lambda: None)
    monkeypatch.setattr("app.services.lab._port_open", lambda *args, **kwargs: True)
    monkeypatch.setattr("app.services.lab._http_get", lambda *args, **kwargs: '{"status": "ok"}')
    assert supervisor.status()["healthy"] is False

    monkeypatch.setattr(
        "app.services.lab._http_get",
        lambda *args, **kwargs: '{"status": "ok", "lab": "%s"}' % LAB_MARKER,
    )
    assert supervisor.status()["healthy"] is True


def test_the_published_local_secret_is_refused_in_production(monkeypatch):
    """SEC-01: the key that used to be printed in start.cmd must never run a deployment."""
    import app.config as config_module

    for key in list(__import__("os").environ):
        if key.startswith("ST_"):
            monkeypatch.delenv(key, raising=False)
    values = dict(
        env="production",
        secret_key=config_module.LOCAL_DEMO_SECRET,
        database_path="/tmp/st-test.db",
        base_url="https://shadowtrace.example.test",
        allowed_hosts=("shadowtrace.example.test",),
        cors_origins=("https://shadowtrace.example.test",),
        cookie_secure=True,
        session_idle_seconds=1800,
        session_absolute_seconds=43200,
        trusted_proxies=(),
        private_allowlist=(),
        max_requests_per_scan_hard_cap=2000,
        max_pages_per_scan_hard_cap=200,
        max_scan_seconds_hard_cap=900,
        max_upload_bytes=8 * 1024 * 1024,
        max_response_bytes=5 * 1024 * 1024,
        scan_concurrency_per_org=3,
        scans_per_day_per_org=50,
        retention_days=90,
        worker_poll_seconds=0.5,
        worker_lease_seconds=30,
        demo_mode=False,
        scanning_enabled=True,
        log_level="INFO",
    )
    with pytest.raises(Exception) as excinfo:
        config_module._validate(config_module.Settings(**values))
    assert "development secret" in str(excinfo.value)


def _load_script(name: str):
    script = Path(__file__).resolve().parents[2] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wait_healthy_ignores_a_stale_worker(tmp_path):
    """BUG-03: a heartbeat written by an earlier run must not satisfy the probe."""
    module = _load_script("wait_healthy")

    db_path = tmp_path / "probe.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE worker_heartbeats (worker_id TEXT PRIMARY KEY, hostname TEXT, pid INTEGER, "
        "started_at INTEGER, last_seen_at INTEGER, scans_run INTEGER, version TEXT)"
    )
    now = int(time.time())
    conn.execute(
        "INSERT INTO worker_heartbeats VALUES ('old', 'host', 1, ?, ?, 5, '1.0.0')", (now - 600, now)
    )
    conn.commit()
    conn.close()

    assert module.wait_for_worker(str(db_path), timeout=1.5, since=now - 5) is False
    assert module.wait_for_worker(str(db_path), timeout=1.5, since=now - 900) is True


def test_wait_healthy_rejects_a_port_held_by_another_process(tmp_path):
    """BUG-03: something answering is not the same as *this run's* API answering."""
    module = _load_script("wait_healthy")

    log = tmp_path / "api.log"
    log.write_text("INFO uvicorn running\nERROR [Errno 10048] address already in use\n", encoding="utf-8")
    # The helper itself only reads the file; assert the contract it is used for.
    assert module._log_contains(str(log), "application_started") is False
    log.write_text("INFO application_started env=development version=1.0.0\n", encoding="utf-8")
    assert module._log_contains(str(log), "application_started") is True


def test_windows_scripts_are_clean():
    """The guard that fails CI if delayed expansion (or a mangled credential) comes back."""
    module = _load_script("check_windows_scripts")
    assert module.check() == []


# ---------------------------------------------------------------------------
# BUG-04 -- the offline administrator recovery command
# ---------------------------------------------------------------------------


def _run_cli(monkeypatch, *argv: str) -> int:
    import sys

    from app import cli

    monkeypatch.setattr(sys, "argv", ["app.cli", *argv])
    return cli.main()


@pytest.fixture()
def recovery_env(monkeypatch, tmp_path):
    """A bootstrapped database plus a live session, so revocation is observable."""
    from fastapi.testclient import TestClient

    from app.main import app

    _fresh_database(monkeypatch, tmp_path, "recovery.db", DOCUMENTED_PASSWORD)
    with TestClient(app) as client:
        assert client.post(
            "/api/v1/auth/login", json={"email": "admin@example.test", "password": DOCUMENTED_PASSWORD}
        ).status_code == 200
        session = client.cookies.get("st_session") or ""
        yield client, session
    reset_settings_cache()


def test_reset_password_restores_access_and_revokes_sessions(recovery_env, monkeypatch):
    client, revoked_cookie = recovery_env
    new_password = "Recovered-Admin-Pass-7!"

    rc = _run_cli(
        monkeypatch, "reset-password", "--email", "admin@example.test", "--password", new_password
    )
    assert rc == 0

    from app.db import db

    with db() as conn:
        audit_row = conn.execute(
            "SELECT details FROM audit_log WHERE action = 'system.admin_password_reset' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        live = conn.execute(
            "SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NULL"
        ).fetchone()["n"]
    assert audit_row is not None
    assert "Recovered-Admin-Pass-7!" not in str(audit_row["details"])
    assert live == 0, "every session must be revoked by a credential reset"

    # The old session cookie is dead ...
    stale = client.get("/api/v1/auth/me", headers={"Cookie": f"st_session={revoked_cookie}"})
    assert stale.status_code in (401, 403)

    # ... the old password is gone, the new one works.
    client.cookies.clear()
    assert client.post(
        "/api/v1/auth/login", json={"email": "admin@example.test", "password": DOCUMENTED_PASSWORD}
    ).status_code == 401
    assert client.post(
        "/api/v1/auth/login", json={"email": "admin@example.test", "password": new_password}
    ).status_code == 200


def test_reset_password_refuses_an_unknown_user(recovery_env, monkeypatch):
    from app.db import db

    with db() as conn:
        before = conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'system.admin_password_reset'").fetchone()["n"]
    rc = _run_cli(monkeypatch, "reset-password", "--email", "nobody@example.test", "--password", "Whatever-Pass-9!")
    assert rc == 2
    with db() as conn:
        after = conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE action = 'system.admin_password_reset'").fetchone()["n"]
    assert after == before


def test_reset_password_applies_the_password_policy(recovery_env, monkeypatch):
    rc = _run_cli(monkeypatch, "reset-password", "--email", "admin@example.test", "--password", "short")
    assert rc == 2


def _production_environment(monkeypatch) -> None:
    """A *valid* production environment, so `_validate` cannot be what refuses the command."""
    monkeypatch.setenv("ST_ENV", "production")
    monkeypatch.setenv("ST_SECRET_KEY", "p" * 48)
    monkeypatch.setenv("ST_BASE_URL", "https://shadowtrace.example.test")
    monkeypatch.setenv("ST_ALLOWED_HOSTS", "shadowtrace.example.test")
    monkeypatch.setenv("ST_CORS_ORIGINS", "https://shadowtrace.example.test")
    monkeypatch.setenv("ST_COOKIE_SECURE", "true")
    monkeypatch.setenv("ST_DEMO_MODE", "false")
    monkeypatch.setenv("ST_LAB_ENABLED", "false")
    reset_settings_cache()


def test_reset_password_refuses_production_without_the_flag(tmp_path, monkeypatch):
    _fresh_database(monkeypatch, tmp_path, "prod.db", DOCUMENTED_PASSWORD)
    _production_environment(monkeypatch)
    rc = _run_cli(
        monkeypatch, "reset-password", "--email", "admin@example.test", "--password", "Recovered-Admin-Pass-7!"
    )
    assert rc == 2, "production must need an explicit --allow-production"
    reset_settings_cache()


def test_reset_password_honours_the_production_flag(tmp_path, monkeypatch):
    _fresh_database(monkeypatch, tmp_path, "prod2.db", DOCUMENTED_PASSWORD)
    _production_environment(monkeypatch)
    rc = _run_cli(
        monkeypatch,
        "reset-password",
        "--email",
        "admin@example.test",
        "--password",
        "Recovered-Admin-Pass-7!",
        "--allow-production",
    )
    assert rc == 0
    reset_settings_cache()

# ---------------------------------------------------------------------------
# BUG-11 -- recovery must target the operator's database, not the container default
# ---------------------------------------------------------------------------


def _bare_recovery_database(monkeypatch, tmp_path, filename: str = "local.db"):
    """Bootstrap a database, then forget ST_DATABASE_PATH like an untouched shell."""
    from app import cli

    db_file = tmp_path / "data" / filename
    db_file.parent.mkdir(parents=True, exist_ok=True)
    _fresh_database(monkeypatch, tmp_path / "data", filename, DOCUMENTED_PASSWORD)
    # _fresh_database points the settings at this file; now simulate "no env set at all"
    monkeypatch.delenv("ST_DATABASE_PATH", raising=False)
    reset_settings_cache()
    monkeypatch.setattr(cli, "LOCAL_DATABASE", db_file)
    return db_file


def test_recovery_finds_the_local_stack_database_without_any_env(monkeypatch, tmp_path):
    """BUG-11: ``cd backend && python -m app.cli reset-password`` must hit <project>/data.

    Without this, config.py's container default (/data/shadowtrace.db) is used: on Linux it
    raises PermissionError, and on Windows it silently resets a *different* database.
    """
    db_file = _bare_recovery_database(monkeypatch, tmp_path)

    rc = _run_cli(
        monkeypatch, "reset-password", "--email", "admin@example.test", "--password", "Recovered-Admin-Pass-7!"
    )

    assert rc == 0
    import sqlite3

    with sqlite3.connect(db_file) as conn:
        assert conn.execute("SELECT COUNT(*) FROM users WHERE email = 'admin@example.test'").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action = 'system.admin_password_reset'").fetchone()[0] == 1
    reset_settings_cache()


def test_an_explicit_database_wins_over_the_local_one(monkeypatch, tmp_path):
    """--database lets an operator point at a backup without touching the environment."""
    from app import cli

    local = _bare_recovery_database(monkeypatch, tmp_path)
    other = tmp_path / "elsewhere" / "copy.db"
    other.parent.mkdir()
    import shutil

    shutil.copy(local, other)

    rc = _run_cli(
        monkeypatch,
        "reset-password",
        "--email",
        "admin@example.test",
        "--password",
        "Recovered-Admin-Pass-7!",
        "--database",
        str(other),
    )

    assert rc == 0
    reset_settings_cache()
    assert cli._resolve_database(str(other)) == str(other.resolve())


def test_a_configured_database_is_not_overridden(monkeypatch, tmp_path):
    """ST_DATABASE_PATH (compose, CI) always outranks the local-stack guess."""
    from app import cli

    local = _bare_recovery_database(monkeypatch, tmp_path)
    chosen = tmp_path / "chosen.db"
    monkeypatch.setenv("ST_DATABASE_PATH", str(chosen))
    reset_settings_cache()

    assert cli._resolve_database(None) == str(chosen)
    assert cli._resolve_database(None) != str(local)


def test_the_error_names_the_database_that_was_searched(monkeypatch, tmp_path, capsys):
    """A reset against the wrong file must say so, not report a vanished account."""
    _bare_recovery_database(monkeypatch, tmp_path)
    empty = tmp_path / "empty" / "nothing.db"

    rc = _run_cli(
        monkeypatch,
        "reset-password",
        "--email",
        "admin@example.test",
        "--password",
        "Recovered-Admin-Pass-7!",
        "--database",
        str(empty),
    )

    assert rc == 2
    err = capsys.readouterr().err
    assert "no user with that email" in err
    assert str(empty.resolve()) in err
    reset_settings_cache()
