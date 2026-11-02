"""CLI password handling: where the credential comes from, and what happens when it doesn't.

Regression origin: on Windows `getpass.getpass()` reads the console handle directly, so with
`stdin=subprocess.DEVNULL` it can still report an interactive stdin and return "" on EOF.
The empty string was treated as a supplied password and reached `validate_password()`, which
reported "password must be at least 12 characters" instead of the missing-password error.
The validator was correct; the input-source decision in `app.cli` was not.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from app import cli
from app.security.passwords import verify_password

BACKEND = Path(__file__).resolve().parent.parent
PASSWORD = "Correct-Horse-Battery-9!"
MISSING = "Provide --password or ST_ADMIN_PASSWORD"


def _args(password: str = "") -> argparse.Namespace:
    return argparse.Namespace(email="cli@example.test", name="CLI User", org="CLI Org", password=password)


def _clean_env(tmp_path, name: str) -> dict:
    return {
        **{k: v for k, v in os.environ.items() if not k.startswith("ST_")},
        "ST_ENV": "test",
        "ST_DATABASE_PATH": str(tmp_path / name),
    }


def _run(tmp_path, name: str, *extra: str, env_extra: dict | None = None, stdin=None) -> subprocess.CompletedProcess:
    env = _clean_env(tmp_path, name)
    env.pop("ST_ADMIN_PASSWORD", None)
    env.update(env_extra or {})
    return subprocess.run(
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
            *extra,
        ],
        cwd=str(BACKEND),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
        stdin=stdin if stdin is not None else subprocess.DEVNULL,
    )


# --------------------------------------------------------------- unit: source selection


def test_password_flag_is_used_verbatim(monkeypatch):
    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    # Surrounding spaces are part of the credential and must not be trimmed.
    assert cli._password(_args("  spaced pass  ")) == "  spaced pass  "


def test_env_password_is_used_when_no_flag(monkeypatch):
    monkeypatch.setenv("ST_ADMIN_PASSWORD", PASSWORD)
    assert cli._password(_args()) == PASSWORD


def test_password_flag_takes_precedence_over_env(monkeypatch):
    monkeypatch.setenv("ST_ADMIN_PASSWORD", "env-value-1234")
    assert cli._password(_args("flag-value")) == "flag-value"


@pytest.mark.parametrize("blank", ["", " ", "\t", "   \n  "])
def test_blank_env_value_counts_as_missing(monkeypatch, blank):
    """A whitespace-only ST_ADMIN_PASSWORD must not be dressed up as a weak password."""
    monkeypatch.setenv("ST_ADMIN_PASSWORD", blank)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    assert cli._password(_args()) is None


def test_no_source_and_non_interactive_stdin_is_missing(monkeypatch):
    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False, raising=False)
    assert cli._password(_args()) is None


def test_missing_stdin_stream_is_treated_as_non_interactive(monkeypatch):
    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys, "stdin", None)
    assert cli._password(_args()) is None


def test_interactive_prompt_value_is_used(monkeypatch):
    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="Password: ": PASSWORD)
    assert cli._password(_args()) == PASSWORD


def test_interactive_prompt_eof_is_treated_as_missing(monkeypatch):
    """The reported bug: prompt returns "" (EOF on a Windows console handle)."""

    def _eof(prompt: str = "Password: ") -> str:
        return ""

    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(getpass, "getpass", _eof)
    assert cli._password(_args()) is None


def test_interactive_prompt_eof_exception_is_treated_as_missing(monkeypatch):
    def _raise(prompt: str = "Password: ") -> str:
        raise EOFError("stdin closed")

    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(getpass, "getpass", _raise)
    assert cli._password(_args()) is None


def test_interactive_prompt_ctrl_c_is_treated_as_missing(monkeypatch):
    def _interrupt(prompt: str = "Password: ") -> str:
        raise KeyboardInterrupt

    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(getpass, "getpass", _interrupt)
    assert cli._password(_args()) is None


def test_interactive_prompt_bare_enter_is_treated_as_missing(monkeypatch):
    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(getpass, "getpass", lambda prompt="Password: ": "  ")
    assert cli._password(_args()) is None


def test_isatty_that_raises_counts_as_non_interactive(monkeypatch):
    def _boom() -> bool:
        raise ValueError("I/O operation on closed file")

    monkeypatch.delenv("ST_ADMIN_PASSWORD", raising=False)
    monkeypatch.setattr(sys.stdin, "isatty", _boom, raising=False)
    assert cli._password(_args()) is None


# ------------------------------------------------------------- end to end via subprocess


def test_cli_reports_missing_password_in_non_interactive_mode(tmp_path):
    result = _run(tmp_path, "missing.db")
    assert result.returncode == 2, result.stderr
    assert MISSING in result.stderr
    # The policy error must not be what the operator sees: nothing was supplied, so nothing
    # was validated.
    assert "must be at least 12 characters" not in result.stderr
    assert (tmp_path / "missing.db").exists(), "the CLI should still have applied migrations"


def test_cli_accepts_password_from_the_environment(tmp_path):
    result = _run(tmp_path, "env.db", env_extra={"ST_ADMIN_PASSWORD": PASSWORD})
    assert result.returncode == 0, result.stderr
    assert "created admin cli-admin@example.test" in result.stdout


def test_cli_prefers_the_flag_over_the_environment(tmp_path):
    """A valid --password must win even when the env var holds something unusable."""
    result = _run(tmp_path, "precedence.db", "--password", PASSWORD, env_extra={"ST_ADMIN_PASSWORD": "x"})
    assert result.returncode == 0, result.stderr


def test_cli_rejects_a_blank_environment_password_as_missing(tmp_path):
    result = _run(tmp_path, "blank.db", env_extra={"ST_ADMIN_PASSWORD": "   "})
    assert result.returncode == 2
    assert MISSING in result.stderr


@pytest.mark.parametrize(
    "candidate, expected",
    [
        ("short", "at least 12 characters"),
        ("passwordpassword", "too common"),
        ("alllowercase12", "three of"),
    ],
)
def test_supplied_passwords_are_still_validated(tmp_path, candidate, expected):
    """Security is unchanged: a real but weak password is rejected by the policy."""
    result = _run(tmp_path, "weak.db", "--password", candidate)
    assert result.returncode == 2
    assert expected in result.stderr


def test_the_created_admin_is_stored_with_argon2id_and_verifies(tmp_path):
    """End to end: the CLI writes an Argon2id hash that the login verifier accepts.

    Reads the database file directly, so the assertion does not depend on process-wide
    settings or environment state.
    """
    created = _run(tmp_path, "auth.db", "--password", PASSWORD)
    assert created.returncode == 0, created.stderr

    with sqlite3.connect(tmp_path / "auth.db") as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT email, role, password_hash FROM users WHERE email = ?", ("cli-admin@example.test",)
        ).fetchone()
        org = conn.execute("SELECT name FROM organizations WHERE id = (SELECT org_id FROM users WHERE email = ?)",
                           ("cli-admin@example.test",)).fetchone()
        audited = conn.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE action = 'system.admin_created'"
        ).fetchone()["n"]

    assert row is not None
    assert row["role"] == "admin"
    assert row["password_hash"].startswith("$argon2id$")
    assert org["name"] == "CLI Org"
    assert audited == 1
    assert verify_password(PASSWORD, row["password_hash"]) is True
    assert verify_password("wrong-password-1234", row["password_hash"]) is False
    assert verify_password("", row["password_hash"]) is False
    # The plaintext never reaches the database.
    assert PASSWORD not in row["password_hash"]


# ------------------------------------------------- bootstrap admin (environment variables)


def _bootstrap_env(monkeypatch, tmp_path, email, password):
    monkeypatch.setenv("ST_ENV", "test")
    monkeypatch.setenv("ST_DATABASE_PATH", str(tmp_path / "bootstrap.db"))
    monkeypatch.setenv("ST_BOOTSTRAP_ADMIN_EMAIL", email)
    monkeypatch.setenv("ST_BOOTSTRAP_ADMIN_PASSWORD", password)
    from app.config import reset_settings_cache
    from app.db import db, init_db

    reset_settings_cache()
    init_db()
    return db


def test_bootstrap_admin_is_created_from_the_environment(monkeypatch, tmp_path):
    db = _bootstrap_env(monkeypatch, tmp_path, "boot@example.test", PASSWORD)
    from app.main import bootstrap_admin_if_configured

    bootstrap_admin_if_configured()
    with db() as conn:
        row = conn.execute("SELECT role, password_hash FROM users WHERE email = ?", ("boot@example.test",)).fetchone()
    assert row is not None and row["role"] == "admin"
    assert row["password_hash"].startswith("$argon2id$")
    assert verify_password(PASSWORD, row["password_hash"]) is True


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_bootstrap_password_is_not_configured(monkeypatch, tmp_path, blank):
    """Consistent with the CLI: a blank env value means "no password", not "weak password"."""
    db = _bootstrap_env(monkeypatch, tmp_path, "boot@example.test", blank)
    from app.main import bootstrap_admin_if_configured

    bootstrap_admin_if_configured()  # must not raise
    with db() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 0


def test_weak_bootstrap_password_still_fails_closed(monkeypatch, tmp_path):
    """Security is unchanged: a real but weak password refuses to start."""
    _bootstrap_env(monkeypatch, tmp_path, "boot@example.test", "short")
    from app.main import bootstrap_admin_if_configured
    from app.security.passwords import WeakPassword

    with pytest.raises(WeakPassword):
        bootstrap_admin_if_configured()


def test_bootstrap_is_skipped_when_users_already_exist(monkeypatch, tmp_path):
    db = _bootstrap_env(monkeypatch, tmp_path, "boot@example.test", PASSWORD)
    from app.main import bootstrap_admin_if_configured

    bootstrap_admin_if_configured()
    bootstrap_admin_if_configured()  # idempotent, no duplicate org/user
    with db() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM organizations").fetchone()["n"] == 1
