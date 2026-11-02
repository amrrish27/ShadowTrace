"""Administration CLI: database init, bootstrap admin, worker helpers.

    python -m app.cli init
    python -m app.cli create-admin --email admin@example.com --name "Admin" --org "Acme"
    python -m app.cli reset-password --email admin@example.com
    python -m app.cli recover
    python -m app.cli run-scan --scan-id <id>

Run these from the ``backend`` directory (``cd backend``): there is no packaging metadata,
so ``app`` is importable only from there. Every command exits non-zero on failure.

Every command accepts ``--database FILE``.  With no flag the CLI prefers
``ST_DATABASE_PATH``, then ``<project>/data/shadowtrace.db`` when it exists (the local stack),
and only then the container default from ``config.py`` -- see ``_resolve_database``.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Optional

from .config import get_settings, reset_settings_cache
from .db import db, init_db, new_id, now
from .security import audit
from .security.passwords import WeakPassword, hash_password, validate_password


MISSING_CREDENTIAL_MSG = "Provide --password or ST_ADMIN_PASSWORD (non-interactive)"

#: ``backend/`` — these commands are only importable from here, so it is a stable anchor.
BACKEND_DIR = Path(__file__).resolve().parent.parent
#: Where ``start.cmd``/``start.sh`` put the local stack's database (``<project>/data``).
LOCAL_DATABASE = BACKEND_DIR.parent / "data" / "shadowtrace.db"


def _resolve_database(explicit: Optional[str]) -> Optional[str]:
    """Point this process at the operator's database and return the path used.

    ``config.py`` defaults ``ST_DATABASE_PATH`` to ``/data/shadowtrace.db`` because that is
    where the container puts it.  Run from a checkout, that path is either unwritable
    (``PermissionError``) or — worse on Windows — a *different*, empty database, so a reset
    would silently target the wrong file.  Resolution order:

    1. ``--database``;
    2. ``ST_DATABASE_PATH`` from the environment;
    3. ``<project>/data/shadowtrace.db`` when that file exists (the local stack);
    4. the configured default, unchanged.

    Returns the path the command will operate on, or ``None`` when nothing was overridden.
    """
    if explicit:
        os.environ["ST_DATABASE_PATH"] = str(Path(explicit).expanduser().resolve())
        reset_settings_cache()
        return os.environ["ST_DATABASE_PATH"]
    if os.environ.get("ST_DATABASE_PATH"):
        return os.environ["ST_DATABASE_PATH"]
    if LOCAL_DATABASE.is_file():
        os.environ["ST_DATABASE_PATH"] = str(LOCAL_DATABASE)
        reset_settings_cache()
        return str(LOCAL_DATABASE)
    return None


def _supplied(value: Optional[str]) -> Optional[str]:
    """Return the value when it carries a real credential, else None.

    Blank/whitespace-only values count as *not supplied* so the caller reports a missing
    password instead of a password-policy error. The value itself is never stripped: a
    password may legitimately contain leading or trailing spaces.
    """
    if value is None or not value.strip():
        return None
    return value


def _stdin_is_interactive() -> bool:
    """True only when a real terminal is attached.

    ``sys.stdin`` can be missing entirely (pythonw) or replaced by a non-file object in
    test harnesses, so both are treated as non-interactive.
    On Windows, NUL (e.g. stdin=subprocess.DEVNULL) is a character device where isatty()
    returns True, but GetConsoleMode fails.
    """
    stream = getattr(sys, "stdin", None)
    if stream is None:
        return False
    try:
        if not stream.isatty():
            return False
    except (ValueError, OSError):
        return False

    if sys.platform == "win32":
        try:
            import ctypes
            import msvcrt

            fileno = stream.fileno()
            h = msvcrt.get_osfhandle(fileno)
            mode = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                return False
        except (AttributeError, ValueError, OSError):
            pass

    return True


def _password(args: argparse.Namespace) -> Optional[str]:
    """Resolve the password to use, or None when the operator supplied no credential.

    Order: ``--password``, then ``ST_ADMIN_PASSWORD``, then an interactive prompt.
    A prompt that reads nothing (EOF / Ctrl-C / bare Enter) is a missing password, not an
    empty one: on Windows ``getpass`` reads the console handle directly, so it can return
    "" even when stdin is redirected. Passing that "" to ``validate_password`` is what
    produced "password must be at least 12 characters" instead of the missing-password
    error.
    """
    explicit = _supplied(getattr(args, "password", None))
    if explicit is not None:
        return explicit
    from_env = _supplied(os.environ.get("ST_ADMIN_PASSWORD", ""))
    if from_env is not None:
        return from_env
    if not _stdin_is_interactive():
        return None
    try:
        entered = getpass.getpass("Password: ")
    except (EOFError, KeyboardInterrupt):
        return None
    return _supplied(entered)


def create_admin(args: argparse.Namespace) -> int:
    settings = get_settings()
    email = args.email.strip().lower()
    password = _password(args)
    if password is None:
        print(f"error: {MISSING_CREDENTIAL_MSG}", file=sys.stderr)
        return 2
    try:
        validate_password(password, email=email, name=args.name)
    except WeakPassword as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            print("error: a user with that email already exists", file=sys.stderr)
            return 2
        org_row = conn.execute("SELECT id FROM organizations WHERE name = ?", (args.org,)).fetchone()
        if org_row is None:
            org_id = new_id()
            conn.execute("INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)", (org_id, args.org, now()))
        else:
            org_id = str(org_row["id"])
        user_id = new_id()
        conn.execute(
            """
            INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at)
            VALUES (?, ?, ?, ?, 'admin', ?, 1, ?)
            """,
            (user_id, org_id, email, args.name, hash_password(password), now()),
        )
        audit.record(
            conn, action="system.admin_created", org_id=org_id, actor_type="system",
            actor_id=user_id, details={"email": email, "env": settings.env},
        )
    print(f"created admin {email} in organization {args.org!r}")
    return 0


def reset_password(args: argparse.Namespace) -> int:
    """Reset one account's password offline. There is deliberately no HTTP equivalent.

    Why this exists: bootstrap runs only while the users table is empty, ``create-admin``
    refuses an email that already exists, and ``POST /auth/change-password`` needs the current
    password. Before this command, a wrong bootstrap password left an installation with no
    supported way back in -- the only options were hand-written SQL against the live file.

    Why it is safe: it requires filesystem access to the SQLite file, which is already total
    control of the deployment. It validates the new password against the same policy, revokes
    every session of that user (a stolen cookie must not survive a credential reset), and
    writes an audit row that records the email and the number of sessions revoked -- never a
    secret. Production needs an explicit ``--allow-production``.
    """
    settings = get_settings()
    email = args.email.strip().lower()
    if settings.is_production and not args.allow_production:
        print("error: refusing to reset a password in production without --allow-production", file=sys.stderr)
        return 2
    password = _password(args)
    if password is None:
        print(f"error: {MISSING_CREDENTIAL_MSG}", file=sys.stderr)
        return 2
    try:
        validate_password(password, email=email)
    except WeakPassword as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    with db() as conn:
        row = conn.execute("SELECT id, org_id FROM users WHERE email = ?", (email,)).fetchone()
        if row is None:
            print(
                f"error: no user with that email (database: {settings.database_path})",
                file=sys.stderr,
            )
            return 2
        revoked = conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (now(), row["id"]),
        ).rowcount
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), row["id"])
        )
        audit.record(
            conn,
            action="system.admin_password_reset",
            org_id=row["org_id"],
            actor_type="system",
            actor_id=str(row["id"]),
            details={"email": email, "sessions_revoked": int(revoked or 0), "env": settings.env},
        )
    print(f"password reset for {email}; {int(revoked or 0)} session(s) revoked")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="ShadowTrace administration")
    sub = parser.add_subparsers(dest="command", required=True)

    db_help = "database file to use (default: ST_DATABASE_PATH, else <project>/data)"

    init_parser = sub.add_parser("init", help="apply database migrations")
    init_parser.add_argument("--database", default=None, help=db_help)

    admin = sub.add_parser("create-admin", help="create the first administrator")
    admin.add_argument("--email", required=True)
    admin.add_argument("--name", default="Administrator")
    admin.add_argument("--org", default="ShadowTrace")
    admin.add_argument("--password", default="")
    admin.add_argument("--database", default=None, help=db_help)

    reset = sub.add_parser("reset-password", help="reset one account's password (offline)")
    reset.add_argument("--email", required=True)
    reset.add_argument("--password", default="")
    reset.add_argument("--allow-production", action="store_true")
    reset.add_argument("--database", default=None, help=db_help)

    recover = sub.add_parser("recover", help="fail scans whose worker lease expired")
    recover.add_argument("--database", default=None, help=db_help)

    run_scan = sub.add_parser("run-scan", help="execute one queued scan in this process")
    run_scan.add_argument("--scan-id", required=True)
    run_scan.add_argument("--database", default=None, help=db_help)

    args = parser.parse_args()
    # Resolve the database before anything opens it: the container default (/data) is the
    # wrong file when this runs from a checkout.
    _resolve_database(getattr(args, "database", None))
    if args.command == "init":
        init_db()
        print(f"database ready: {get_settings().database_path}")
        return 0
    if args.command == "create-admin":
        init_db()
        return create_admin(args)
    if args.command == "reset-password":
        init_db()
        return reset_password(args)
    if args.command == "recover":
        from .workers.worker import recover_stale

        with db() as conn:
            print("recovered:", recover_stale(conn))
        return 0
    if args.command == "run-scan":
        from .workers.worker import execute_scan

        with db() as conn:
            summary = execute_scan(conn, args.scan_id)
        print(summary.as_counters())
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
