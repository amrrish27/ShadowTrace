"""Database access: one connection factory, a tiny migration runner and helpers.

All SQL in the application is parameterized.  There is no string-built SQL.
The runtime connection enables foreign keys and uses WAL for concurrent readers.
"""
from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from .config import get_settings

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def new_id() -> str:
    return uuid.uuid4().hex


def now() -> int:
    return int(time.time())


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=15, isolation_level="DEFERRED", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    path = get_settings().database_path
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        yield conn


def apply_migrations(path: Optional[str] = None) -> List[str]:
    """Apply every unapplied .sql file in lexicographic order. Returns applied names."""
    db_path = path or get_settings().database_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    applied: List[str] = []
    conn = _connect(db_path)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)"
        )
        conn.commit()
        done = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}
        for sql_file in sorted(MIGRATIONS_DIR.glob("*.sql")):
            if sql_file.name in done:
                continue
            conn.executescript(sql_file.read_text(encoding="utf-8"))
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (sql_file.name, now())
            )
            conn.commit()
            applied.append(sql_file.name)
    finally:
        conn.close()
    return applied


def init_db() -> None:
    apply_migrations()


def fetch_one(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> Optional[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchone()


def fetch_all(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
    return list(conn.execute(sql, tuple(params)).fetchall())


def row_to_dict(row: Optional[sqlite3.Row]) -> Dict[str, Any]:
    return dict(row) if row is not None else {}


def integrity_check(path: Optional[str] = None) -> str:
    conn = _connect(path or get_settings().database_path)
    try:
        return str(conn.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        conn.close()


def reset_for_tests(path: str) -> None:
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass
