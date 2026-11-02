"""Append-only audit trail writer.

Every security-relevant action is recorded here.  The table rejects UPDATE and
DELETE through SQLite triggers, so history cannot be rewritten by the app.
Details are redacted before storage.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Mapping, Optional

from ..db import now
from .redaction import audit_redact


def record(
    conn: sqlite3.Connection,
    *,
    action: str,
    org_id: Optional[str] = None,
    actor_type: str = "system",
    actor_id: Optional[str] = None,
    object_type: str = "",
    object_id: str = "",
    ip: str = "",
    details: Optional[Mapping[str, Any]] = None,
    durable: bool = False,
) -> None:
    if actor_type not in {"user", "system", "worker", "anonymous"}:
        actor_type = "system"
    conn.execute(
        """
        INSERT INTO audit_log (org_id, ts, actor_type, actor_id, action, object_type, object_id, ip, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            org_id,
            now(),
            actor_type,
            (actor_id or "")[:64],
            action[:80],
            object_type[:40],
            (object_id or "")[:64],
            (ip or "")[:64],
            __import__("json").dumps(audit_redact(details or {}), separators=(",", ":"))[:2000],
        ),
    )
    if durable:
        # Authentication failures abort the request, which would otherwise roll the
        # record back with the rest of the transaction. Security events must survive.
        conn.commit()
