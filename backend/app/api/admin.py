"""Administration: audit trail and system limits."""
from __future__ import annotations

import json
import sqlite3
import time
from typing import Dict

from fastapi import APIRouter, Depends, Query

from ..config import get_settings
from ..security.auth import AuthContext, require_role
from .deps import current_auth, get_conn

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/audit")
def audit_log(
    limit: int = Query(default=100, ge=1, le=500),
    action: str = Query(default="", max_length=60),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "admin")
    if action:
        rows = conn.execute(
            """
            SELECT id, ts, actor_type, actor_id, action, object_type, object_id, ip, details
            FROM audit_log WHERE org_id = ? AND action = ? ORDER BY id DESC LIMIT ?
            """,
            (auth.org_id, action, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, ts, actor_type, actor_id, action, object_type, object_id, ip, details
            FROM audit_log WHERE org_id = ? ORDER BY id DESC LIMIT ?
            """,
            (auth.org_id, limit),
        ).fetchall()
    entries = []
    for row in rows:
        entry = dict(row)
        try:
            entry["details"] = json.loads(entry["details"] or "{}")
        except json.JSONDecodeError:
            entry["details"] = {}
        entries.append(entry)
    return {"entries": entries}


@router.get("/workers")
def worker_health(
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    """Live view of the scan workers that have reported a heartbeat.

    `alive` is derived, not stored: a worker is considered alive when it wrote a heartbeat
    within the lease window. This is what tells an operator whether "the scan is stuck"
    means a slow scan or a worker that is not running at all.
    """
    require_role(auth, "admin")
    settings = get_settings()
    window = max(30, int(settings.worker_lease_seconds))
    cutoff = int(time.time()) - window
    rows = conn.execute(
        """
        SELECT worker_id, hostname, pid, started_at, last_seen_at, scans_run, version
        FROM worker_heartbeats ORDER BY last_seen_at DESC LIMIT 50
        """
    ).fetchall()
    workers = []
    for row in rows:
        last_seen = int(row["last_seen_at"] or 0)
        workers.append(
            {
                "worker_id": row["worker_id"],
                "hostname": row["hostname"],
                "pid": row["pid"],
                "started_at": row["started_at"],
                "last_seen_at": last_seen,
                "scans_run": row["scans_run"],
                "version": row["version"],
                "alive": last_seen >= cutoff,
                "seconds_since_seen": max(0, int(time.time()) - last_seen),
            }
        )
    return {
        "workers": workers,
        "alive": len([worker for worker in workers if worker["alive"]]),
        "window_seconds": window,
        "scanning_enabled": settings.scanning_enabled,
    }


@router.get("/settings")
def settings_view(
    auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    require_role(auth, "admin")
    settings = get_settings()
    counts = {}
    for row in conn.execute("SELECT state, COUNT(*) AS n FROM scans WHERE org_id = ? GROUP BY state", (auth.org_id,)):
        counts[str(row["state"])] = int(row["n"])
    return {
        "scanning_enabled": settings.scanning_enabled,
        "limits": {
            "max_requests_per_scan": settings.max_requests_per_scan_hard_cap,
            "max_pages_per_scan": settings.max_pages_per_scan_hard_cap,
            "max_scan_seconds": settings.max_scan_seconds_hard_cap,
            "scan_concurrency_per_org": settings.scan_concurrency_per_org,
            "scans_per_day_per_org": settings.scans_per_day_per_org,
            "max_upload_bytes": settings.max_upload_bytes,
            "max_response_bytes": settings.max_response_bytes,
            "retention_days": settings.retention_days,
        },
        "scan_counts": counts,
        "environment": settings.env,
        "private_allowlist_configured": bool(settings.private_allowlist),
    }
