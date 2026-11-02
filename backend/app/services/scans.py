"""Scan lifecycle service: state machine, quotas, idempotency, comparison."""
from __future__ import annotations

import json
import sqlite3
from typing import Dict, List, Optional, Sequence, Tuple

from ..config import Settings
from ..db import new_id, now
from ..security.audit import record as audit_record
from ..security.errors import ApiError

# `assignments` holds literal "column = ?" fragments built in transition(); values are bound.
UPDATE_SCAN_SQL = "UPDATE scans SET {assignments} WHERE id = ? AND org_id = ?"

STATES = {"queued", "running", "cancelling", "completed", "failed", "cancelled", "timed_out"}
TERMINAL = {"completed", "failed", "cancelled", "timed_out"}
ACTIVE = {"queued", "running", "cancelling"}

TRANSITIONS: Dict[str, set] = {
    "queued": {"running", "cancelled", "failed"},
    "running": {"cancelling", "completed", "failed", "cancelled", "timed_out"},
    "cancelling": {"cancelled", "failed", "timed_out"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
    "timed_out": set(),
}


class InvalidTransition(ApiError):
    def __init__(self, current: str, target_state: str) -> None:
        super().__init__(409, "invalid_transition", f"Cannot move a scan from {current} to {target_state}.")


def transition(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    org_id: str,
    from_states: Sequence[str],
    to_state: str,
    partial: Optional[bool] = None,
    error_category: Optional[str] = None,
    error_message: Optional[str] = None,
) -> None:
    row = conn.execute("SELECT state FROM scans WHERE id = ? AND org_id = ?", (scan_id, org_id)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "The requested resource was not found.")
    current = str(row["state"])
    if current not in from_states:
        raise InvalidTransition(current, to_state)
    if to_state not in TRANSITIONS.get(current, set()):
        raise InvalidTransition(current, to_state)
    timestamp = now()
    fields = ["state = ?", "updated_at = ?"]
    params: List[object] = [to_state, timestamp]
    if to_state == "running":
        fields.append("started_at = COALESCE(started_at, ?)")
        params.append(timestamp)
    if to_state in TERMINAL:
        fields.append("finished_at = ?")
        params.append(timestamp)
    if partial is not None:
        fields.append("partial = ?")
        params.append(1 if partial else 0)
    if error_category is not None:
        fields.append("error_category = ?")
        params.append(error_category)
    if error_message is not None:
        fields.append("error_message = ?")
        params.append(error_message[:500])
    params.extend([scan_id, org_id])
    # `fields` holds literal "column = ?" fragments built above; all values are bound.
    conn.execute(UPDATE_SCAN_SQL.format(assignments=", ".join(fields)), tuple(params))


def check_quotas(conn: sqlite3.Connection, org_id: str, settings: Settings) -> None:
    active = conn.execute(
        "SELECT COUNT(*) AS n FROM scans WHERE org_id = ? AND state IN ('queued','running','cancelling')",
        (org_id,),
    ).fetchone()["n"]
    if int(active) >= settings.scan_concurrency_per_org:
        raise ApiError(429, "quota_exceeded", "The concurrent-scan quota for this organization is in use.")
    day_start = now() - 86400
    today = conn.execute(
        "SELECT COUNT(*) AS n FROM scans WHERE org_id = ? AND created_at >= ?", (org_id, day_start)
    ).fetchone()["n"]
    if int(today) >= settings.scans_per_day_per_org:
        raise ApiError(429, "quota_exceeded", "The daily scan quota for this organization is exhausted.")


def create_scan(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    user_id: str,
    target_row: sqlite3.Row,
    idempotency_key: str,
    config: Dict[str, object],
    baseline_id: Optional[str],
    settings: Settings,
) -> Tuple[sqlite3.Row, bool]:
    existing = conn.execute(
        "SELECT * FROM scans WHERE org_id = ? AND idempotency_key = ?", (org_id, idempotency_key)
    ).fetchone()
    if existing is not None:
        return existing, False
    if str(target_row["authorization_status"]) != "approved":
        raise ApiError(
            409,
            "target_not_authorized",
            "Scans require an approved authorization for the target.",
        )
    check_quotas(conn, org_id, settings)
    scan_id = new_id()
    timestamp = now()
    conn.execute(
        """
        INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                           baseline_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'queued', ?, '{}', ?, ?, ?, ?)
        """,
        (
            scan_id,
            org_id,
            target_row["id"],
            user_id,
            json.dumps(config, separators=(",", ":")),
            idempotency_key[:64],
            baseline_id,
            timestamp,
            timestamp,
        ),
    )
    audit_record(
        conn,
        action="scan.created",
        org_id=org_id,
        actor_type="user",
        actor_id=user_id,
        object_type="scan",
        object_id=scan_id,
        details={"target_id": target_row["id"], "config": {k: v for k, v in config.items() if k != "attestation"}},
    )
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return row, True


def request_cancel(conn: sqlite3.Connection, *, scan_id: str, org_id: str, user_id: str) -> str:
    row = conn.execute("SELECT state FROM scans WHERE id = ? AND org_id = ?", (scan_id, org_id)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "The requested resource was not found.")
    current = str(row["state"])
    if current in TERMINAL:
        return current
    conn.execute("UPDATE scans SET cancel_requested = 1, updated_at = ? WHERE id = ?", (now(), scan_id))
    if current == "queued":
        transition(conn, scan_id=scan_id, org_id=org_id, from_states=["queued"], to_state="cancelled", partial=True)
        audit_record(conn, action="scan.cancelled", org_id=org_id, actor_type="user", actor_id=user_id, object_type="scan", object_id=scan_id)
        return "cancelled"
    if current == "running":
        transition(conn, scan_id=scan_id, org_id=org_id, from_states=["running"], to_state="cancelling")
    return "cancelling"


def delete_scan(conn: sqlite3.Connection, *, scan_id: str, org_id: str, user_id: str, is_admin: bool) -> None:
    row = conn.execute("SELECT state FROM scans WHERE id = ? AND org_id = ?", (scan_id, org_id)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "The requested resource was not found.")
    if str(row["state"]) in ACTIVE:
        raise ApiError(409, "conflict", "Cancel the scan before deleting it.")
    if not is_admin:
        raise ApiError(403, "forbidden", "Only administrators can delete scans.")
    conn.execute("UPDATE endpoints SET first_seen_scan = NULL WHERE first_seen_scan = ? AND org_id = ?", (scan_id, org_id))
    conn.execute("UPDATE endpoints SET last_seen_scan = NULL WHERE last_seen_scan = ? AND org_id = ?", (scan_id, org_id))
    conn.execute("DELETE FROM endpoints WHERE id NOT IN (SELECT DISTINCT endpoint_id FROM scan_endpoints) AND target_id NOT IN (SELECT target_id FROM baselines)")
    conn.execute("DELETE FROM scans WHERE id = ? AND org_id = ?", (scan_id, org_id))
    audit_record(conn, action="scan.deleted", org_id=org_id, actor_type="user", actor_id=user_id, object_type="scan", object_id=scan_id)


def previous_completed_scan(conn: sqlite3.Connection, *, target_id: str, org_id: str, before_created_at: int) -> Optional[sqlite3.Row]:
    return conn.execute(
        """
        SELECT * FROM scans
        WHERE target_id = ? AND org_id = ? AND state IN ('completed','timed_out')
          AND created_at < ?
        ORDER BY created_at DESC LIMIT 1
        """,
        (target_id, org_id, before_created_at),
    ).fetchone()


def scan_endpoint_map(conn: sqlite3.Connection, scan_id: str) -> Dict[str, Tuple[str, str, Optional[int]]]:
    rows = conn.execute(
        """
        SELECT e.fingerprint, e.method, e.path_template,
               COALESCE(se.response_status, e.response_status) AS response_status
        FROM scan_endpoints se JOIN endpoints e ON e.id = se.endpoint_id
        WHERE se.scan_id = ?
        """,
        (scan_id,),
    ).fetchall()
    return {
        str(row["fingerprint"]): (str(row["method"]), str(row["path_template"]), row["response_status"]) for row in rows
    }


def compare_with_previous(conn: sqlite3.Connection, scan: sqlite3.Row, org_id: str) -> Dict[str, object]:
    previous = previous_completed_scan(
        conn, target_id=str(scan["target_id"]), org_id=org_id, before_created_at=int(scan["created_at"])
    )
    if previous is None:
        return {"previous_scan_id": None, "new": [], "removed": [], "changed": [], "findings_new": [], "findings_resolved": []}
    current_map = scan_endpoint_map(conn, str(scan["id"]))
    previous_map = scan_endpoint_map(conn, str(previous["id"]))
    new = [dict(fingerprint=k, method=v[0], path=v[1], status=v[2]) for k, v in current_map.items() if k not in previous_map]
    removed = [dict(fingerprint=k, method=v[0], path=v[1], status=v[2]) for k, v in previous_map.items() if k not in current_map]
    changed = [
        dict(fingerprint=k, method=v[0], path=v[1], status=v[2], previous_status=previous_map[k][2])
        for k, v in current_map.items()
        if k in previous_map and previous_map[k][2] != v[2]
    ]
    current_findings = {
        row["fingerprint"] for row in conn.execute("SELECT fingerprint FROM findings WHERE scan_id = ?", (scan["id"],))
    }
    previous_findings = {
        row["fingerprint"] for row in conn.execute("SELECT fingerprint FROM findings WHERE scan_id = ?", (previous["id"],))
    }
    return {
        "previous_scan_id": previous["id"],
        "new": new,
        "removed": removed,
        "changed": changed,
        "findings_new": sorted(current_findings - previous_findings),
        "findings_resolved": sorted(previous_findings - current_findings),
    }


def expire_stale_scan(conn: sqlite3.Connection, scan_id: str, settings: Settings, reason: str) -> None:
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None or str(row["state"]) not in ACTIVE:
        return
    conn.execute(
        """
        UPDATE scans SET state = 'failed', partial = 1, error_category = 'internal', error_message = ?,
                         finished_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (reason[:500], now(), now(), scan_id),
    )
