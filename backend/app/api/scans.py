"""Scan creation, lifecycle, inventory/findings views, comparison and exports."""
from __future__ import annotations

import json
import sqlite3
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Header, Query, Request, Response

from ..config import get_settings
from ..db import new_id, now
from ..security import audit
from ..security.auth import AuthContext, client_ip, require_role
from ..security.errors import ApiError
from ..services import reports, scans as scan_service
from .deps import current_auth, get_conn, rate_limit
from .schemas import ScanCreateRequest

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

# Structural-only interpolation in the queries below: `{where}` is assembled from fixed
# clause literals, `{column}`/`{direction}` come from SORTABLE_ENDPOINTS and a two-value
# branch, and every user-supplied value is bound as a query parameter.
SCAN_COUNT_SQL = "SELECT COUNT(*) AS n FROM scans s WHERE "

SCAN_ENDPOINT_COUNT_SQL = (
    "SELECT COUNT(*) AS n FROM scan_endpoints se JOIN endpoints e ON e.id = se.endpoint_id WHERE "
)

SCAN_LIST_SQL = """
SELECT s.*, t.name AS target_name FROM scans s JOIN targets t ON t.id = s.target_id
WHERE {where} ORDER BY s.created_at DESC LIMIT ? OFFSET ?
"""

SCAN_ENDPOINT_PAGE_SQL = """
SELECT e.id, e.method, e.host, e.path_template, e.query_template, e.classification, e.validation_status,
       e.response_status, e.first_seen_at, e.last_seen_at,
       (SELECT GROUP_CONCAT(DISTINCT s.source_type) FROM endpoint_sources s WHERE s.endpoint_id = e.id) AS source_types
FROM scan_endpoints se JOIN endpoints e ON e.id = se.endpoint_id
WHERE {where} ORDER BY {column} {direction} LIMIT ? OFFSET ?
"""

FINDING_COUNT_SQL = """
SELECT COUNT(*) AS n FROM findings f
LEFT JOIN triage_records t ON t.target_id = f.target_id AND t.fingerprint = f.fingerprint
WHERE {where}
"""

FINDING_PAGE_SQL = """
SELECT f.id, f.rule_id, f.title, f.severity, f.confidence, f.status, f.risk_score, f.fingerprint,
       f.created_at, COALESCE(t.status, 'open') AS triage_status,
       e.method AS endpoint_method, e.path_template AS endpoint_path
FROM findings f
LEFT JOIN triage_records t ON t.target_id = f.target_id AND t.fingerprint = f.fingerprint
LEFT JOIN endpoints e ON e.id = f.endpoint_id
WHERE {where}
ORDER BY f.risk_score DESC, f.severity LIMIT ? OFFSET ?
"""

SORTABLE_ENDPOINTS = {
    "path": "e.path_template",
    "method": "e.method",
    "classification": "e.classification",
    "validation": "e.validation_status",
    "status": "e.response_status",
    "last_seen": "e.last_seen_at",
    "first_seen": "e.first_seen_at",
}

EXPORT_FORMATS = {
    "json": ("application/json; charset=utf-8", "json", reports.render_json, "report.json"),
    "csv_inventory": ("text/csv; charset=utf-8", "csv", reports.render_csv_inventory, "inventory.csv"),
    "csv_findings": ("text/csv; charset=utf-8", "csv", reports.render_csv_findings, "findings.csv"),
    "markdown": ("text/markdown; charset=utf-8", "md", reports.render_markdown, "report.md"),
    "html": ("text/html; charset=utf-8", "html", reports.render_html, "report.html"),
    "openapi_stub": ("application/json; charset=utf-8", "json", reports.render_openapi_stub, "openapi-stub.json"),
}


PHASES = ("queued", "discover", "normalize", "reconcile", "validate", "analyze", "done")
RETRYABLE_STATES = ("failed", "cancelled", "timed_out")


def _scan_payload(row: sqlite3.Row, target_name: str = "") -> Dict[str, object]:
    counters = json.loads(row["counters"] or "{}")
    default_active_phase = "discover" if row["state"] == "running" else ("queued" if row["state"] == "queued" else "done")
    raw_phase = str(counters.get("phase") or default_active_phase)
    # If the scan is still running or queued, it cannot be "done"
    if row["state"] in ("running", "queued", "cancelling") and raw_phase == "done":
        phase = default_active_phase
    elif row["state"] in ("timed_out", "failed", "cancelled") and raw_phase == "queued":
        phase = "discover"
    else:
        phase = raw_phase if raw_phase in PHASES else "done"
    config = json.loads(row["config"] or "{}")
    return {
        "id": row["id"],
        "target_id": row["target_id"],
        "target_name": target_name,
        "state": row["state"],
        "partial": bool(row["partial"]),
        "error_category": row["error_category"],
        "error_message": row["error_message"],
        "counters": counters,
        "config": config,
        "phase": phase,
        "outcome": str(counters.get("outcome") or ""),
        "profile": str(config.get("profile") or "standard"),
        "retryable": str(row["state"]) in RETRYABLE_STATES,
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "cancel_requested": bool(row["cancel_requested"]),
        "created_by": row["created_by"],
    }


def _scoped_scan(conn: sqlite3.Connection, scan_id: str, org_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM scans WHERE id = ? AND org_id = ?", (scan_id, org_id)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "The requested resource was not found.")
    return row


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("")
def list_scans(
    state: Optional[str] = Query(default=None, max_length=20),
    target_id: Optional[str] = Query(default=None, max_length=64),
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=25, ge=1, le=100),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    clauses = ["s.org_id = ?"]
    params: List[object] = [auth.org_id]
    if state:
        if state not in scan_service.STATES:
            raise ApiError(422, "invalid_filter", "Unknown scan state.")
        clauses.append("s.state = ?")
        params.append(state)
    if target_id:
        clauses.append("s.target_id = ?")
        params.append(target_id)
    where = " AND ".join(clauses)
    total = conn.execute(SCAN_COUNT_SQL + where, tuple(params)).fetchone()["n"]
    rows = conn.execute(
        SCAN_LIST_SQL.format(where=where),
        tuple(params + [page_size, (page - 1) * page_size]),
    ).fetchall()
    return {
        "scans": [_scan_payload(row, row["target_name"]) for row in rows],
        "page": page,
        "page_size": page_size,
        "total": int(total),
    }


@router.post("", status_code=201)
def create_scan(
    payload: ScanCreateRequest,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=8, max_length=64),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
    _limit=Depends(rate_limit("scan_create")),
) -> Dict[str, object]:
    require_role(auth, "analyst")
    if not get_settings().scanning_enabled:
        raise ApiError(503, "scanning_disabled", "Scanning is disabled by the operator.")
    target = conn.execute(
        "SELECT * FROM targets WHERE id = ? AND org_id = ?", (payload.target_id, auth.org_id)
    ).fetchone()
    if target is None:
        raise ApiError(404, "not_found", "The requested target was not found.")
    baseline_id = payload.baseline_id
    if baseline_id:
        baseline = conn.execute(
            "SELECT id FROM baselines WHERE id = ? AND target_id = ? AND org_id = ?",
            (baseline_id, payload.target_id, auth.org_id),
        ).fetchone()
        if baseline is None:
            raise ApiError(422, "invalid_baseline", "The baseline does not belong to this target.")
    har_id = payload.har_import_id
    if har_id:
        har_row = conn.execute(
            "SELECT id FROM har_imports WHERE id = ? AND target_id = ? AND org_id = ?",
            (har_id, payload.target_id, auth.org_id),
        ).fetchone()
        if har_row is None:
            raise ApiError(422, "invalid_har", "The HAR import does not belong to this target.")
    config = {
        "include_crawler": payload.include_crawler,
        "include_source_maps": payload.include_source_maps,
        "include_specs": payload.include_specs,
        "active_validation": payload.active_validation,
        "max_pages": payload.max_pages,
        "max_scripts": payload.max_scripts,
        "max_requests": payload.max_requests,
        "max_seconds": payload.max_seconds,
        "seeds": payload.seeds,
        "attestation": payload.attestation,
        "har_import_id": har_id,
    }
    row, created = scan_service.create_scan(
        conn,
        org_id=auth.org_id,
        user_id=auth.user_id,
        target_row=target,
        idempotency_key=idempotency_key,
        config=config,
        baseline_id=baseline_id,
        settings=get_settings(),
    )
    return {"scan": _scan_payload(row, str(target["name"])), "created": created}


@router.get("/{scan_id}")
def get_scan(
    scan_id: str, auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    row = _scoped_scan(conn, scan_id, auth.org_id)
    target = conn.execute("SELECT name FROM targets WHERE id = ?", (row["target_id"],)).fetchone()
    return {"scan": _scan_payload(row, target["name"] if target else "")}


@router.post("/{scan_id}/start")
def start_scan(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "analyst")
    row = _scoped_scan(conn, scan_id, auth.org_id)
    if str(row["state"]) in scan_service.TERMINAL:
        raise ApiError(409, "invalid_transition", "This scan has already finished.")
    if not get_settings().scanning_enabled:
        raise ApiError(503, "scanning_disabled", "Scanning is disabled by the operator.")
    audit.record(
        conn,
        action="scan.start_requested",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="scan",
        object_id=scan_id,
        ip=client_ip(request),
    )
    target = conn.execute("SELECT name FROM targets WHERE id = ?", (row["target_id"],)).fetchone()
    return {"scan": _scan_payload(row, target["name"] if target else "")}


@router.post("/{scan_id}/cancel")
def cancel_scan(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "analyst")
    state = scan_service.request_cancel(conn, scan_id=scan_id, org_id=auth.org_id, user_id=auth.user_id)
    audit.record(
        conn,
        action="scan.cancel_requested",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="scan",
        object_id=scan_id,
        ip=client_ip(request),
        details={"state": state},
    )
    row = _scoped_scan(conn, scan_id, auth.org_id)
    return {"state": state, "scan": _scan_payload(row)}


@router.post("/{scan_id}/retry", status_code=201)
def retry_scan(
    scan_id: str,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=8, max_length=64),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
    _limit=Depends(rate_limit("scan_create")),
) -> Dict[str, object]:
    """Queue a fresh scan with the same target and configuration as an eligible scan.

    Only finished-and-unsuccessful scans can be retried: re-running a completed scan is a
    new decision (with its own attestation and quota), not a retry. The original scan is
    left untouched, so the history shows what failed.
    """
    require_role(auth, "analyst")
    if not get_settings().scanning_enabled:
        raise ApiError(503, "scanning_disabled", "Scanning is disabled by the operator.")
    row = _scoped_scan(conn, scan_id, auth.org_id)
    if str(row["state"]) not in RETRYABLE_STATES:
        raise ApiError(
            409,
            "invalid_transition",
            f"Only failed, cancelled or timed-out scans can be retried (this scan is {row['state']}).",
        )
    target = conn.execute(
        "SELECT * FROM targets WHERE id = ? AND org_id = ?", (row["target_id"], auth.org_id)
    ).fetchone()
    if target is None:
        raise ApiError(409, "target_missing", "The target no longer exists.")
    config = json.loads(row["config"] or "{}")
    new_row, created = scan_service.create_scan(
        conn,
        org_id=auth.org_id,
        user_id=auth.user_id,
        target_row=target,
        idempotency_key=idempotency_key,
        config=config,
        baseline_id=row["baseline_id"],
        settings=get_settings(),
    )
    audit.record(
        conn,
        action="scan.retried",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="scan",
        object_id=str(new_row["id"]),
        ip=client_ip(request),
        details={"retry_of": scan_id, "state": row["state"]},
    )
    return {"scan": _scan_payload(new_row, str(target["name"])), "retry_of": scan_id, "created": created}


@router.delete("/{scan_id}")
def delete_scan(
    scan_id: str,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    scan_service.delete_scan(conn, scan_id=scan_id, org_id=auth.org_id, user_id=auth.user_id, is_admin=auth.is_admin)
    return {"ok": True}


@router.get("/{scan_id}/events")
def scan_events(
    scan_id: str,
    after: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=500),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    _scoped_scan(conn, scan_id, auth.org_id)
    rows = conn.execute(
        "SELECT id, ts, level, kind, message FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id LIMIT ?",
        (scan_id, after, limit),
    ).fetchall()
    return {"events": [dict(row) for row in rows]}


@router.get("/{scan_id}/endpoints")
def scan_endpoints(
    scan_id: str,
    q: Optional[str] = Query(default=None, max_length=200),
    classification: Optional[str] = Query(default=None, max_length=20),
    validation_status: Optional[str] = Query(default=None, max_length=30),
    method: Optional[str] = Query(default=None, max_length=10),
    sort: str = Query(default="path", max_length=20),
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
    page: int = Query(default=1, ge=1, le=10_000),
    page_size: int = Query(default=25, ge=1, le=100),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    _scoped_scan(conn, scan_id, auth.org_id)
    clauses = ["se.scan_id = ?"]
    params: List[object] = [scan_id]
    if q:
        clauses.append("e.path_template LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(q)}%")
    if classification:
        if classification not in {"shadow", "documented", "zombie", "unknown", "candidate", "discovered"}:
            raise ApiError(422, "invalid_filter", "Unknown classification.")
        clauses.append("e.classification = ?")
        params.append(classification)
    if validation_status:
        clauses.append("e.validation_status = ?")
        params.append(validation_status)
    if method:
        clauses.append("e.method = ?")
        params.append(method.upper())
    column = SORTABLE_ENDPOINTS.get(sort, "e.path_template")
    direction = "DESC" if order == "desc" else "ASC"
    where = " AND ".join(clauses)
    total = conn.execute(SCAN_ENDPOINT_COUNT_SQL + where, tuple(params)).fetchone()["n"]
    rows = conn.execute(
        SCAN_ENDPOINT_PAGE_SQL.format(where=where, column=column, direction=direction),
        tuple(params + [page_size, (page - 1) * page_size]),
    ).fetchall()
    return {
        "endpoints": [dict(row) for row in rows],
        "page": page,
        "page_size": page_size,
        "total": int(total),
        "sort": sort,
        "order": order,
    }


@router.get("/{scan_id}/findings")
def scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(default=None, max_length=20),
    confidence: Optional[str] = Query(default=None, max_length=20),
    status: Optional[str] = Query(default=None, max_length=30),
    rule: Optional[str] = Query(default=None, max_length=20),
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=25, ge=1, le=100),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    _scoped_scan(conn, scan_id, auth.org_id)
    clauses = ["f.scan_id = ?"]
    params: List[object] = [scan_id]
    if severity:
        clauses.append("f.severity = ?")
        params.append(severity)
    if confidence:
        clauses.append("f.confidence = ?")
        params.append(confidence)
    if rule:
        clauses.append("f.rule_id = ?")
        params.append(rule)
    if status:
        if status == "open":
            clauses.append("(t.status IS NULL OR t.status = 'open')")
        else:
            clauses.append("t.status = ?")
            params.append(status)
    where = " AND ".join(clauses)
    total = conn.execute(FINDING_COUNT_SQL.format(where=where), tuple(params)).fetchone()["n"]
    rows = conn.execute(
        FINDING_PAGE_SQL.format(where=where),
        tuple(params + [page_size, (page - 1) * page_size]),
    ).fetchall()
    return {"findings": [dict(row) for row in rows], "page": page, "page_size": page_size, "total": int(total)}


@router.get("/{scan_id}/comparison")
def scan_comparison(
    scan_id: str, auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    row = _scoped_scan(conn, scan_id, auth.org_id)
    return scan_service.compare_with_previous(conn, row, auth.org_id)


@router.get("/{scan_id}/export")
def export_scan(
    scan_id: str,
    format: str = Query(default="json", max_length=20),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
    request: Request = None,  # type: ignore[assignment]
    _limit=Depends(rate_limit("export")),
) -> Response:
    if format not in EXPORT_FORMATS:
        raise ApiError(422, "invalid_format", "Unknown export format.")
    _scoped_scan(conn, scan_id, auth.org_id)
    data = reports.load_report_data(conn, scan_id=scan_id, org_id=auth.org_id)
    content_type, extension, renderer, filename = EXPORT_FORMATS[format]
    body = renderer(data)
    conn.execute(
        "INSERT INTO report_exports (id, org_id, scan_id, format, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (new_id(), auth.org_id, scan_id, format, auth.user_id, now()),
    )
    audit.record(
        conn,
        action="report.exported",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="scan",
        object_id=scan_id,
        ip=client_ip(request) if request is not None else "",
        details={"format": format, "filename": filename},
    )
    scanned = scan_id[:8]
    return Response(
        content=body,
        media_type=content_type,
        headers=reports.attachment_headers(f"shadowtrace-{scanned}-{filename}", content_type.split(";")[0]),
    )
