"""Endpoint inventory and findings (with provenance, evidence and triage)."""
from __future__ import annotations

import json
import sqlite3
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request

from ..db import new_id, now
from ..security import audit
from ..security.auth import AuthContext, client_ip, scoped
from ..security.errors import ApiError
from .deps import current_auth, get_conn
from .schemas import TriageRequest
from .scans import SORTABLE_ENDPOINTS, _escape_like

router = APIRouter(prefix="/api/v1", tags=["inventory"])

# Structural-only interpolation: `{where}` is assembled from fixed clause literals,
# `{column}`/`{direction}` come from SORTABLE_ENDPOINTS and a two-value branch, and
# every user-supplied value is bound as a query parameter.
ENDPOINT_PAGE_SQL = """
SELECT id, method, host, path_template, query_template, classification, validation_status, response_status,
       first_seen_at, last_seen_at, target_id,
       (SELECT GROUP_CONCAT(DISTINCT s.source_type) FROM endpoint_sources s WHERE s.endpoint_id = endpoints.id) AS source_types
FROM endpoints WHERE {where} ORDER BY {column} {direction} LIMIT ? OFFSET ?
"""

ENDPOINT_COUNT_SQL = "SELECT COUNT(*) AS n FROM endpoints WHERE "


@router.get("/endpoints")
def list_endpoints(
    target_id: Optional[str] = Query(default=None, max_length=64),
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
    clauses = ["org_id = ?"]
    params: List[object] = [auth.org_id]
    if target_id:
        clauses.append("target_id = ?")
        params.append(target_id)
    if q:
        clauses.append("path_template LIKE ? ESCAPE '\\'")
        params.append(f"%{_escape_like(q)}%")
    if classification:
        if classification not in {"shadow", "documented", "zombie", "unknown", "candidate", "discovered"}:
            raise ApiError(422, "invalid_filter", "Unknown classification.")
        clauses.append("classification = ?")
        params.append(classification)
    if validation_status:
        clauses.append("validation_status = ?")
        params.append(validation_status)
    if method:
        clauses.append("method = ?")
        params.append(method.upper())
    column = SORTABLE_ENDPOINTS.get(sort, "path_template").replace("e.", "")
    direction = "DESC" if order == "desc" else "ASC"
    where = " AND ".join(clauses)
    total = conn.execute(ENDPOINT_COUNT_SQL + where, tuple(params)).fetchone()["n"]
    rows = conn.execute(
        ENDPOINT_PAGE_SQL.format(where=where, column=column, direction=direction),
        tuple(params + [page_size, (page - 1) * page_size]),
    ).fetchall()
    return {"endpoints": [dict(row) for row in rows], "page": page, "page_size": page_size, "total": int(total)}


@router.get("/endpoints/{endpoint_id}")
def endpoint_detail(
    endpoint_id: str, auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    row = scoped(conn, "endpoints", endpoint_id, auth.org_id)
    sources = conn.execute(
        """
        SELECT source_type, source_url, location, method, snippet, extractor, created_at
        FROM endpoint_sources WHERE endpoint_id = ? ORDER BY created_at DESC LIMIT 50
        """,
        (endpoint_id,),
    ).fetchall()
    observations = conn.execute(
        """
        SELECT method, url, status_code, content_type, content_length, elapsed_ms, error, checked_at
        FROM observations WHERE endpoint_id = ? ORDER BY checked_at DESC LIMIT 20
        """,
        (endpoint_id,),
    ).fetchall()
    return {
        "endpoint": dict(row),
        "sources": [dict(source) for source in sources],
        "observations": [dict(observation) for observation in observations],
        "note": "All values originate from the scanned target and must be treated as hostile text.",
    }


@router.get("/findings")
def list_findings(
    scan_id: Optional[str] = Query(default=None, max_length=64),
    target_id: Optional[str] = Query(default=None, max_length=64),
    severity: Optional[str] = Query(default=None, max_length=20),
    confidence: Optional[str] = Query(default=None, max_length=20),
    status: Optional[str] = Query(default=None, max_length=30),
    rule: Optional[str] = Query(default=None, max_length=20),
    page: int = Query(default=1, ge=1, le=1000),
    page_size: int = Query(default=25, ge=1, le=100),
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    clauses = ["f.org_id = ?"]
    params: List[object] = [auth.org_id]
    if scan_id:
        clauses.append("f.scan_id = ?")
        params.append(scan_id)
    if target_id:
        clauses.append("f.target_id = ?")
        params.append(target_id)
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
    base = """
        FROM findings f
        LEFT JOIN triage_records t ON t.target_id = f.target_id AND t.fingerprint = f.fingerprint
    """
    total = conn.execute(f"SELECT COUNT(*) AS n {base} WHERE {where}", tuple(params)).fetchone()["n"]
    rows = conn.execute(
        f"""
        SELECT f.id, f.scan_id, f.target_id, f.rule_id, f.title, f.severity, f.confidence, f.status, f.risk_score,
               f.fingerprint, f.created_at, COALESCE(t.status, 'open') AS triage_status,
               e.method AS endpoint_method, e.path_template AS endpoint_path
        {base}
        LEFT JOIN endpoints e ON e.id = f.endpoint_id
        WHERE {where} ORDER BY f.risk_score DESC LIMIT ? OFFSET ?
        """,
        tuple(params + [page_size, (page - 1) * page_size]),
    ).fetchall()
    return {"findings": [dict(row) for row in rows], "page": page, "page_size": page_size, "total": int(total)}


@router.get("/findings/{finding_id}")
def finding_detail(
    finding_id: str, auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    row = scoped(conn, "findings", finding_id, auth.org_id)
    try:
        evidence = json.loads(row["evidence"] or "{}")
    except json.JSONDecodeError:
        evidence = {}
    triage = conn.execute(
        "SELECT status, reason, updated_at FROM triage_records WHERE target_id = ? AND fingerprint = ?",
        (row["target_id"], row["fingerprint"]),
    ).fetchone()
    history = []
    if triage is not None:
        history = [
            dict(item)
            for item in conn.execute(
                """
                SELECT h.ts, h.status, h.reason, u.email AS user_email
                FROM triage_history h
                JOIN triage_records t ON t.id = h.triage_id
                LEFT JOIN users u ON u.id = h.user_id
                WHERE t.target_id = ? AND t.fingerprint = ? ORDER BY h.id DESC LIMIT 20
                """,
                (row["target_id"], row["fingerprint"]),
            ).fetchall()
        ]
    endpoint = None
    if row["endpoint_id"]:
        endpoint_row = conn.execute(
            "SELECT id, method, host, path_template, classification, validation_status FROM endpoints WHERE id = ?",
            (row["endpoint_id"],),
        ).fetchone()
        endpoint = dict(endpoint_row) if endpoint_row else None
    return {
        "finding": {**dict(row), "evidence": evidence},
        "triage": dict(triage) if triage else {"status": "open", "reason": "", "updated_at": None},
        "triage_history": history,
        "endpoint": endpoint,
        "scoring": {
            "severity": row["severity"],
            "confidence": row["confidence"],
            "exposure": row["exposure"],
            "risk_score": row["risk_score"],
            "explanation": "risk_score = severity base + 12 x confidence weight + 4 x exposure (0-100, monotonic in severity and confidence)",
        },
    }


@router.post("/findings/{finding_id}/triage")
def triage_finding(
    finding_id: str,
    payload: TriageRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    finding = scoped(conn, "findings", finding_id, auth.org_id)
    existing = conn.execute(
        "SELECT id FROM triage_records WHERE target_id = ? AND fingerprint = ?",
        (finding["target_id"], finding["fingerprint"]),
    ).fetchone()
    timestamp = now()
    if existing is None:
        triage_id = new_id()
        conn.execute(
            """
            INSERT INTO triage_records (id, org_id, target_id, fingerprint, status, reason, updated_by, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (triage_id, auth.org_id, finding["target_id"], finding["fingerprint"], payload.status, payload.reason, auth.user_id, timestamp),
        )
    else:
        triage_id = str(existing["id"])
        conn.execute(
            "UPDATE triage_records SET status = ?, reason = ?, updated_by = ?, updated_at = ? WHERE id = ?",
            (payload.status, payload.reason, auth.user_id, timestamp, triage_id),
        )
    conn.execute(
        "INSERT INTO triage_history (triage_id, ts, status, reason, user_id) VALUES (?, ?, ?, ?, ?)",
        (triage_id, timestamp, payload.status, payload.reason, auth.user_id),
    )
    audit.record(
        conn,
        action="finding.triaged",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="finding",
        object_id=finding_id,
        ip=client_ip(request),
        details={"status": payload.status, "reason": payload.reason, "fingerprint": finding["fingerprint"]},
    )
    return {"ok": True, "status": payload.status, "fingerprint": finding["fingerprint"]}
