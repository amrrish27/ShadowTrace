"""Dashboard aggregates — every number comes from the database."""
from __future__ import annotations

import sqlite3
from typing import Dict

from fastapi import APIRouter, Depends

from ..db import now
from ..security.auth import AuthContext
from .deps import current_auth, get_conn

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# The overview shows a short "most urgent" list; the full list lives behind /api/v1/findings.
RECENT_FINDINGS_LIMIT = 5


@router.get("/overview")
def overview(auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)) -> Dict[str, object]:
    org = auth.org_id
    scans_by_state = {
        row["state"]: int(row["n"])
        for row in conn.execute("SELECT state, COUNT(*) AS n FROM scans WHERE org_id = ? GROUP BY state", (org,))
    }
    # Classification is per scan (`scan_endpoints`), not per endpoint: `endpoints.classification`
    # only holds whatever the most recent upsert wrote, and a scan without a baseline writes
    # "unknown" for everything. Take each endpoint's most recent *meaningful* classification so
    # the dashboard agrees with the inventory instead of showing zeros.
    endpoint_classes = conn.execute(
        """
        SELECT e.id,
               COALESCE(
                   (
                       SELECT se.classification
                       FROM scan_endpoints se JOIN scans s ON s.id = se.scan_id
                       WHERE se.endpoint_id = e.id AND se.classification <> 'unknown'
                       ORDER BY s.created_at DESC, s.id DESC
                       LIMIT 1
                   ),
                   e.classification
               ) AS classification
        FROM endpoints e
        WHERE e.org_id = ?
        """,
        (org,),
    ).fetchall()
    endpoint_totals = {
        "total": len(endpoint_classes),
        "shadow": sum(1 for row in endpoint_classes if row["classification"] == "shadow"),
        "documented": sum(1 for row in endpoint_classes if row["classification"] == "documented"),
    }
    dynamic_zombies = conn.execute(
        "SELECT COUNT(*) AS n FROM findings WHERE org_id = ? AND rule_id = 'ST-016'", (org,)
    ).fetchone()["n"]
    findings_by_severity = {severity: 0 for severity in SEVERITIES}
    for row in conn.execute(
        "SELECT severity, COUNT(*) AS n FROM findings WHERE org_id = ? GROUP BY severity", (org,)
    ):
        findings_by_severity[str(row["severity"])] = int(row["n"])
    triage_counts = {"open": 0, "accepted_risk": 0, "false_positive": 0, "fixed": 0}
    for row in conn.execute(
        """
        SELECT COALESCE(t.status, 'open') AS status, COUNT(*) AS n
        FROM findings f
        LEFT JOIN triage_records t ON t.target_id = f.target_id AND t.fingerprint = f.fingerprint
        WHERE f.org_id = ? GROUP BY COALESCE(t.status, 'open')
        """,
        (org,),
    ):
        triage_counts[str(row["status"])] = int(row["n"])
    source_breakdown = [
        {"source": row["source_type"], "endpoints": int(row["endpoints"])}
        for row in conn.execute(
            """
            SELECT s.source_type, COUNT(DISTINCT s.endpoint_id) AS endpoints
            FROM endpoint_sources s JOIN scans sc ON sc.id = s.scan_id
            WHERE sc.org_id = ? GROUP BY s.source_type ORDER BY endpoints DESC LIMIT 12
            """,
            (org,),
        )
    ]
    recent_scans = [
        dict(row)
        for row in conn.execute(
            """
            SELECT s.id, s.state, s.created_at, s.finished_at, s.counters, t.name AS target_name
            FROM scans s JOIN targets t ON t.id = s.target_id
            WHERE s.org_id = ? ORDER BY s.created_at DESC LIMIT 8
            """,
            (org,),
        )
    ]
    for scan in recent_scans:
        import json

        try:
            scan["counters"] = json.loads(scan["counters"] or "{}")
        except json.JSONDecodeError:
            scan["counters"] = {}
    timeline = [
        {"day": row["day"], "scans": int(row["n"])}
        for row in conn.execute(
            """
            SELECT date(created_at, 'unixepoch') AS day, COUNT(*) AS n
            FROM scans WHERE org_id = ? AND created_at >= ? GROUP BY day ORDER BY day
            """,
            (org, now() - 14 * 86400),
        )
    ]
    # Recent findings carry the same columns as GET /api/v1/findings so the frontend can
    # reuse its Finding type. Org-scoped on f.org_id; ordering is total so the panel is
    # stable between requests (risk desc, newest first, id as the final tie-break).
    recent_findings = [
        dict(row)
        for row in conn.execute(
            """
            SELECT f.id, f.rule_id, f.title, f.severity, f.confidence, f.status, f.risk_score,
                   f.fingerprint, f.created_at, COALESCE(t.status, 'open') AS triage_status,
                   e.method AS endpoint_method, e.path_template AS endpoint_path
            FROM findings f
            LEFT JOIN triage_records t ON t.target_id = f.target_id AND t.fingerprint = f.fingerprint
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.org_id = ?
            ORDER BY f.risk_score DESC, f.created_at DESC, f.id
            LIMIT ?
            """,
            (org, RECENT_FINDINGS_LIMIT),
        )
    ]
    targets_total = conn.execute("SELECT COUNT(*) AS n FROM targets WHERE org_id = ?", (org,)).fetchone()["n"]
    targets_approved = conn.execute(
        "SELECT COUNT(*) AS n FROM targets WHERE org_id = ? AND authorization_status = 'approved'", (org,)
    ).fetchone()["n"]
    return {
        "scans_by_state": scans_by_state,
        "endpoints": {
            "total": int(endpoint_totals["total"]),
            "shadow": int(endpoint_totals["shadow"]),
            "documented": int(endpoint_totals["documented"]),
            # A zombie is a *documented* endpoint that is no longer reachable, so it exists as
            # a finding (ST-016) rather than as an `endpoints` row.
            "zombie": int(dynamic_zombies),
        },
        "findings_by_severity": findings_by_severity,
        "triage": triage_counts,
        "recent_findings": recent_findings,
        "source_breakdown": source_breakdown,
        "recent_scans": recent_scans,
        "scan_timeline": timeline,
        "targets": {"total": int(targets_total), "approved": int(targets_approved)},
    }
