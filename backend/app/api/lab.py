"""Training-lab control surface.

Everything here is a *controlled* operation on the bundled ShadowLab:

* ``GET  /api/v1/lab/status``     — supervisor + health + the lab target, read-only
* ``GET  /api/v1/lab/scenarios``  — the scenario catalogue (from lab/app/scenarios.json)
* ``GET  /api/v1/lab/mappings``   — scenario → expected scanner rules
* ``POST /api/v1/lab/start``      — admin only, audited
* ``POST /api/v1/lab/stop``       — admin only, audited
* ``POST /api/v1/lab/restart``    — admin only, audited
* ``POST /api/v1/lab/reset``      — admin only, audited (restarts the in-memory demo state)
* ``POST /api/v1/lab/target``     — create/adopt the approved lab target (admin only)
* ``POST /api/v1/lab/scan``       — queue a scan of the lab target (analyst+), audited

There is no endpoint that accepts a command, a path or an arbitrary URL: the supervisor
runs one fixed argv (``app/services/lab.py``) and the scan endpoint reuses the ordinary
scan-creation path, so every existing quota, policy and audit rule still applies.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request

from ..config import get_settings
from ..db import new_id, now
from ..security import audit
from ..security.auth import AuthContext, client_ip, require_role
from ..security.errors import ApiError
from ..security.labgrant import grant_for_target
from ..services import scans as scan_service
from ..services.lab import LabUnavailable, get_supervisor, scenario_catalogue
from .deps import current_auth, get_conn
from .schemas import LabScanRequest, LabTargetRequest

router = APIRouter(prefix="/api/v1/lab", tags=["lab"])

LAB_TARGET_NAME = "ShadowLab (bundled training target)"


def _ensure_enabled() -> None:
    settings = get_settings()
    if not settings.lab_enabled:
        raise ApiError(
            404,
            "not_found",
            "The training lab is disabled on this deployment (ST_LAB_ENABLED=false).",
        )


def _lab_target(conn: sqlite3.Connection, org_id: str) -> Optional[sqlite3.Row]:
    settings = get_settings()
    return conn.execute(
        "SELECT * FROM targets WHERE org_id = ? AND host = ? AND ports LIKE ?",
        (org_id, settings.lab_host, f"%{settings.lab_port}%"),
    ).fetchone()


def _target_payload(row: Optional[sqlite3.Row]) -> Optional[Dict[str, object]]:
    if row is None:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
        "base_url": row["base_url"],
        "host": row["host"],
        "authorization_status": row["authorization_status"],
        "authorization_mode": row["authorization_mode"],
        "lab_granted": bool(row["lab_grant"]),
        "scan_ready": str(row["authorization_status"]) == "approved",
    }


@router.get("/status")
def lab_status(
    auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    """Status is readable by every signed-in role: it changes nothing."""
    settings = get_settings()
    status = get_supervisor().status()
    status["scenarios"] = len(scenario_catalogue())
    status["target"] = _target_payload(_lab_target(conn, auth.org_id))
    allowlist = {(host, int(port)) for host, port in settings.private_allowlist}
    status["allowlisted"] = (settings.lab_host, settings.lab_port) in allowlist
    status["scanning_enabled"] = settings.scanning_enabled
    if not status["allowlisted"] and settings.lab_enabled:
        status["hint"] = (
            f"Add {settings.lab_host}:{settings.lab_port} to ST_PRIVATE_ALLOWLIST in both the "
            "API and worker environment, then restart both processes."
        )
    return {"lab": status}


@router.get("/scenarios")
def lab_scenarios(_auth: AuthContext = Depends(current_auth)) -> Dict[str, object]:
    _ensure_enabled()
    return {"scenarios": scenario_catalogue()}


@router.get("/mappings")
def lab_mappings(_auth: AuthContext = Depends(current_auth)) -> Dict[str, object]:
    """Scenario → expected-rule matrix, for the Lab page and the docs."""
    _ensure_enabled()
    scenarios = scenario_catalogue()
    mappings: List[Dict[str, Any]] = []
    wanted = sorted({rule for item in scenarios for rule in (item.get("expected_rules") or [])})
    for rule_id in wanted:
        hit = conn_free_rule(rule_id)
        mappings.append(
            {
                "rule_id": rule_id,
                "title": hit.get("title", ""),
                "severity": hit.get("severity", ""),
                "status": hit.get("status", ""),
                "scenarios": [item["id"] for item in scenarios if rule_id in (item.get("expected_rules") or [])],
            }
        )
    return {"rules": mappings, "scenarios": len(scenarios)}


def conn_free_rule(rule_id: str) -> Dict[str, str]:
    """Rule metadata without a DB handle (the rule registry is static)."""
    from ..engine.rules import rules_documentation

    for row in rules_documentation():
        if row["id"] == rule_id:
            return dict(row)
    return {}


def _require_admin(auth: AuthContext) -> None:
    require_role(auth, "admin")


def _audit(conn: sqlite3.Connection, auth: AuthContext, request: Request, action: str, **details) -> None:
    audit.record(
        conn,
        action=action,
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="lab",
        object_id="shadowlab",
        ip=client_ip(request),
        details=details or None,
    )


@router.post("/start")
def lab_start(
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    _ensure_enabled()
    _require_admin(auth)
    try:
        status = get_supervisor().start()
    except LabUnavailable as exc:
        _audit(conn, auth, request, "lab.start_failed", error=str(exc)[:200])
        raise ApiError(503, "lab_unavailable", str(exc)) from exc
    _audit(conn, auth, request, "lab.started", url=status["url"])
    return {"lab": status}


@router.post("/stop")
def lab_stop(
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    _ensure_enabled()
    _require_admin(auth)
    try:
        status = get_supervisor().stop()
    except LabUnavailable as exc:
        raise ApiError(409, "lab_unavailable", str(exc)) from exc
    _audit(conn, auth, request, "lab.stopped")
    return {"lab": status}


@router.post("/restart")
def lab_restart(
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    _ensure_enabled()
    _require_admin(auth)
    try:
        status = get_supervisor().restart()
    except LabUnavailable as exc:
        _audit(conn, auth, request, "lab.restart_failed", error=str(exc)[:200])
        raise ApiError(503, "lab_unavailable", str(exc)) from exc
    _audit(conn, auth, request, "lab.restarted", url=status["url"])
    return {"lab": status}


@router.post("/reset")
def lab_reset(
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    """Reset the lab to its initial state.

    ShadowLab keeps no persistent state: every record is a constant in the process. A
    restart is therefore a complete reset, and it is the only operation performed — no
    database of the *application* is touched.
    """
    _ensure_enabled()
    _require_admin(auth)
    try:
        status = get_supervisor().restart()
    except LabUnavailable as exc:
        raise ApiError(503, "lab_unavailable", str(exc)) from exc
    _audit(conn, auth, request, "lab.reset", url=status["url"])
    return {"lab": status, "reset": True}


@router.post("/target")
def lab_target(
    request: Request,
    payload: Optional[LabTargetRequest] = None,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    """Create (or return) the approved lab target for this organization.

    This is a thin wrapper over the ordinary target rules: the operator allow-list must
    contain the lab `host:port` or the request is refused exactly as a manual target
    creation would be. It exists so the UI does not have to know the deployment's port.
    """
    _ensure_enabled()
    require_role(auth, "analyst")
    settings = get_settings()
    payload = payload or LabTargetRequest()
    existing = _lab_target(conn, auth.org_id)
    if existing is not None:
        return {"target": _target_payload(existing), "created": False}
    pair = (settings.lab_host, settings.lab_port)
    allowed = {(host, int(port)) for host, port in settings.private_allowlist}
    if pair not in allowed:
        raise ApiError(
            422,
            "invalid_target",
            f"Add {settings.lab_host}:{settings.lab_port} to ST_PRIVATE_ALLOWLIST in the API and "
            "worker environment, then restart both processes.",
        )
    target_id = new_id()
    timestamp = now()
    base_url = f"http://{settings.lab_host}:{settings.lab_port}"
    grant = grant_for_target(
        conn,
        target_id=target_id,
        scheme="http",
        host=settings.lab_host,
        port=settings.lab_port,
        secret=settings.secret_key,
        allowlist=settings.private_allowlist,
    )
    conn.execute(
        """
        INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes, authorization_mode,
                             authorization_status, attestation, justification, verification_token, verified_at,
                             verified_by, created_by, created_at, limits, lab_grant, lab_grant_at)
        VALUES (?, ?, ?, ?, ?, 'http', ?, '[]', 'lab_allowlist', 'approved', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_id,
            auth.org_id,
            payload.name or LAB_TARGET_NAME,
            base_url,
            settings.lab_host,
            json.dumps([settings.lab_port]),
            payload.attestation
            or "Bundled training lab; the operator allow-listed this host:port explicitly.",
            "Bundled ShadowLab training target (synthetic, loopback only).",
            new_id(),
            timestamp,
            auth.user_id,
            auth.user_id,
            timestamp,
            json.dumps({"max_requests": 300, "max_pages": 12, "max_seconds": 300}),
            grant,
            timestamp if grant else None,
        ),
    )
    audit.record(
        conn,
        action="lab.target_created",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="target",
        object_id=target_id,
        ip=client_ip(request),
        details={"host": settings.lab_host, "port": settings.lab_port, "lab_granted": bool(grant)},
    )
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return {"target": _target_payload(row), "created": True}


@router.post("/scan")
def lab_scan(
    payload: LabScanRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    """Queue a scan of the lab target using the ordinary, audited scan path."""
    _ensure_enabled()
    require_role(auth, "analyst")
    settings = get_settings()
    if not settings.scanning_enabled:
        raise ApiError(503, "scanning_disabled", "Scanning is disabled by the operator.")
    row = _lab_target(conn, auth.org_id)
    if row is None:
        raise ApiError(409, "lab_target_missing", "Register the lab target first (POST /api/v1/lab/target).")
    if str(row["authorization_status"]) != "approved":
        raise ApiError(409, "target_not_approved", "The lab target is not approved.")
    config = {
        "include_crawler": True,
        "include_source_maps": True,
        "include_specs": True,
        "active_validation": True,
        "max_pages": payload.max_pages,
        "max_scripts": payload.max_scripts,
        "max_requests": payload.max_requests,
        "max_seconds": payload.max_seconds,
        # Seed the training pages so the scan demonstrably covers the scenario catalogue.
        "seeds": [f"{str(row['base_url']).rstrip('/')}/lab"],
        "attestation": payload.attestation
        or "Scan of the bundled ShadowLab training target (synthetic, loopback only).",
        "profile": payload.profile,
    }
    row_scan, created = scan_service.create_scan(
        conn,
        org_id=auth.org_id,
        user_id=auth.user_id,
        target_row=row,
        idempotency_key=payload.idempotency_key,
        config=config,
        baseline_id=None,
        settings=settings,
    )
    audit.record(
        conn,
        action="lab.scan_queued",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="scan",
        object_id=str(row_scan["id"]),
        ip=client_ip(request),
        details={"target_id": row["id"], "profile": payload.profile},
    )
    return {
        "scan": {
            "id": row_scan["id"],
            "target_id": row_scan["target_id"],
            "state": row_scan["state"],
            "created_at": row_scan["created_at"],
            "config": json.loads(row_scan["config"] or "{}"),
        },
        "created": created,
    }
