"""Health and metadata endpoints."""
from __future__ import annotations

import sqlite3
from typing import Dict

from fastapi import APIRouter, Depends

from ..config import get_settings
from ..engine.rules import rules_documentation
from ..engine.scan_rules import SCAN_RULES
from ..engine.safe_http import VERSION
from ..security.auth import AuthContext
from .deps import current_auth, get_conn

router = APIRouter(prefix="/api/v1", tags=["meta"])


@router.get("/health")
def health(conn: sqlite3.Connection = Depends(get_conn)) -> Dict[str, object]:
    try:
        conn.execute("SELECT 1").fetchone()
        status = "ok"
    except sqlite3.Error:
        status = "degraded"
    return {"status": status, "version": VERSION}


@router.get("/meta/config")
def public_config(auth: AuthContext = Depends(current_auth)) -> Dict[str, object]:
    settings = get_settings()
    return {
        "version": VERSION,
        "scanning_enabled": settings.scanning_enabled,
        "environment": settings.env,
        "features": {
            "crawler": True,
            "source_maps": True,
            "specifications": True,
            "har_import": True,
            "graphql_introspection": False,
            "headless_browser": False,
        },
        "limits": {
            "max_requests_per_scan": settings.max_requests_per_scan_hard_cap,
            "max_pages_per_scan": settings.max_pages_per_scan_hard_cap,
            "max_scan_seconds": settings.max_scan_seconds_hard_cap,
        },
    }


@router.get("/meta/rules")
def rule_catalogue(auth: AuthContext = Depends(current_auth)) -> Dict[str, object]:
    return {
        "rules": rules_documentation(),
        "scan_rules": list(SCAN_RULES),
        "scoring": "risk_score = severity base + 12 x confidence weight + 4 x exposure (clamped to 0-100)",
    }
