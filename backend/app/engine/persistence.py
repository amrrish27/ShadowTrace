"""Persistence helpers for the scanner.

All writes are organization-scoped and parameterized.  Evidence, snippets and
headers are redacted before they reach the database.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Dict, Optional

from ..db import new_id, now
from ..security.redaction import make_snippet, redact_headers
from .evidence import header_digest
from .normalizer import NormalizedEndpoint
from .types import DiscoveredEndpoint, RuleHit


def upsert_endpoint(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    target_id: str,
    normalized: NormalizedEndpoint,
    scan_id: str,
    classification: str,
) -> str:
    timestamp = now()
    row = conn.execute(
        """
        SELECT id FROM endpoints
        WHERE org_id = ? AND target_id = ? AND method = ? AND host = ? AND path_template = ? AND query_template = ?
        """,
        (org_id, target_id, normalized.method, normalized.host, normalized.path_template, normalized.query_template),
    ).fetchone()
    if row is not None:
        conn.execute(
            "UPDATE endpoints SET last_seen_at = ?, last_seen_scan = ?, classification = ? WHERE id = ?",
            (timestamp, scan_id, classification, row["id"]),
        )
        return str(row["id"])
    endpoint_id = new_id()
    conn.execute(
        """
        INSERT INTO endpoints (id, org_id, target_id, host, method, path_template, query_template, classification,
                               validation_status, fingerprint, first_seen_at, last_seen_at, first_seen_scan,
                               last_seen_scan, origin)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unvalidated', ?, ?, ?, ?, ?, ?)
        """,
        (
            endpoint_id,
            org_id,
            target_id,
            normalized.host,
            normalized.method,
            normalized.path_template,
            normalized.query_template,
            classification,
            normalized.fingerprint,
            timestamp,
            timestamp,
            scan_id,
            scan_id,
            normalized.origin,
        ),
    )
    return endpoint_id


def link_scan_endpoint(
    conn: sqlite3.Connection,
    scan_id: str,
    endpoint_id: str,
    validation_status: str,
    classification: str,
    response_status: Optional[int] = None,
) -> None:
    conn.execute(
        """
        INSERT INTO scan_endpoints (scan_id, endpoint_id, validation_status, classification, response_status)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(scan_id, endpoint_id) DO UPDATE SET validation_status = excluded.validation_status,
                                                        classification = excluded.classification,
                                                        response_status = excluded.response_status
        """,
        (scan_id, endpoint_id, validation_status, classification, response_status),
    )


def add_source(
    conn: sqlite3.Connection,
    *,
    endpoint_id: str,
    scan_id: str,
    source: DiscoveredEndpoint,
) -> None:
    conn.execute(
        """
        INSERT INTO endpoint_sources (endpoint_id, scan_id, source_type, source_url, location, method, snippet,
                                      extractor, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            endpoint_id,
            scan_id,
            source.source_type[:40],
            (source.source_url or "")[:500],
            make_snippet(source.location, 200),
            source.method.upper()[:10],
            make_snippet(source.snippet),
            source.extractor[:60],
            now(),
        ),
    )


def add_observation(
    conn: sqlite3.Connection,
    *,
    scan_id: str,
    endpoint_id: Optional[str],
    url: str,
    method: str,
    status_code: Optional[int],
    content_type: str,
    content_length: Optional[int],
    elapsed_ms: Optional[int],
    headers: Dict[str, str],
    snippet: str,
    error: Optional[str],
) -> str:
    observation_id = new_id()
    conn.execute(
        """
        INSERT INTO observations (id, scan_id, endpoint_id, url, method, status_code, content_type, content_length,
                                  elapsed_ms, headers, snippet, error, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            observation_id,
            scan_id,
            endpoint_id,
            url[:2048],
            method[:10],
            status_code,
            content_type[:100],
            content_length,
            elapsed_ms,
            json.dumps(redact_headers(headers), separators=(",", ":"))[:8000],
            make_snippet(snippet),
            (error or "")[:300],
            now(),
        ),
    )
    return observation_id


def set_endpoint_status(
    conn: sqlite3.Connection, endpoint_id: str, status: str, response_status: Optional[int]
) -> None:
    conn.execute(
        "UPDATE endpoints SET validation_status = ?, response_status = ?, last_seen_at = ? WHERE id = ?",
        (status, response_status, now(), endpoint_id),
    )


def set_endpoint_classification(
    conn: sqlite3.Connection, endpoint_id: str, classification: str
) -> None:
    conn.execute(
        "UPDATE endpoints SET classification = ?, last_seen_at = ? WHERE id = ?",
        (classification, now(), endpoint_id),
    )


def update_scan_endpoint_classification(
    conn: sqlite3.Connection, scan_id: str, endpoint_id: str, classification: str
) -> None:
    conn.execute(
        "UPDATE scan_endpoints SET classification = ? WHERE scan_id = ? AND endpoint_id = ?",
        (classification, scan_id, endpoint_id),
    )


def add_finding(
    conn: sqlite3.Connection,
    *,
    org_id: str,
    target_id: str,
    scan_id: str,
    endpoint_id: Optional[str],
    hit: RuleHit,
    risk: float,
    fingerprint: str,
) -> bool:
    """Insert a finding and return True only when it was actually inserted (not a duplicate)."""
    cur = conn.execute(
        """
        INSERT INTO findings (id, org_id, target_id, scan_id, endpoint_id, rule_id, title, severity, confidence,
                              status, exposure, risk_score, fingerprint, rationale, limitations, remediation,
                              evidence, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_id, fingerprint) DO NOTHING
        """,
        (
            new_id(),
            org_id,
            target_id,
            scan_id,
            endpoint_id,
            hit.rule_id,
            hit.title,
            hit.severity,
            hit.confidence,
            hit.status,
            float(hit.exposure),
            float(risk),
            fingerprint,
            hit.rationale[:4000],
            hit.limitations[:2000],
            hit.remediation[:2000],
            json.dumps(hit.evidence, separators=(",", ":"))[:20000],
            now(),
        ),
    )
    return cur.rowcount > 0


def add_event(
    conn: sqlite3.Connection, scan_id: str, kind: str, message: str, level: str = "info"
) -> None:
    conn.execute(
        "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, ?, ?, ?)",
        (scan_id, now(), level if level in {"debug", "info", "warning", "error"} else "info", kind[:40], message[:500]),
    )


def update_counters(conn: sqlite3.Connection, scan_id: str, counters: Dict[str, object]) -> None:
    conn.execute(
        "UPDATE scans SET counters = ?, updated_at = ?, heartbeat_at = ? WHERE id = ?",
        (json.dumps(counters, separators=(",", ":")), now(), now(), scan_id),
    )


def redacted_header_digest(headers: Dict[str, str]) -> Dict[str, str]:
    return header_digest(redact_headers(headers))
