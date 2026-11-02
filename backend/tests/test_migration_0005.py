"""Test upgrading database from 0004 schema to 0005 schema."""
from __future__ import annotations

import sqlite3
from pathlib import Path
import pytest

from app.db import _connect, apply_migrations, MIGRATIONS_DIR, new_id, now


def test_upgrade_0004_to_0005_with_data(tmp_path: Path):
    db_path = str(tmp_path / "test_migration.db")
    conn = _connect(db_path)
    
    # 1. Apply migrations 0001 to 0004
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)"
    )
    for v in ["0001_init.sql", "0002_har.sql", "0003_scan_endpoint_status.sql", "0004_lab_grants_worker_health.sql"]:
        sql_file = MIGRATIONS_DIR / v
        conn.executescript(sql_file.read_text(encoding="utf-8"))
        conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (v, now()))
    conn.commit()

    # 2. Insert test data
    org_id = new_id()
    user_id = new_id()
    target_id = new_id()
    scan_id = new_id()
    ep_id = new_id()

    conn.execute("INSERT INTO organizations (id, name, created_at) VALUES (?, 'Org', ?)", (org_id, now()))
    conn.execute(
        "INSERT INTO users (id, org_id, email, name, role, password_hash, created_at) VALUES (?, ?, 'u@test.org', 'User', 'admin', 'hash', ?)",
        (user_id, org_id, now()),
    )
    conn.execute(
        """
        INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes, authorization_mode,
                             authorization_status, attestation, justification, verification_token, created_by, created_at, limits)
        VALUES (?, ?, 'Target', 'https://example.com', 'example.com', 'https', '[443]', '[]', 'ownership', 'approved', 'attest', 'just', 'tok', ?, ?, '{}')
        """,
        (target_id, org_id, user_id, now()),
    )
    conn.execute(
        """
        INSERT INTO scans (id, org_id, target_id, created_by, state, config, idempotency_key, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'completed', '{}', 'idem1', ?, ?)
        """,
        (scan_id, org_id, target_id, user_id, now(), now()),
    )
    conn.execute(
        """
        INSERT INTO endpoints (id, org_id, target_id, host, method, path_template, classification, validation_status, fingerprint, first_seen_at, last_seen_at, origin)
        VALUES (?, ?, ?, 'example.com', 'GET', '/api/v1/data', 'shadow', 'live', 'fp1', ?, ?, 'https://example.com')
        """,
        (ep_id, org_id, target_id, now(), now()),
    )
    conn.execute(
        "INSERT INTO scan_endpoints (scan_id, endpoint_id, validation_status, classification) VALUES (?, ?, 'live', 'shadow')",
        (scan_id, ep_id),
    )
    conn.execute(
        """
        INSERT INTO endpoint_sources (endpoint_id, scan_id, source_type, source_url, extractor, created_at)
        VALUES (?, ?, 'html', 'https://example.com', 'link', ?)
        """,
        (ep_id, scan_id, now()),
    )
    conn.commit()

    # 3. Verify that under 0004, 'candidate' or 'discovered' or 'probe' fail CHECK constraints
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO endpoints (id, org_id, target_id, host, method, path_template, classification, validation_status, fingerprint, first_seen_at, last_seen_at, origin)
            VALUES ('ep_fail', ?, ?, 'example.com', 'GET', '/api/cand', 'candidate', 'unvalidated', 'fp_cand', ?, ?, 'https://example.com')
            """,
            (org_id, target_id, now(), now()),
        )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO endpoint_sources (endpoint_id, scan_id, source_type, source_url, extractor, created_at)
            VALUES (?, ?, 'probe', 'https://example.com', 'probe', ?)
            """,
            (ep_id, scan_id, now()),
        )

    conn.close()

    # 4. Apply migrations (which runs 0005)
    applied = apply_migrations(db_path)
    assert "0005_classification_and_sources.sql" in applied

    # 5. Verify data integrity and new capabilities
    conn2 = _connect(db_path)
    try:
        # FK integrity check
        fk_violations = list(conn2.execute("PRAGMA foreign_key_check"))
        assert fk_violations == []

        # Previous data still present
        row = conn2.execute("SELECT * FROM endpoints WHERE id = ?", (ep_id,)).fetchone()
        assert row is not None
        assert row["path_template"] == "/api/v1/data"
        assert row["classification"] == "shadow"

        src_row = conn2.execute("SELECT * FROM endpoint_sources WHERE endpoint_id = ?", (ep_id,)).fetchone()
        assert src_row is not None
        assert src_row["source_type"] == "html"

        # Now inserting 'candidate' and 'discovered' works
        cand_id = new_id()
        conn2.execute(
            """
            INSERT INTO endpoints (id, org_id, target_id, host, method, path_template, classification, validation_status, fingerprint, first_seen_at, last_seen_at, origin)
            VALUES (?, ?, ?, 'example.com', 'GET', '/api/candidate', 'candidate', 'unvalidated', 'fp_cand', ?, ?, 'https://example.com')
            """,
            (cand_id, org_id, target_id, now(), now()),
        )

        disc_id = new_id()
        conn2.execute(
            """
            INSERT INTO endpoints (id, org_id, target_id, host, method, path_template, classification, validation_status, fingerprint, first_seen_at, last_seen_at, origin)
            VALUES (?, ?, ?, 'example.com', 'GET', '/api/disc', 'discovered', 'live', 'fp_disc', ?, ?, 'https://example.com')
            """,
            (disc_id, org_id, target_id, now(), now()),
        )

        # Inserting 'probe' source_type works
        conn2.execute(
            """
            INSERT INTO endpoint_sources (endpoint_id, scan_id, source_type, source_url, extractor, created_at)
            VALUES (?, ?, 'probe', 'https://example.com/api/probe', 'well_known_probe', ?)
            """,
            (cand_id, scan_id, now()),
        )
        conn2.commit()

        # Indexes check
        indexes = {r["name"] for r in conn2.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        assert "ux_endpoints_identity" in indexes
        assert "ix_endpoints_target" in indexes
        assert "ix_endpoints_class" in indexes
        assert "ix_endpoint_sources_ep" in indexes
        assert "ix_endpoint_sources_scan" in indexes
    finally:
        conn2.close()
