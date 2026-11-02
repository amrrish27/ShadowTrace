"""Test fixtures. Everything runs offline against a temporary database."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Iterator, Tuple

BACKEND = Path(__file__).resolve().parent.parent
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))

os.environ.setdefault("ST_ENV", "test")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import reset_settings_cache  # noqa: E402
from app.db import db, init_db, new_id, now  # noqa: E402
from app.security.passwords import hash_password  # noqa: E402
from app.security.tokens import verification_token  # noqa: E402

PASSWORD = "Correct-Horse-Battery-9!"


def _seed() -> Dict[str, Dict[str, str]]:
    ids = {}
    with db() as conn:
        for org_key, org_name in (("org", "Primary Org"), ("other", "Other Org")):
            org_id = new_id()
            conn.execute("INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)", (org_id, org_name, now()))
            ids[org_key] = {"org_id": org_id}
            for role in ("admin", "analyst", "viewer"):
                user_id = new_id()
                email = f"{role}@{org_key}.example.test"
                conn.execute(
                    """
                    INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                    """,
                    (user_id, org_id, email, role.title(), role, hash_password(PASSWORD), now()),
                )
                ids[f"{org_key}_{role}"] = {"id": user_id, "email": email, "org_id": org_id}
        # An approved target owned by the primary org (loopback lab host, no scanning in unit tests).
        target_id = new_id()
        conn.execute(
            """
            INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes, authorization_mode,
                                 authorization_status, attestation, justification, verification_token, verified_at,
                                 verified_by, created_by, created_at, limits)
            VALUES (?, ?, 'Alpha', 'http://127.0.0.1:8099', '127.0.0.1', 'http', '[8099]', '[]', 'lab_allowlist',
                    'approved', 'Operator-approved lab target for the test suite.', 'test lab',
                    ?, ?, ?, ?, ?, '{}')
            """,
            (
                target_id,
                ids["org"]["org_id"],
                verification_token(),
                now(),
                ids["org_analyst"]["id"],
                ids["org_analyst"]["id"],
                now(),
            ),
        )
        ids["target"] = {"id": target_id, "org_id": ids["org"]["org_id"]}
    return ids


@pytest.fixture()
def app_env(tmp_path, monkeypatch) -> Iterator[Dict[str, Dict[str, str]]]:
    monkeypatch.setenv("ST_ENV", "test")
    monkeypatch.setenv("ST_DATABASE_PATH", str(tmp_path / "shadowtrace-test.db"))
    monkeypatch.setenv("ST_ALLOWED_HOSTS", "testserver,localhost,127.0.0.1")
    monkeypatch.setenv("ST_CORS_ORIGINS", "http://testserver")
    monkeypatch.setenv("ST_COOKIE_SECURE", "false")
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", "")
    monkeypatch.setenv("ST_SCANNING_ENABLED", "true")
    monkeypatch.delenv("SCANNING_ENABLED", raising=False)
    reset_settings_cache()
    init_db()
    from app.security.ratelimit import limiter

    limiter.reset()
    yield _seed()
    reset_settings_cache()


@pytest.fixture()
def client(app_env) -> Iterator[TestClient]:
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, email: str, password: str = PASSWORD) -> Tuple[str, Dict[str, str]]:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    csrf = client.cookies.get("st_csrf")
    assert csrf
    return csrf, {"X-CSRF-Token": csrf}


@pytest.fixture()
def admin_client(client, app_env):
    csrf, headers = login(client, "admin@org.example.test")
    return client, headers, app_env


@pytest.fixture()
def analyst_client(client, app_env):
    csrf, headers = login(client, "analyst@org.example.test")
    return client, headers, app_env


@pytest.fixture()
def viewer_client(client, app_env):
    csrf, headers = login(client, "viewer@org.example.test")
    return client, headers, app_env
