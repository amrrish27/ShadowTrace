"""Authorization matrix: every API route declares a minimum role and enforces it."""
from __future__ import annotations

import pytest

from app.api.deps import ROUTE_POLICY

from .conftest import PASSWORD, login

ROLE_RANK = {"public": 0, "viewer": 1, "analyst": 2, "admin": 3}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _documented_routes():
    from app.main import app

    routes = set()
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith("/api/"):
            continue
        for method in operations:
            upper = method.upper()
            if upper in {"HEAD", "OPTIONS"}:
                continue
            routes.add(f"{upper} {path}")
    return routes


def _real_path(template: str) -> str:
    """Substitute concrete values for path parameters."""
    return (
        template.replace("{target_id}", "00000000-0000-0000-0000-000000000000")
        .replace("{scan_id}", "00000000-0000-0000-0000-000000000000")
        .replace("{endpoint_id}", "00000000-0000-0000-0000-000000000000")
        .replace("{finding_id}", "00000000-0000-0000-0000-000000000000")
        .replace("{user_id}", "00000000-0000-0000-0000-000000000000")
    )


def test_every_route_has_a_policy_entry():
    documented = _documented_routes()
    missing = sorted(documented - set(ROUTE_POLICY))
    assert missing == [], f"routes without a minimum role: {missing}"
    stale = sorted(set(ROUTE_POLICY) - documented)
    assert stale == [], f"policy entries for routes that do not exist: {stale}"


def test_policy_values_are_valid_roles():
    assert set(ROUTE_POLICY.values()) <= set(ROLE_RANK)
    # Mutating and administrative surfaces are never public.
    for key, role in ROUTE_POLICY.items():
        method = key.split(" ", 1)[0]
        if method in {"DELETE", "PATCH"}:
            assert role in {"analyst", "admin"}, key
    assert ROUTE_POLICY["GET /api/v1/admin/audit"] == "admin"
    assert ROUTE_POLICY["GET /api/v1/health"] == "public"


@pytest.fixture()
def session_client(client, app_env):
    """One client that can switch identities; returns (client, login helper)."""

    cache = {}

    def as_role(role: str):
        if role in cache:
            return cache[role]
        if role == "anonymous":
            client.cookies.clear()
            headers = {}
        else:
            _, headers = login(client, f"{role}@org.example.test")
        cache[role] = headers
        return headers

    return client, as_role


@pytest.mark.parametrize("role", ["anonymous", "viewer", "analyst", "admin"])
def test_role_matrix_enforcement(session_client, role):
    client, as_role = session_client
    failures = []
    # Logout revokes the session, so it is exercised last (below).
    ordered = [(key, role_) for key, role_ in sorted(ROUTE_POLICY.items(), key=lambda item: item[0].split(" ")[1])
               if key != "POST /api/v1/auth/logout"]
    for key, minimum in ordered:
        method, template = key.split(" ", 1)
        headers = as_role(role)
        url = _real_path(template)
        is_public_form = method in SAFE_METHODS
        response = client.request(
            method,
            url,
            headers=headers,
            json={} if method in {"POST", "PATCH"} and not is_public_form else None,
        )
        status = response.status_code
        if role == "anonymous":
            if minimum == "public":
                assert status not in {401, 403}, (key, status, response.text)
            else:
                assert status == 401, (key, status, response.text)
        else:
            if ROLE_RANK[role] < ROLE_RANK[minimum]:
                # Insufficient role is always a clean 403, never a 404/500.
                if status != 403:
                    failures.append((key, role, status))
            else:
                if status in {401, 403}:
                    failures.append((key, role, status, response.text))
    # Logout: anonymous is rejected, any signed-in role may end its own session.
    headers = as_role(role)
    logout = client.post("/api/v1/auth/logout", headers=headers)
    if role == "anonymous":
        assert logout.status_code == 401
    else:
        if logout.status_code != 200:
            failures.append(("POST /api/v1/auth/logout", role, logout.status_code, logout.text))
        assert client.get("/api/v1/auth/me").status_code == 401
    assert failures == [], f"authorization matrix violations: {failures}"


def test_viewer_cannot_mutate_but_can_read(viewer_client):
    client, headers, env = viewer_client
    target_id = env["target"]["id"]
    assert client.get("/api/v1/targets").status_code == 200
    assert client.post("/api/v1/targets", json={"name": "x"}, headers=headers).status_code == 403
    assert client.post(f"/api/v1/targets/{target_id}/approve", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/audit", headers=headers).status_code == 403
    assert client.post("/api/v1/users/invite", json={"email": "x@y.test", "role": "viewer"}, headers=headers).status_code == 403


def test_analyst_cannot_reach_admin_surfaces(analyst_client):
    client, headers, env = analyst_client
    assert client.get("/api/v1/admin/audit", headers=headers).status_code == 403
    assert client.get("/api/v1/admin/settings", headers=headers).status_code == 403
    assert client.get("/api/v1/users", headers=headers).status_code == 403
    assert client.post(f"/api/v1/targets/{env['target']['id']}/approve", headers=headers).status_code == 403


def test_admin_can_reach_admin_surfaces(admin_client):
    client, headers, env = admin_client
    assert client.get("/api/v1/admin/audit", headers=headers).status_code == 200
    assert client.get("/api/v1/admin/settings", headers=headers).status_code == 200
    assert client.get("/api/v1/users", headers=headers).status_code == 200


def test_cross_organization_access_is_not_found(analyst_client):
    """Objects from another organization must look like they do not exist."""
    client, headers, env = analyst_client
    from app.db import db, new_id, now

    other_org = env["other"]["org_id"]
    foreign_target = new_id()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes,
                                 authorization_mode, authorization_status, attestation, justification,
                                 verification_token, created_by, created_at, limits)
            VALUES (?, ?, 'Foreign', 'http://127.0.0.1:8099', '127.0.0.1', 'http', '[8099]', '[]',
                    'lab_allowlist', 'approved', 'x', 'x', 'tok', ?, ?, '{}')
            """,
            (foreign_target, other_org, env["other_analyst"]["id"], now()),
        )
    assert client.get(f"/api/v1/targets/{foreign_target}", headers=headers).status_code == 404
    assert client.delete(f"/api/v1/targets/{foreign_target}", headers=headers).status_code == 403
    # An admin of the primary org still cannot read across the tenant boundary.
    csrf, admin_headers = login(client, "admin@org.example.test", PASSWORD)
    assert client.get(f"/api/v1/targets/{foreign_target}", headers=admin_headers).status_code == 404
