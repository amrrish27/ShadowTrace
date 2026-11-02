"""Authentication, session, CSRF, invitation and rate-limit behaviour."""
from __future__ import annotations

from app.db import db

from .conftest import PASSWORD, login


def _audit_actions(conn) -> list[str]:
    return [row["action"] for row in conn.execute("SELECT action FROM audit_log ORDER BY rowid").fetchall()]


def test_login_sets_hardened_cookies(client, app_env):
    response = client.post(
        "/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": PASSWORD}
    )
    assert response.status_code == 200
    assert response.json()["user"]["role"] == "viewer"
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(cookie for cookie in cookies if cookie.startswith("st_session="))
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie
    assert "Path=/" in session_cookie
    assert "Secure" not in session_cookie  # ST_COOKIE_SECURE=false in the test environment


def test_login_failures_do_not_reveal_account_existence(client, app_env):
    wrong = client.post("/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": "Wrong-Password-1!"})
    unknown = client.post("/api/v1/auth/login", json={"email": "ghost@org.example.test", "password": "Wrong-Password-1!"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]
    assert wrong.json()["error"]["code"] == "invalid_credentials"


def test_login_is_audited_without_secrets(client, app_env):
    client.post("/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": PASSWORD})
    client.post("/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": "nope-nope-nope"})
    with db() as conn:
        rows = conn.execute("SELECT action, details FROM audit_log WHERE action LIKE 'auth.login%'").fetchall()
    actions = [row["action"] for row in rows]
    assert "auth.login_success" in actions
    assert "auth.login_failed" in actions
    assert len(actions) == 2
    assert PASSWORD not in str([row["details"] for row in rows])


def test_csrf_header_is_required_for_state_changes(client, app_env):
    login(client, "analyst@org.example.test")
    missing = client.post("/api/v1/targets", json={"name": "x"})
    assert missing.status_code == 403
    assert missing.json()["error"]["code"] == "csrf_failed"
    # GET requests are exempt.
    assert client.get("/api/v1/targets").status_code == 200


def test_cross_origin_state_change_is_rejected(client, app_env):
    _, headers = login(client, "analyst@org.example.test")
    response = client.post(
        "/api/v1/targets",
        json={"name": "x"},
        headers={**headers, "Origin": "https://evil.example.net"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


def test_logout_revokes_the_session(client, app_env):
    _, headers = login(client, "analyst@org.example.test")
    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401
    with db() as conn:
        revoked = conn.execute("SELECT COUNT(*) AS n FROM sessions WHERE revoked_at IS NOT NULL").fetchone()["n"]
    assert revoked >= 1


def test_password_change_requires_current_password_and_rotates_sessions(client, app_env):
    _, headers = login(client, "analyst@org.example.test")
    bad = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "wrong-current-pass", "new_password": "Another-Strong-Pass-42!"},
        headers=headers,
    )
    assert bad.status_code == 400
    weak = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "password1234"},
        headers=headers,
    )
    assert weak.status_code == 422
    # A second, concurrent session for the same user must be revoked by the change.
    from fastapi.testclient import TestClient

    from app.main import app

    other = TestClient(app)
    other.__enter__()
    try:
        login(other, "analyst@org.example.test")
        assert other.get("/api/v1/auth/me").status_code == 200
        ok = client.post(
            "/api/v1/auth/change-password",
            json={"current_password": PASSWORD, "new_password": "Another-Strong-Pass-42!"},
            headers=headers,
        )
        assert ok.status_code == 200
        # The current session survives, every other session is revoked.
        assert client.get("/api/v1/auth/me").status_code == 200
        assert other.get("/api/v1/auth/me").status_code == 401
    finally:
        other.__exit__(None, None, None)
    # Restore the fixture password by logging in with the new one.
    csrf, new_headers = login(client, "analyst@org.example.test", "Another-Strong-Pass-42!")
    restore = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "Another-Strong-Pass-42!", "new_password": PASSWORD},
        headers=new_headers,
    )
    assert restore.status_code == 200


def test_invitation_acceptance_flow(admin_client):
    client, headers, env = admin_client
    invite = client.post(
        "/api/v1/users/invite",
        json={"email": "new.analyst@org.example.test", "role": "analyst"},
        headers=headers,
    )
    assert invite.status_code == 200
    token = invite.json()["token"]
    assert len(token) >= 20
    # Only the hash is stored, never the raw token.
    with db() as conn:
        stored = conn.execute("SELECT token_hash FROM invitations WHERE email = ?", ("new.analyst@org.example.test",)).fetchone()
    assert stored["token_hash"] != token
    accepted = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": token, "name": "New Analyst", "password": "Invited-Analyst-Pass-7!"},
    )
    assert accepted.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200
    # Single use: replaying the token fails.
    replay = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": token, "name": "New Analyst", "password": "Invited-Analyst-Pass-7!"},
    )
    assert replay.status_code == 400
    # An existing account cannot be invited again (as the admin, not the invitee).
    _, admin_headers = login(client, "admin@org.example.test")
    duplicate = client.post(
        "/api/v1/users/invite",
        json={"email": "viewer@org.example.test", "role": "viewer"},
        headers=admin_headers,
    )
    assert duplicate.status_code == 409


def test_invalid_invitation_token_is_rejected(client, app_env):
    response = client.post(
        "/api/v1/auth/accept-invite",
        json={"token": "x" * 40, "name": "Nobody", "password": "Invited-Analyst-Pass-7!"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_invitation"


def test_login_rate_limit_per_account(client, app_env):
    from app.security.ratelimit import POLICY, limiter

    limit, _window = POLICY["login_account"]
    for _ in range(limit):
        client.post("/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": "wrong-password-1"})
    blocked = client.post("/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": PASSWORD})
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After")
    limiter.reset()
    assert client.post("/api/v1/auth/login", json={"email": "viewer@org.example.test", "password": PASSWORD}).status_code == 200


def test_me_returns_csrf_token_and_organization(client, app_env):
    _, headers = login(client, "viewer@org.example.test")
    body = client.get("/api/v1/auth/me", headers=headers).json()
    assert body["user"]["email"] == "viewer@org.example.test"
    assert body["organization"] == "Primary Org"
    assert len(body["csrf_token"]) >= 16


def test_admin_user_management_guards(admin_client):
    client, headers, env = admin_client
    users = client.get("/api/v1/users", headers=headers).json()["users"]
    assert {user["email"] for user in users} >= {
        "admin@org.example.test",
        "analyst@org.example.test",
        "viewer@org.example.test",
    }
    # An admin cannot demote or disable themselves.
    self_update = client.patch(
        f"/api/v1/users/{env['org_admin']['id']}", json={"role": "viewer"}, headers=headers
    )
    assert self_update.status_code == 409
    # Deactivating a user revokes their sessions on the next request.
    viewer_id = env["org_viewer"]["id"]
    assert client.patch(f"/api/v1/users/{viewer_id}", json={"is_active": False}, headers=headers).status_code == 200
    with db() as conn:
        assert conn.execute("SELECT is_active FROM users WHERE id = ?", (viewer_id,)).fetchone()["is_active"] == 0
