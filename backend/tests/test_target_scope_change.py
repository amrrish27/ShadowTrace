"""An approval belongs to the origin that was reviewed (BUG-20).

`PATCH /api/v1/targets/{id}` re-validated the *new* URL but carried the old
`authorization_status` forward, so an analyst could repoint an admin-approved target at any
host and immediately queue a scan against it (201). `POST /verify` was the same hole from the
other side: it approved whatever target the caller could serve a token for, which made the
approval recoverable by the very account that had just lost it.

Every test here fails if either behaviour comes back. The names say what must be true.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.db import db

SECONDARY_HOST = "https://unrelated-third-party.example.net"
PASSWORD = "Correct-Horse-Battery-9!"  # the seeded password in tests/conftest.py


def _serve(body: bytes, status: int = 200):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib naming
            self.send_response(self.status)
            self.end_headers()
            self.wfile.write(self.body)

        def log_message(self, *_args):  # keep the test output clean
            return

    handler = type("Handler", (Handler,), {"body": body, "status": status})
    server = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, handler


@pytest.fixture()
def admin_target(admin_client):
    """An approved, admin-authorized target on a public host, plus the admin's headers."""
    client, headers, env = admin_client
    created = client.post(
        "/api/v1/targets",
        json={
            "name": "Approved Site",
            "base_url": "https://approved.example.test",
            "authorization_mode": "admin",
            "attestation": "Operator owns approved.example.test for this regression test.",
            "ports": [443],
        },
        headers=headers,
    )
    assert created.status_code in {200, 201}, created.text
    target = created.json()["target"]
    assert target["authorization_status"] == "approved"
    return client, headers, env, target


def _status(client, headers, target_id):
    body = client.get(f"/api/v1/targets/{target_id}", headers=headers).json()["target"]
    return body["authorization_status"], body["host"], body["verified_at"]


def _scan_is_refused(client, headers, target_id, key="scope-change-1"):
    response = client.post(
        "/api/v1/scans",
        json={"target_id": target_id, "attestation": "Attempting to scan a repointed target."},
        headers={**headers, "Idempotency-Key": key},
    )
    assert response.status_code == 409, response.text
    assert response.json()["error"]["code"] == "target_not_authorized"
    return response


# --------------------------------------------------------------------------
# The reported exploit
# --------------------------------------------------------------------------


def _become(client, email):
    """Re-login the shared client as another seeded user and return CSRF headers."""
    response = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": client.cookies.get("st_csrf") or ""}


def test_an_analyst_repointing_an_approved_target_drops_the_approval(admin_client, admin_target):
    """The exact reported bypass: PATCH the host, keep `approved`, scan it (201)."""
    client, _admin_headers, _env, target = admin_target
    analyst_headers = _become(client, "analyst@org.example.test")

    patched = client.patch(
        f"/api/v1/targets/{target['id']}",
        json={"base_url": SECONDARY_HOST},
        headers=analyst_headers,
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()["target"]
    assert body["host"] == "unrelated-third-party.example.net"
    assert body["authorization_status"] == "pending"
    assert body["scan_ready"] is False
    assert body["verified_at"] is None, "the old approval stamp must not survive the repoint"

    _scan_is_refused(client, analyst_headers, target["id"])


def test_the_revocation_is_audited_with_both_scopes(admin_client, admin_target):
    client, _admin_headers, _env, target = admin_target
    client.patch(
        f"/api/v1/targets/{target['id']}",
        json={"base_url": SECONDARY_HOST},
        headers=_become(client, "analyst@org.example.test"),
    )
    with db() as conn:
        row = conn.execute(
            "SELECT action, details FROM audit_log WHERE action = 'target.approval_revoked' ORDER BY ts DESC"
        ).fetchone()
    assert row is not None, "a revoked approval must leave its own audit row"
    details = json.loads(row["details"])
    assert details["from"]["host"] == "approved.example.test"
    assert details["to"]["host"] == "unrelated-third-party.example.net"
    assert details["from"]["ports"] == [443]
    assert details["mode"] == "admin"


# --------------------------------------------------------------------------
# The rest of the scope: scheme, ports, path prefixes
# --------------------------------------------------------------------------


def test_changing_the_scheme_drops_the_approval(admin_client, admin_target):
    client, headers, _env, target = admin_target
    # Same host, same port, different scheme -- the only field that moves is `scheme`.
    patched = client.patch(
        f"/api/v1/targets/{target['id']}",
        json={"base_url": "http://approved.example.test:443"},
        headers=headers,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["target"]["scheme"] == "http"
    assert patched.json()["target"]["authorization_status"] == "pending"


def test_widening_the_port_set_drops_the_approval(admin_client, admin_target):
    client, headers, _env, target = admin_target
    patched = client.patch(f"/api/v1/targets/{target['id']}", json={"ports": [443, 8443]}, headers=headers)
    assert patched.json()["target"]["authorization_status"] == "pending"


def test_widening_the_path_prefixes_drops_the_approval(admin_client, admin_target):
    """Same host, wider paths: the reviewed surface changed, so the review is void."""
    client, headers, _env, target = admin_target
    patched = client.patch(
        f"/api/v1/targets/{target['id']}", json={"path_prefixes": ["/admin"]}, headers=headers
    )
    assert patched.json()["target"]["authorization_status"] == "pending"


def test_an_administrator_repointing_also_needs_to_re_approve(admin_client, admin_target):
    """Not a special case for analysts: the approval describes the *origin*, not the actor."""
    client, headers, _env, target = admin_target
    patched = client.patch(
        f"/api/v1/targets/{target['id']}", json={"base_url": SECONDARY_HOST}, headers=headers
    )
    assert patched.json()["target"]["authorization_status"] == "pending"

    # ... and an explicit approval restores it, on the new scope.
    approved = client.post(
        f"/api/v1/targets/{target['id']}/approve",
        json={"justification": "Reviewed the new origin and re-approved it."},
        headers=headers,
    )
    assert approved.status_code == 200
    assert approved.json()["target"]["authorization_status"] == "approved"
    assert approved.json()["target"]["verified_at"] is not None


# --------------------------------------------------------------------------
# No false positives: edits that do not change scope must keep the approval
# --------------------------------------------------------------------------


def test_renaming_a_target_keeps_the_approval(admin_client, admin_target):
    client, headers, _env, target = admin_target
    patched = client.patch(f"/api/v1/targets/{target['id']}", json={"name": "Renamed"}, headers=headers)
    assert patched.json()["target"]["authorization_status"] == "approved"


def test_resending_the_same_scope_keeps_the_approval(admin_client, admin_target):
    """A form that submits every field must not cost an approval when nothing moved."""
    client, headers, _env, target = admin_target
    patched = client.patch(
        f"/api/v1/targets/{target['id']}",
        json={
            "base_url": "https://approved.example.test/",
            "ports": [443],
            "path_prefixes": [],
        },
        headers=headers,
    )
    assert patched.json()["target"]["authorization_status"] == "approved"


def test_a_cosmetic_prefix_difference_is_not_a_scope_change(admin_client, admin_target):
    client, headers, _env, target = admin_target
    first = client.patch(
        f"/api/v1/targets/{target['id']}", json={"path_prefixes": ["/app"]}, headers=headers
    )
    assert first.json()["target"]["authorization_status"] == "pending"
    client.post(
        f"/api/v1/targets/{target['id']}/approve",
        json={"justification": "Approved with the /app prefix for the cosmetic test."},
        headers=headers,
    )
    again = client.patch(
        f"/api/v1/targets/{target['id']}", json={"path_prefixes": ["/app/"]}, headers=headers
    )
    assert again.json()["target"]["authorization_status"] == "approved", (
        '"/app/" and "/app" scope the same paths; that must not revoke an approval'
    )


# --------------------------------------------------------------------------
# The documented exception: lab targets follow the operator allow-list
# --------------------------------------------------------------------------


def test_a_lab_target_may_move_within_the_operator_allowlist(analyst_client, monkeypatch):
    """`lab_allowlist` re-validates against ST_PRIVATE_ALLOWLIST on every edit, so the
    operator's allow-list -- not this row -- authorises the destination."""
    client, headers, _env = analyst_client
    from app.config import reset_settings_cache

    first, _handler_a = _serve(b"a")
    second, _handler_b = _serve(b"b")
    port_a = first.server_address[1]
    port_b = second.server_address[1]
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port_a},127.0.0.1:{port_b}")
    reset_settings_cache()
    with db() as conn:
        conn.execute("DELETE FROM targets")  # hosts are unique per organization
    try:
        created = client.post(
            "/api/v1/targets",
            json={
                "name": "Lab A",
                "base_url": f"http://127.0.0.1:{port_a}",
                "ports": [port_a],
                "authorization_mode": "lab_allowlist",
                "attestation": "Operator-owned lab target, allow-listed for this test.",
            },
            headers=headers,
        )
        assert created.status_code in {200, 201}, created.text
        target = created.json()["target"]
        assert target["authorization_status"] == "approved"

        moved = client.patch(
            f"/api/v1/targets/{target['id']}",
            json={"base_url": f"http://127.0.0.1:{port_b}", "ports": [port_b]},
            headers=headers,
        )
        assert moved.status_code == 200, moved.text
        assert moved.json()["target"]["authorization_status"] == "approved"
    finally:
        for server in (first, second):
            server.shutdown()
            server.server_close()
        reset_settings_cache()


def test_a_lab_target_may_not_move_off_the_operator_allowlist(analyst_client, monkeypatch):
    client, headers, _env = analyst_client
    from app.config import reset_settings_cache

    server, _handler = _serve(b"x")
    port = server.server_address[1]
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port}")
    reset_settings_cache()
    with db() as conn:
        conn.execute("DELETE FROM targets")
    try:
        created = client.post(
            "/api/v1/targets",
            json={
                "name": "Lab Only",
                "base_url": f"http://127.0.0.1:{port}",
                "ports": [port],
                "authorization_mode": "lab_allowlist",
                "attestation": "Operator-owned lab target, allow-listed for this test.",
            },
            headers=headers,
        )
        target = created.json()["target"]
        refused = client.patch(
            f"/api/v1/targets/{target['id']}",
            json={"base_url": "http://127.0.0.1:1", "ports": [1]},
            headers=headers,
        )
        assert refused.status_code == 422, refused.text
        assert refused.json()["error"]["code"] == "invalid_target"
    finally:
        server.shutdown()
        server.server_close()
        reset_settings_cache()


# --------------------------------------------------------------------------
# The other half: verification is not an approval authority
# --------------------------------------------------------------------------


def test_verification_cannot_self_approve_a_pending_admin_target(analyst_client, monkeypatch):
    """A repointed admin target drops to `pending`. The analyst can read the verification
    token, so if `/verify` still approved, the reset would be pointless."""
    client, headers, env = analyst_client
    from app.config import reset_settings_cache
    from app.security.tokens import verification_token

    server, handler = _serve(b"placeholder")
    port = server.server_address[1]
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port}")
    reset_settings_cache()
    token = verification_token()
    with db() as conn:
        conn.execute("DELETE FROM targets")
        conn.execute(
            """
            INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes,
                                 authorization_mode, authorization_status, attestation, justification,
                                 verification_token, verified_at, verified_by, created_by, created_at, limits)
            VALUES ('admin-pending', ?, 'Admin pending', ?, '127.0.0.1', 'http', ?, '[]',
                    'admin', 'pending', 'Admin-owned target awaiting approval.', 'test',
                    ?, NULL, NULL, ?, 1, '{}')
            """,
            (
                env["org"]["org_id"],
                f"http://127.0.0.1:{port}",
                json.dumps([port]),
                token,
                env["org_admin"]["id"],
            ),
        )
    handler.body = token.encode()
    try:
        checked = client.post("/api/v1/targets/admin-pending/verify", headers=headers)
        assert checked.status_code == 200, checked.text
        assert checked.json()["verified"] is True, "the challenge itself succeeded"
        assert checked.json()["self_approved"] is False
        assert checked.json()["requires_admin_approval"] is True
        assert checked.json()["target"]["authorization_status"] == "pending"
        _scan_is_refused(client, headers, "admin-pending", key="admin-pending-1")
    finally:
        server.shutdown()
        server.server_close()
        reset_settings_cache()


def test_verification_still_approves_an_ownership_target(analyst_client, monkeypatch):
    """The self-service path that `ownership` mode exists for must keep working."""
    client, headers, _env = analyst_client
    from app.config import reset_settings_cache

    server, handler = _serve(b"placeholder")
    port = server.server_address[1]
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port}")
    reset_settings_cache()
    with db() as conn:
        conn.execute("DELETE FROM targets")
    try:
        created = client.post(
            "/api/v1/targets",
            json={
                "name": "Ownership Lab",
                "base_url": f"http://127.0.0.1:{port}",
                "ports": [port],
                "authorization_mode": "ownership",
                "attestation": "Fixture used to exercise the ownership challenge.",
            },
            headers=headers,
        )
        target = created.json()["target"]
        assert target["authorization_status"] == "pending"
        handler.body = target["verification_token"].encode()
        checked = client.post(f"/api/v1/targets/{target['id']}/verify", headers=headers)
        assert checked.json()["verified"] is True
        assert checked.json()["self_approved"] is True
        assert checked.json()["target"]["authorization_status"] == "approved"
    finally:
        server.shutdown()
        server.server_close()
        reset_settings_cache()


def test_a_repointed_ownership_target_needs_a_fresh_challenge(analyst_client, monkeypatch):
    """Ownership does not exempt a target from the reset: the new host must answer too."""
    client, headers, _env = analyst_client
    from app.config import reset_settings_cache

    first, handler_a = _serve(b"placeholder")
    second, _handler_b = _serve(b"not-the-token")
    port_a, port_b = first.server_address[1], second.server_address[1]
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port_a},127.0.0.1:{port_b}")
    reset_settings_cache()
    with db() as conn:
        conn.execute("DELETE FROM targets")
    try:
        created = client.post(
            "/api/v1/targets",
            json={
                "name": "Ownership Move",
                "base_url": f"http://127.0.0.1:{port_a}",
                "ports": [port_a],
                "authorization_mode": "ownership",
                "attestation": "Fixture used to exercise ownership re-verification.",
            },
            headers=headers,
        )
        target = created.json()["target"]
        handler_a.body = target["verification_token"].encode()
        approved = client.post(f"/api/v1/targets/{target['id']}/verify", headers=headers)
        assert approved.json()["target"]["authorization_status"] == "approved"

        moved = client.patch(
            f"/api/v1/targets/{target['id']}",
            json={"base_url": f"http://127.0.0.1:{port_b}", "ports": [port_b]},
            headers=headers,
        )
        assert moved.json()["target"]["authorization_status"] == "pending"

        # The new host answers with the wrong body: still pending, still not scannable.
        recheck = client.post(f"/api/v1/targets/{target['id']}/verify", headers=headers)
        assert recheck.json()["verified"] is False
        assert recheck.json()["target"]["authorization_status"] == "pending"
        _scan_is_refused(client, headers, target["id"], key="ownership-move-1")
    finally:
        for server in (first, second):
            server.shutdown()
            server.server_close()
        reset_settings_cache()
