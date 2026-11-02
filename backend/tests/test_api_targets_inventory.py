"""Target authorization, baselines, HAR import and the inventory/findings APIs.

These are the day-to-day surfaces an analyst drives in the UI, so the tests cover the
happy path, the filter/pagination contract and every refusal branch (wrong role,
cross-organization access, unsafe specification, oversized upload).
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app.db import db, new_id, now

from .conftest import login
from .test_api_scan_objects import _seed_scan

MINIMAL_OPENAPI = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "Contract", "version": "1.0.0"},
        "paths": {
            "/api/v1/users": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/api/v1/reports": {"post": {"responses": {"201": {"description": "created"}}}},
        },
    }
)


@pytest.fixture()
def seeded(analyst_client):
    client, headers, env = analyst_client
    return client, headers, env, _seed_scan(env)


class _Handler(BaseHTTPRequestHandler):
    """Serves one canned response, so tests never depend on an external server."""

    body = b""
    status = 200
    seen: list = []

    def do_GET(self):  # noqa: N802 - http.server API
        type(self).seen.append(self.path)
        self.send_response(type(self).status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *args):  # keep the test output clean
        return None


def _serve(body: bytes, status: int = 200):
    handler = type("Handler", (_Handler,), {"body": body, "status": status, "seen": []})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, handler


# ---------------------------------------------------------------- inventory


def test_endpoint_list_filters_sorting_and_pagination(seeded):
    client, headers, _env, data = seeded
    base = client.get("/api/v1/endpoints", headers=headers, params={"page_size": 2}).json()
    assert base["total"] == 3
    assert len(base["endpoints"]) == 2

    second = client.get("/api/v1/endpoints", headers=headers, params={"page_size": 2, "page": 2}).json()
    assert len(second["endpoints"]) == 1
    assert {row["id"] for row in base["endpoints"]} & {row["id"] for row in second["endpoints"]} == set()

    shadow = client.get("/api/v1/endpoints", headers=headers, params={"classification": "shadow"}).json()
    assert shadow["total"] == 2
    assert {row["classification"] for row in shadow["endpoints"]} == {"shadow"}

    by_method = client.get("/api/v1/endpoints", headers=headers, params={"method": "get"}).json()
    assert by_method["total"] == 3

    search = client.get("/api/v1/endpoints", headers=headers, params={"q": "internal"}).json()
    assert search["total"] == 1
    assert search["endpoints"][0]["path_template"] == "/api/v1/internal/reports"

    sorted_desc = client.get(
        "/api/v1/endpoints", headers=headers, params={"sort": "path", "order": "desc"}
    ).json()
    paths = [row["path_template"] for row in sorted_desc["endpoints"]]
    assert paths == sorted(paths, reverse=True)

    # An unknown sort key falls back to the default instead of reaching SQL.
    fallback = client.get("/api/v1/endpoints", headers=headers, params={"sort": "bogus"})
    assert fallback.status_code == 200
    assert fallback.json()["total"] == 3
    overlong = client.get("/api/v1/endpoints", headers=headers, params={"sort": "'; DROP TABLE endpoints; --"})
    assert overlong.status_code == 422

    for params in ({"order": "sideways"}, {"page": 0}, {"page_size": 101}):
        assert client.get("/api/v1/endpoints", headers=headers, params=params).status_code == 422
    bad = client.get("/api/v1/endpoints", headers=headers, params={"classification": "unknownish"})
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "invalid_filter"


def test_endpoint_detail_is_scoped_to_the_organization(seeded):
    client, headers, _env, data = seeded
    detail = client.get(f"/api/v1/endpoints/{data['endpoints'][1]}", headers=headers)
    assert detail.status_code == 200
    payload = detail.json()["endpoint"]
    assert payload["method"] == "GET"
    body = detail.json()
    assert body["endpoint"]["path_template"] == "/api/v1/internal/reports"
    assert body["sources"] and body["sources"][0]["source_type"] in {"openapi", "javascript"}
    assert body["observations"] and body["observations"][0]["status_code"] == 200
    assert "hostile" in body["note"]

    assert client.get("/api/v1/endpoints/does-not-exist", headers=headers).status_code == 404

    _csrf, other_headers = login(client, "analyst@other.example.test")
    cross_org = client.get(f"/api/v1/endpoints/{data['endpoints'][1]}", headers=other_headers)
    assert cross_org.status_code == 404


def test_finding_list_filters_and_detail_payload(seeded):
    client, headers, _env, data = seeded
    high = client.get("/api/v1/findings", headers=headers, params={"severity": "high"}).json()
    assert high["total"] == 1
    assert high["findings"][0]["rule_id"] == "ST-003"

    by_rule = client.get("/api/v1/findings", headers=headers, params={"rule": "ST-001"}).json()
    assert by_rule["total"] == 1

    assert client.get("/api/v1/findings", headers=headers, params={"confidence": "high"}).json()["total"] == 2
    assert client.get("/api/v1/findings", headers=headers, params={"target_id": data["endpoints"][0]})
    assert client.get("/api/v1/findings", headers=headers, params={"target_id": "missing"}).json()["total"] == 0

    detail = client.get(f"/api/v1/findings/{data['findings'][0]}", headers=headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["scoring"]["risk_score"] == 49.6
    assert "confidence" in body["scoring"]["explanation"]
    assert body["triage"]["status"] == "open"
    assert body["triage_history"] == []
    assert body["endpoint"]["path_template"]
    assert isinstance(body["finding"]["evidence"], dict)

    assert client.get("/api/v1/findings/missing", headers=headers).status_code == 404


def test_triage_records_history_and_updates_finding_filters(seeded):
    client, headers, _env, data = seeded
    finding_id = data["findings"][0]
    first = client.post(
        f"/api/v1/findings/{finding_id}/triage",
        json={"status": "accepted_risk", "reason": "Confirmed by the platform owner."},
        headers=headers,
    )
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "accepted_risk"

    second = client.post(
        f"/api/v1/findings/{finding_id}/triage",
        json={"status": "false_positive", "reason": "Documented internal tool after review."},
        headers=headers,
    )
    assert second.status_code == 200

    detail = client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    assert detail["triage"]["status"] == "false_positive"
    assert len(detail["triage_history"]) == 2
    assert detail["triage_history"][0]["user_email"] == "analyst@org.example.test"

    filtered = client.get("/api/v1/findings", headers=headers, params={"status": "false_positive"}).json()
    assert filtered["total"] == 1
    open_only = client.get("/api/v1/findings", headers=headers, params={"status": "open"}).json()
    assert open_only["total"] == 1

    with db() as conn:
        actions = [
            row["action"]
            for row in conn.execute("SELECT action FROM audit_log WHERE action = 'finding.triaged'").fetchall()
        ]
    assert len(actions) == 2

    bad_status = client.post(
        f"/api/v1/findings/{finding_id}/triage",
        json={"status": "not-a-state", "reason": "invalid transition"},
        headers=headers,
    )
    assert bad_status.status_code == 422
    short_reason = client.post(
        f"/api/v1/findings/{finding_id}/triage", json={"status": "accepted", "reason": "no"}, headers=headers
    )
    assert short_reason.status_code == 422


def test_viewer_cannot_triage_but_can_read(seeded, viewer_client):
    _client, _headers, _env, data = seeded
    client, headers, _ = viewer_client
    assert client.get("/api/v1/findings", headers=headers).status_code == 200
    denied = client.post(
        f"/api/v1/findings/{data['findings'][0]}/triage",
        json={"status": "accepted_risk", "reason": "Viewers must not be able to triage."},
        headers=headers,
    )
    assert denied.status_code == 403


# ---------------------------------------------------------------- targets


def test_ownership_target_stays_pending_until_an_admin_approves(admin_client):
    client, headers, _env = admin_client
    created = client.post(
        "/api/v1/targets",
        json={
            "name": "Customer Portal",
            "base_url": "http://portal.example.test",
            "ports": [80],
            "authorization_mode": "ownership",
            "attestation": "I am authorized to test this asset on behalf of its owner.",
            "justification": "Quarterly assurance review.",
        },
        headers=headers,
    )
    assert created.status_code in {200, 201}, created.text
    target = created.json()["target"]
    assert target["authorization_status"] == "pending"
    assert target["verification_token"]

    duplicate = client.post(
        "/api/v1/targets",
        json={
            "name": "Dup",
            "base_url": "http://portal.example.test",
            "ports": [80],
            "authorization_mode": "ownership",
            "attestation": "A second registration of the same host must be refused.",
        },
        headers=headers,
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "conflict"

    approved = client.post(
        f"/api/v1/targets/{target['id']}/approve",
        json={"justification": "Ownership confirmed by the platform owner."},
        headers=headers,
    )
    assert approved.status_code == 200
    assert approved.json()["target"]["authorization_status"] == "approved"

    listed = client.get("/api/v1/targets", headers=headers).json()["targets"]
    assert any(item["id"] == target["id"] for item in listed)


def test_target_creation_requires_attestation_and_matching_ports(admin_client):
    client, headers, _env = admin_client
    short_attestation = client.post(
        "/api/v1/targets",
        json={
            "name": "No Attestation",
            "base_url": "http://attest.example.test",
            "ports": [80],
            "authorization_mode": "ownership",
            "attestation": "too short",
        },
        headers=headers,
    )
    assert short_attestation.status_code == 422

    wrong_port = client.post(
        "/api/v1/targets",
        json={
            "name": "Wrong Port",
            "base_url": "http://ports.example.test:8080",
            "ports": [80, 443],
            "authorization_mode": "ownership",
            "attestation": "The base URL port must be part of the authorized port list.",
        },
        headers=headers,
    )
    assert wrong_port.status_code == 422
    assert wrong_port.json()["error"]["code"] == "invalid_target"

    not_http = client.post(
        "/api/v1/targets",
        json={
            "name": "FTP",
            "base_url": "ftp://files.example.test",
            "ports": [21],
            "authorization_mode": "ownership",
            "attestation": "Only http and https targets are supported by the scanner.",
        },
        headers=headers,
    )
    assert not_http.status_code == 422


def test_only_admins_approve_targets(analyst_client):
    client, headers, env = analyst_client
    target_id = env["target"]["id"]
    denied = client.post(
        f"/api/v1/targets/{target_id}/approve",
        json={"justification": "An analyst must not be able to approve a target."},
        headers=headers,
    )
    assert denied.status_code == 403


def test_target_delete_is_blocked_while_a_scan_is_active(admin_client, app_env):
    client, headers, env = admin_client
    target_id = env["target"]["id"]
    scan_id = new_id()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                               partial, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'running', '{}', '{}', 'delete-guard', 0, ?, ?)
            """,
            (scan_id, env["target"]["org_id"], target_id, env["org_analyst"]["id"], now(), now()),
        )
    blocked = client.delete(f"/api/v1/targets/{target_id}", headers=headers)
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "conflict"

    with db() as conn:
        conn.execute("UPDATE scans SET state = 'completed' WHERE id = ?", (scan_id,))
    assert client.delete(f"/api/v1/targets/{target_id}", headers=headers).status_code == 200
    assert client.get(f"/api/v1/targets/{target_id}", headers=headers).status_code == 404

    with db() as conn:
        row = conn.execute("SELECT action FROM audit_log WHERE action = 'target.deleted'").fetchone()
    assert row is not None


def test_baseline_upload_validates_the_document(analyst_client):
    client, headers, env = analyst_client
    target_id = env["target"]["id"]
    assert client.get(f"/api/v1/targets/{target_id}/baselines", headers=headers).json()["baselines"] == []

    created = client.post(
        f"/api/v1/targets/{target_id}/baselines",
        json={"source": "upload", "content": MINIMAL_OPENAPI},
        headers=headers,
    )
    assert created.status_code == 200, created.text
    assert created.json()["endpoint_count"] == 2

    listed = client.get(f"/api/v1/targets/{target_id}/baselines", headers=headers).json()["baselines"]
    assert len(listed) == 1
    assert listed[0]["endpoint_count"] == 2

    missing = client.post(
        f"/api/v1/targets/{target_id}/baselines", json={"source": "upload"}, headers=headers
    )
    assert missing.status_code == 422
    not_a_spec = client.post(
        f"/api/v1/targets/{target_id}/baselines",
        json={"source": "upload", "content": json.dumps({"paths": {}})},
        headers=headers,
    )
    assert not_a_spec.status_code == 422
    assert not_a_spec.json()["error"]["code"] == "invalid_baseline"

    empty_spec = client.post(
        f"/api/v1/targets/{target_id}/baselines",
        json={"source": "upload", "content": json.dumps({"openapi": "3.0.0", "paths": {}})},
        headers=headers,
    )
    assert empty_spec.status_code == 422


def test_baseline_url_fetch_is_subject_to_the_egress_policy(analyst_client):
    client, headers, env = analyst_client
    target_id = env["target"]["id"]
    blocked = client.post(
        f"/api/v1/targets/{target_id}/baselines",
        json={"source": "url", "url": "http://169.254.169.254/latest/meta-data/"},
        headers=headers,
    )
    assert blocked.status_code == 422
    assert "fetched safely" in blocked.json()["error"]["message"]

    no_url = client.post(
        f"/api/v1/targets/{target_id}/baselines", json={"source": "url"}, headers=headers
    )
    assert no_url.status_code == 422


def test_har_import_counts_scope_and_rejects_bad_uploads(analyst_client):
    client, headers, env = analyst_client
    target_id = env["target"]["id"]
    har = json.dumps(
        {
            "log": {
                "version": "1.2",
                "entries": [
                    {"request": {"method": "GET", "url": "http://127.0.0.1:8099/api/v1/users"}},
                    {"request": {"method": "POST", "url": "http://127.0.0.1:8099/api/v1/orders"}},
                    {"request": {"method": "GET", "url": "https://elsewhere.example.net/api/v1/users"}},
                ],
            }
        }
    )
    imported = client.post(
        f"/api/v1/targets/{target_id}/har", content=har, headers={**headers, "X-Har-Name": "capture.har"}
    )
    assert imported.status_code == 200, imported.text
    body = imported.json()
    assert body["entries_total"] == 3
    assert body["entries_in_scope"] == 2
    assert body["entries_out_of_scope"] == 1
    assert body["endpoints_found"] >= 2

    assert client.post(f"/api/v1/targets/{target_id}/har", content=b"", headers=headers).status_code == 422
    bad = client.post(f"/api/v1/targets/{target_id}/har", content=b"{not json", headers=headers)
    assert bad.status_code == 422
    assert bad.json()["error"]["code"] == "invalid_har"


def test_har_import_enforces_the_upload_limit(analyst_client, monkeypatch):
    client, headers, env = analyst_client
    from app.config import reset_settings_cache

    monkeypatch.setenv("ST_MAX_UPLOAD_BYTES", "16")
    reset_settings_cache()
    try:
        response = client.post(
            f"/api/v1/targets/{env['target']['id']}/har",
            content=json.dumps({"log": {"version": "1.2", "entries": [{"request": {}}]}}),
            headers=headers,
        )
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "payload_too_large"
    finally:
        reset_settings_cache()


def test_target_verification_succeeds_only_with_the_issued_token(analyst_client, monkeypatch):
    client, headers, _env = analyst_client
    from app.config import reset_settings_cache

    server, handler = _serve(b"placeholder")
    port = server.server_address[1]
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port}")
    reset_settings_cache()
    # hosts are unique per organization, so retire the seeded loopback target first
    with db() as conn:
        conn.execute("DELETE FROM targets")
    try:
        created = client.post(
            "/api/v1/targets",
            json={
                "name": "Verification Lab",
                "base_url": f"http://127.0.0.1:{port}",
                "ports": [port],
                "authorization_mode": "ownership",
                "attestation": "Loopback fixture used to exercise the ownership challenge.",
            },
            headers=headers,
        )
        assert created.status_code in {200, 201}, created.text
        target = created.json()["target"]
        assert target["authorization_status"] == "pending"

        # The fixture answers with the wrong body first: verification must stay false.
        failed = client.post(f"/api/v1/targets/{target['id']}/verify", headers=headers)
        assert failed.status_code == 200
        assert failed.json()["verified"] is False
        assert failed.json()["target"]["authorization_status"] == "pending"

        handler.body = target["verification_token"].encode()
        succeeded = client.post(f"/api/v1/targets/{target['id']}/verify", headers=headers)
        assert succeeded.json()["verified"] is True
        assert succeeded.json()["target"]["authorization_status"] == "approved"
        assert handler.seen[-1] == "/.well-known/shadowtrace-verification.txt"
    finally:
        server.shutdown()
        server.server_close()
        reset_settings_cache()


def test_target_verification_fails_closed_when_the_host_is_unreachable(analyst_client):
    client, headers, env = analyst_client
    # Nothing listens on the conftest target's port; the probe must not raise.
    response = client.post(f"/api/v1/targets/{env['target']['id']}/verify", headers=headers)
    assert response.status_code == 200
    assert response.json()["verified"] is False
