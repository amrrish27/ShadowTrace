"""Security helpers: redaction, password policy, tokens and HTTP hardening."""
from __future__ import annotations

import json

import pytest

from app.security.middleware import host_allowed
from app.security.passwords import (
    WeakPassword,
    constant_time_equals,
    generate_password,
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)
from app.security.redaction import (
    audit_redact,
    contains_secret,
    make_snippet,
    redact_headers,
    redact_har_entry,
    redact_text,
    redact_url,
    secret_kinds,
)
from app.security.tokens import generate_token, hash_token, tokens_equal, verification_token

PASSWORD = "Correct-Horse-Battery-9!"


# ---------------------------------------------------------------- redaction


def test_redaction_masks_well_known_secret_shapes():
    samples = {
        "aws": "AKIAIOSFODNN7EXAMPLE",
        "github": "ghp_" + "a" * 36,
        "slack": "xoxb-1234-5678-abcdefghij",
        "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signaturepart",
        "bearer": "Authorization: Bearer abcdef1234567890abcdef",
        "private_key": (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----"
        ),
    }
    for kind, value in samples.items():
        redacted = redact_text(value)
        assert "REDACTED" in redacted.upper() or redacted != value, kind
        assert contains_secret(value)


def test_secret_kinds_reports_names_only():
    kinds = secret_kinds("AKIAIOSFODNN7EXAMPLE and ghp_" + "b" * 36)
    assert kinds
    assert all("AKIA" not in kind for kind in kinds)
    assert secret_kinds("nothing secret here") == []


def test_redact_headers_drops_sensitive_values():
    headers = {
        "Authorization": "Bearer abcdef1234567890",
        "Cookie": "st_session=supersecretvalue",
        "Set-Cookie": "st_session=abc",
        "X-Api-Key": "key-1234567890",
        "Content-Type": "application/json",
        "Server": "Lab/1.0",
    }
    redacted = redact_headers(headers)
    assert redacted["Content-Type"] == "application/json"
    assert redacted["Server"] == "Lab/1.0"
    for key in ("Authorization", "Cookie", "Set-Cookie", "X-Api-Key"):
        assert "REDACTED" in redacted[key].upper()


def test_redact_url_masks_query_secrets():
    assert "REDACTED" in redact_url("https://api.test/x?api_key=abcdef123456&page=2").upper()
    assert redact_url("https://api.test/x?page=2").endswith("page=2")


def test_snippet_is_bounded_and_redacted():
    snippet = make_snippet("token=AKIAIOSFODNN7EXAMPLE " + "x" * 5000, 120)
    assert len(snippet) <= 200
    assert "AKIAIOSFODNN7EXAMPLE" not in snippet


def test_redact_har_entry_handles_both_header_shapes():
    entry = {
        "request": {
            "url": "https://api.test/x?token=abcdef1234567890",
            "headers": [
                {"name": "Cookie", "value": "st_session=abc"},
                {"name": "Accept", "value": "*/*"},
            ],
        },
        "response": {
            "headers": {"Set-Cookie": "st_session=abc", "Content-Type": "application/json"},
            "content": {"text": "AKIAIOSFODNN7EXAMPLE"},
        },
    }
    redacted = redact_har_entry(entry)
    dumped = json.dumps(redacted)
    assert "st_session=abc" not in dumped
    assert "AKIAIOSFODNN7EXAMPLE" not in dumped
    assert "abcdef1234567890" not in dumped
    assert redacted["response"]["headers"]["Content-Type"] == "application/json"


def test_audit_redaction_never_leaks_values():
    payload = {"email": "a@b.test", "token": "abc123", "password": PASSWORD, "nested": {"api_key": "k"}}
    redacted = audit_redact(payload)
    dumped = json.dumps(redacted)
    assert PASSWORD not in dumped
    assert "abc123" not in dumped
    assert redacted["email"] == "a@b.test"


# ---------------------------------------------------------------- passwords


def test_password_policy_accepts_strong_and_rejects_weak():
    validate_password(PASSWORD, email="analyst@org.example.test")
    for weak in (
        "short",
        "passwordpassword",
        "12345678901234",
        "aaaaaaaaaaaaaaaaa",
        "Correct-Horse-Battery-9!".lower().replace("!", "")  # equal to the email local part? no
        if False
        else "analystanalystanalyst",
    ):
        with pytest.raises(WeakPassword):
            validate_password(weak, email="analyst@org.example.test", name="Analyst")


def test_password_policy_rejects_identity_material():
    with pytest.raises(WeakPassword):
        validate_password("analyst@org.example.test", email="analyst@org.example.test")
    with pytest.raises(WeakPassword):
        validate_password("Analyzt", name="Analyzt")
    # Merely containing the name is acceptable; only equality is refused.
    validate_password("Analyzt-Unique-Name-1!", name="Analyzt")


def test_hashing_is_salted_and_verifiable():
    first = hash_password(PASSWORD)
    second = hash_password(PASSWORD)
    assert first != second
    assert PASSWORD not in first
    assert verify_password(PASSWORD, first)
    assert not verify_password(PASSWORD + "x", first)
    # Unknown users still cost a verification, and a missing hash never verifies.
    assert not verify_password(PASSWORD, None)
    assert needs_rehash("{md5}abc") is True
    assert needs_rehash(first) is False


def test_generated_passwords_are_random_and_strong():
    values = {generate_password() for _ in range(5)}
    assert len(values) == 5
    for value in values:
        assert len(value) >= 20
        validate_password(value)


def test_constant_time_equals():
    assert constant_time_equals("abc", "abc")
    assert not constant_time_equals("abc", "abd")
    assert not constant_time_equals("abc", "abcd")


# ---------------------------------------------------------------- tokens


def test_tokens_are_random_and_hashed_for_storage():
    token = generate_token()
    assert len(token) >= 40
    assert generate_token() != token
    digest = hash_token(token)
    assert len(digest) == 64
    assert token not in digest
    assert tokens_equal(digest, hash_token(token))
    assert not tokens_equal(digest, hash_token(token + "x"))
    verify = verification_token()
    assert verify.startswith("shadowtrace-verify-")
    assert generate_token(8) != generate_token(8)


# ---------------------------------------------------------------- host allow-list


def test_host_allowlist_matching():
    allowed = ("app.shadowtrace.test", "localhost", "127.0.0.1")
    assert host_allowed("app.shadowtrace.test", allowed)
    assert host_allowed("app.shadowtrace.test:8443", allowed)
    assert host_allowed("LOCALHOST:8099", allowed)
    assert not host_allowed("evil.test", allowed)
    assert not host_allowed("app.shadowtrace.test.evil.test", allowed)
    assert not host_allowed("", allowed)


# ---------------------------------------------------------------- response hardening


def test_security_headers_and_request_id(client, app_env):
    response = client.get("/api/v1/health")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] in {"DENY", "SAMEORIGIN"}
    assert "content-security-policy" in response.headers
    assert response.headers["referrer-policy"]
    assert response.headers["x-request-id"]
    # A well-formed caller id is echoed, anything else is replaced by a fresh id.
    supplied = client.get("/api/v1/health", headers={"X-Request-ID": "abc-123-def-456"})
    assert supplied.headers["x-request-id"] == "abc-123-def-456"
    for hostile_value in ("abc", "x" * 400, "id with spaces"):
        generated = client.get("/api/v1/health", headers={"X-Request-ID": hostile_value})
        assert generated.headers["x-request-id"] != hostile_value
        assert len(generated.headers["x-request-id"]) >= 8


def test_unknown_host_is_rejected(client, app_env):
    response = client.get("/api/v1/health", headers={"Host": "evil.example.net"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "bad_request"


def test_body_limit_is_enforced(client, app_env):
    from app.config import get_settings

    limit = get_settings().max_upload_bytes
    oversized = b"{" + b'"x": "' + b"a" * (limit + 1024) + b'"}'
    response = client.post(
        "/api/v1/auth/login",
        content=oversized,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code in {413, 400}
    assert response.json()["error"]["code"] in {"payload_too_large", "bad_request"}


def test_api_404_is_json_not_spa_shell(client, app_env):
    response = client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_scanning_kill_switch_blocks_scan_creation(analyst_client, monkeypatch):
    client, headers, env = analyst_client
    from app.config import get_settings, reset_settings_cache

    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    monkeypatch.delenv("SCANNING_ENABLED", raising=False)
    reset_settings_cache()
    assert get_settings().scanning_enabled is False
    response = client.post(
        "/api/v1/scans",
        json={"target_id": env["target"]["id"], "attestation": "Kill switch regression test."},
        headers={**headers, "Idempotency-Key": "kill-switch-0001"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "scanning_disabled"
    reset_settings_cache()
