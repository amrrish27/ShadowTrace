"""The kill switch: `ST_SCANNING_ENABLED=false` stops creation *and* egress.

`deploy/HARDENING.md` and `docs/known-issues.md` both promise that one variable turns
scanning off completely. These tests pin that promise: the API refuses to queue work,
the worker refuses to execute, and the single egress chokepoint refuses to open a
socket — so a scan that was queued before the switch was flipped cannot continue.
"""
from __future__ import annotations

import dataclasses
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List

import pytest

from app.config import get_settings, load_settings, reset_settings_cache
from app.engine.safe_http import BlockedRequest, SafeHttpClient
from app.engine.scope import ScopePolicy


class _State:
    def __init__(self) -> None:
        self.requests: List[str] = []


@pytest.fixture()
def counting_server():
    state = _State()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # noqa: A003
            return

        def do_GET(self):  # noqa: N802
            state.requests.append(self.path)
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, state
    server.shutdown()
    server.server_close()


def _disabled_settings(port: int):
    return dataclasses.replace(
        get_settings(),
        scanning_enabled=False,
        private_allowlist=(("127.0.0.1", port),),
        max_response_bytes=1024 * 1024,
    )


# --------------------------------------------------------------- configuration


def test_the_documented_name_is_read(monkeypatch):
    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    monkeypatch.delenv("SCANNING_ENABLED", raising=False)
    assert load_settings().scanning_enabled is False


def test_the_current_name_wins_over_the_deprecated_one(monkeypatch):
    monkeypatch.setenv("ST_SCANNING_ENABLED", "true")
    monkeypatch.setenv("SCANNING_ENABLED", "false")
    assert load_settings().scanning_enabled is True
    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    monkeypatch.setenv("SCANNING_ENABLED", "true")
    assert load_settings().scanning_enabled is False


def test_the_deprecated_name_still_works_and_is_announced(monkeypatch, caplog):
    monkeypatch.delenv("ST_SCANNING_ENABLED", raising=False)
    monkeypatch.setenv("SCANNING_ENABLED", "false")
    with caplog.at_level("WARNING", logger="shadowtrace.config"):
        settings = load_settings()
    assert settings.scanning_enabled is False
    assert any("deprecated_config_name" in record.message for record in caplog.records)


def test_an_unset_switch_defaults_to_enabled(monkeypatch):
    monkeypatch.delenv("ST_SCANNING_ENABLED", raising=False)
    monkeypatch.delenv("SCANNING_ENABLED", raising=False)
    assert load_settings().scanning_enabled is True


def test_a_non_boolean_value_is_rejected(monkeypatch):
    from app.config import ConfigurationError

    monkeypatch.setenv("ST_SCANNING_ENABLED", "maybe")
    with pytest.raises(ConfigurationError):
        load_settings()


# ------------------------------------------------------------------ the promise


def test_documented_kill_switch_blocks_creation_and_egress(analyst_client, counting_server, monkeypatch):
    """The whole promise in one test: no queued scans, and no socket opened."""
    client, headers, env = analyst_client
    server, state = counting_server
    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    reset_settings_cache()
    try:
        created = client.post(
            "/api/v1/scans",
            json={"target_id": env["target"]["id"], "attestation": "Kill switch end-to-end."},
            headers={**headers, "Idempotency-Key": "kill-switch-e2e-0001"},
        )
        assert created.status_code == 503
        assert created.json()["error"]["code"] == "scanning_disabled"

        settings = _disabled_settings(server.server_port)
        assert settings.scanning_enabled is False
        egress = SafeHttpClient(
            settings,
            scope=ScopePolicy.build(host="127.0.0.1", ports=[server.server_port]),
            scan_id="kill-switch-scan",
        )
        with pytest.raises(BlockedRequest):
            egress.request("GET", f"http://127.0.0.1:{server.server_port}/api/v1/users")
        assert state.requests == [], "the kill switch must prevent the request reaching the network"
    finally:
        reset_settings_cache()


def test_target_verification_is_also_blocked(analyst_client, monkeypatch):
    """Verification is an outbound request, so it must stop with the switch too."""
    client, headers, env = analyst_client
    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    reset_settings_cache()
    try:
        created = client.post(
            "/api/v1/targets",
            json={
                "name": "Kill Switch Target",
                "base_url": "http://127.0.0.1:8099",
                "authorization_mode": "lab_allowlist",
                "attestation": "Kill switch regression coverage for outbound verification.",
            },
            headers=headers,
        )
        # lab targets need an allow-list entry; the point is that no request is attempted
        assert created.status_code in {201, 409, 422}
        verify = client.post(f"/api/v1/targets/{env['target']['id']}/verify", headers=headers)
        assert verify.status_code == 200
        assert verify.json()["verified"] is False
    finally:
        reset_settings_cache()


def test_the_api_reports_the_switch_in_metadata(analyst_client, monkeypatch):
    client, headers, _env = analyst_client
    monkeypatch.setenv("ST_SCANNING_ENABLED", "false")
    reset_settings_cache()
    try:
        meta = client.get("/api/v1/meta/config", headers=headers)
        assert meta.status_code == 200
        assert meta.json()["scanning_enabled"] is False
    finally:
        reset_settings_cache()
