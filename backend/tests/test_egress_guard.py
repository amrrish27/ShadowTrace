"""The private-egress guard: only the operator may send the scanner into private space.

Regression origin (reported in review): a canary on `127.0.0.1:9999` that was **not** in
`ST_PRIVATE_ALLOWLIST` received 10 requests from a scan. `SafeHttpClient._preflight`
concatenated the operator allow-list with `target_ports` — the ports declared on the
target record — and handed the result to `validate_destination`, whose allow-list branch
skips the private-address check. Anyone who could create (and, with `admin` mode,
self-approve) a target could therefore aim the scanner at loopback or RFC1918 services and
keep the responses as evidence, contradicting README/HARDENING/known-issues C12.

The fix separates the two permissions: `private_allowlist` (operator configuration) is the
only thing that permits a non-public address, while `declared_ports` only relaxes the
*port* rule. Target creation additionally refuses a private host that is not allow-listed,
so the refusal happens before any scan is queued.
"""
from __future__ import annotations

import dataclasses
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List

import pytest

from app.config import get_settings
from app.engine.safe_http import BlockedRequest, SafeHttpClient
from app.engine.scope import ScopePolicy
from app.engine.urlguard import BlockedDestination, validate_destination

PUBLIC_IP = "93.184.216.34"


class StubResolver:
    """Deterministic DNS: no network, and a public address unless told otherwise."""

    def __init__(self, mapping: Dict[str, object] | None = None) -> None:
        self.mapping = mapping or {}
        self.calls: List[tuple[str, int]] = []

    def resolve(self, host: str, port: int):
        self.calls.append((host, port))
        value = self.mapping.get(host, [PUBLIC_IP])
        if isinstance(value, Exception):
            raise value
        return value  # type: ignore[return-value]


class Canary:
    """A request-counting HTTP server: proof of whether a connection was attempted."""

    def __init__(self) -> None:
        self.paths: List[str] = []
        canary = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # noqa: A003
                return

            def do_GET(self):  # noqa: N802
                canary.paths.append(self.path)
                body = b'{"Secret":"internal-only"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture()
def canary():
    server = Canary()
    yield server
    server.close()


def _settings(**overrides):
    return dataclasses.replace(
        get_settings(),
        scanning_enabled=overrides.pop("scanning_enabled", True),
        max_response_bytes=1024 * 1024,
        private_allowlist=overrides.pop("private_allowlist", ()),
    )


# ---------------------------------------------------------------- the reported exploit


def test_target_declared_ports_cannot_unlock_a_private_destination(canary):
    """The exact reported path: declared port, empty operator allow-list, loopback target."""
    client = SafeHttpClient(
        _settings(private_allowlist=()),
        scope=ScopePolicy.build(host="127.0.0.1", ports=[canary.port]),
        target_ports=(("127.0.0.1", canary.port),),
        resolver=StubResolver({"127.0.0.1": ["127.0.0.1"]}),
        rate_per_second=0,
    )
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{canary.port}/admin/users")
    assert canary.paths == [], "a private destination must never receive a request"
    assert client.blocked_attempts, "the refusal is recorded for the scan event log"


@pytest.mark.parametrize("host, address", [
    ("internal.example.test", "10.0.0.5"),
    ("internal.example.test", "192.168.1.10"),
    ("internal.example.test", "172.16.4.4"),
    ("internal.example.test", "fd00::1"),
    ("internal.example.test", "169.254.169.254"),
])
def test_declared_ports_cannot_unlock_any_private_range(host, address):
    """A hostname that resolves into private space is blocked just like a literal."""
    client = SafeHttpClient(
        _settings(private_allowlist=()),
        target_ports=((host, 8443),),
        resolver=StubResolver({host: [address]}),
        rate_per_second=0,
    )
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://{host}:8443/")


def test_the_operator_allow_list_is_still_the_one_way_in(canary):
    """Lab mode keeps working: an explicit operator entry permits exactly that pair."""
    client = SafeHttpClient(
        _settings(private_allowlist=(("127.0.0.1", canary.port),)),
        scope=ScopePolicy.build(host="127.0.0.1", ports=[canary.port]),
        target_ports=(("127.0.0.1", canary.port),),
        resolver=StubResolver({"127.0.0.1": ["127.0.0.1"]}),
        rate_per_second=0,
    )
    assert client.request("GET", f"http://127.0.0.1:{canary.port}/ok").status == 200
    assert canary.paths == ["/ok"]


def test_an_allow_listed_pair_does_not_open_the_same_host_on_another_port(canary):
    """The grant is an exact host:port pair, never the host or a range."""
    other = canary.port + 1
    client = SafeHttpClient(
        _settings(private_allowlist=(("127.0.0.1", canary.port),)),
        target_ports=(("127.0.0.1", other),),
        resolver=StubResolver({"127.0.0.1": ["127.0.0.1"]}),
        rate_per_second=0,
    )
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{other}/ok")
    assert canary.paths == []


def test_metadata_stays_blocked_even_when_operator_allow_listed():
    """`is_always_blocked` is checked before the allow-list grant, by design."""
    client = SafeHttpClient(
        _settings(private_allowlist=(("metadata.internal", 80),)),
        target_ports=(("metadata.internal", 80),),
        resolver=StubResolver({"metadata.internal": ["169.254.169.254"]}),
        rate_per_second=0,
    )
    with pytest.raises(BlockedRequest):
        client.request("GET", "http://metadata.internal/latest/meta-data/")


# --------------------------------------------------- declared ports still do their job


def test_a_declared_port_authorises_a_public_destination_without_operator_config():
    """The legitimate reason `declared_ports` exists: a public target on port 8443."""
    approved = validate_destination(
        "https://api.example.test:8443/v1",
        StubResolver({"api.example.test": [PUBLIC_IP]}),
        declared_ports=(("api.example.test", 8443),),
    )
    assert approved.url.port == 8443
    assert approved.addresses == (PUBLIC_IP,)


def test_an_undeclared_port_is_still_refused_for_a_public_destination():
    with pytest.raises(BlockedDestination) as excinfo:
        validate_destination(
            "https://api.example.test:8443/v1",
            StubResolver({"api.example.test": [PUBLIC_IP]}),
            declared_ports=(),
        )
    assert excinfo.value.reason == "port_not_allowed"


def test_a_declared_port_never_relaxes_the_address_rule():
    """The heart of the fix: port permission and address permission are independent."""
    with pytest.raises(BlockedDestination) as excinfo:
        validate_destination(
            "http://internal.example.test:8443/",
            StubResolver({"internal.example.test": ["10.0.0.5"]}),
            declared_ports=(("internal.example.test", 8443),),
        )
    assert excinfo.value.reason == "blocked_address"


def test_one_private_answer_among_public_ones_blocks_the_destination():
    """DNS with a mix of answers must fail closed."""
    with pytest.raises(BlockedDestination):
        validate_destination(
            "http://api.example.test:8443/",
            StubResolver({"api.example.test": [PUBLIC_IP, "10.0.0.5"]}),
            declared_ports=(("api.example.test", 8443),),
        )


# ------------------------------------------------------------- creation-time refusal


PRIVATE_BASE_URLS = [
    "http://127.0.0.1:9999",
    "http://localhost:9999",
    "http://10.0.0.5",
    "http://192.168.1.10",
    "http://172.16.4.4",
    "http://[::1]:9999",
]


def _clear_targets() -> None:
    """Hosts are unique per organization; the seeded loopback target would mask the check."""
    from app.db import db

    with db() as conn:
        conn.execute("DELETE FROM targets")


@pytest.mark.parametrize("base_url", PRIVATE_BASE_URLS)
@pytest.mark.parametrize("mode", ["ownership", "admin", "lab_allowlist"])
def test_private_targets_are_refused_without_an_allow_list_entry(admin_client, base_url, mode):
    """No authorization mode makes a private destination acceptable without operator consent."""
    client, headers, _env = admin_client
    _clear_targets()
    response = client.post(
        "/api/v1/targets",
        json={
            "name": f"Private {mode}",
            "base_url": base_url,
            "ports": [9999, 80, 443],
            "authorization_mode": mode,
            "attestation": "Operator-owned lab target used for the egress regression suite.",
        },
        headers=headers,
    )
    assert response.status_code == 422, (base_url, mode, response.text)
    body = response.json()["error"]
    assert body["code"] == "invalid_target"
    # `lab_allowlist` mode refuses earlier, with its own allow-list message; both are the
    # same decision — a private destination needs operator consent.
    assert "allow-list" in body["message"] or "ST_PRIVATE_ALLOWLIST" in body["message"]


def test_the_metadata_address_is_refused_even_when_allow_listed(admin_client, monkeypatch):
    """169.254.169.254 is rejected by `canonicalize` before the allow-list is consulted."""
    from app.config import reset_settings_cache

    client, headers, _env = admin_client
    _clear_targets()
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", "169.254.169.254:80")
    reset_settings_cache()
    try:
        response = client.post(
            "/api/v1/targets",
            json={
                "name": "Metadata",
                "base_url": "http://169.254.169.254",
                "ports": [80],
                "authorization_mode": "lab_allowlist",
                "attestation": "Attempt to register the cloud metadata endpoint as a target.",
            },
            headers=headers,
        )
    finally:
        monkeypatch.delenv("ST_PRIVATE_ALLOWLIST", raising=False)
        reset_settings_cache()
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "invalid_target"
    assert "metadata" in error["message"], "the refusal must name the metadata rule"


def test_an_allow_listed_private_target_is_still_created(admin_client, monkeypatch):
    """Lab mode is unchanged for the operator who actually configured it."""
    from app.config import reset_settings_cache

    client, headers, env = admin_client
    _clear_targets()
    port = 8099
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port}")
    reset_settings_cache()
    try:
        created = client.post(
            "/api/v1/targets",
            json={
                "name": "Allow-listed Lab",
                "base_url": f"http://127.0.0.1:{port}",
                "ports": [port],
                "authorization_mode": "lab_allowlist",
                "attestation": "Operator allow-listed lab target for the egress regression suite.",
            },
            headers=headers,
        )
        assert created.status_code == 200, created.text
        assert created.json()["target"]["authorization_status"] == "approved"
    finally:
        monkeypatch.delenv("ST_PRIVATE_ALLOWLIST", raising=False)
        reset_settings_cache()


def test_a_public_target_is_unaffected(admin_client):
    client, headers, _env = admin_client
    _clear_targets()
    created = client.post(
        "/api/v1/targets",
        json={
            "name": "Public Target",
            "base_url": "https://api.public.example.test",
            "ports": [443],
            "authorization_mode": "admin",
            "attestation": "Operator owns this public target; egress regression suite.",
        },
        headers=headers,
    )
    assert created.status_code == 200, created.text
    assert created.json()["target"]["authorization_status"] == "approved"
