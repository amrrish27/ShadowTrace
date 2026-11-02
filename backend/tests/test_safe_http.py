"""SSRF-06..SSRF-16: SafeHttpClient controls against a local counting server."""
from __future__ import annotations

import dataclasses
import gzip
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List

import pytest

from app.config import get_settings
from app.engine.safe_http import (
    MAX_REDIRECTS,
    ResponseData,
    BlockedRequest,
    BudgetExceeded,
    RequestBudget,
    ResponseTimeout,
    ResponseTooLarge,
    SafeHttpClient,
    ScanCancelled,
    TargetRequestError,
)
from app.engine.scope import ScopePolicy


class _State:
    def __init__(self) -> None:
        self.requests: List[Dict[str, str]] = []


def _make_server(state: _State) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # noqa: A003
            return

        def _send(self, status: int, body: bytes, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            state.requests.append(
                {
                    "path": self.path,
                    "host": self.headers.get("Host", ""),
                    "ua": self.headers.get("User-Agent", ""),
                    "scan": self.headers.get("X-ShadowTrace-Scan", ""),
                    "custom": self.headers.get("X-Custom", ""),
                    "long": self.headers.get("X-Too-Long", ""),
                }
            )
            if self.path.startswith("/ok"):
                self._send(200, b'{"ok": true}')
            elif self.path.startswith("/redirect/metadata"):
                self._send(302, b"", {"Location": "http://169.254.169.254/latest/meta-data/"})
            elif self.path.startswith("/redirect/loopback"):
                self._send(302, b"", {"Location": f"http://127.0.0.1:{self.server.server_port}/ok"})
            elif self.path.startswith("/redirect/cross"):
                self._send(302, b"", {"Location": "https://example.com/"})
            elif self.path.startswith("/redirect/loop"):
                self._send(302, b"", {"Location": "/redirect/loop"})
            elif self.path.startswith("/redirect/downgrade"):
                self._send(302, b"", {"Location": "http://example.com/"})
            elif self.path.startswith("/big"):
                self._send(200, b"B" * (2 * 1024 * 1024))
            elif self.path.startswith("/headers"):
                extra = {f"X-Pad-{index}": "P" * 900 for index in range(80)}
                self._send(200, b"{}", extra)
            elif self.path.startswith("/slow"):
                time.sleep(1.0)
                self._send(200, b'{"slow": true}')
            elif self.path.startswith("/gzip"):
                payload = gzip.compress(b"\x00" * (8 * 1024 * 1024))
                self._send(200, payload, {"Content-Content": "x", "Content-Encoding": "gzip"})
            elif self.path.startswith("/status/429"):
                self._send(429, b"{}")
            else:
                self._send(404, b"{}")

        def do_HEAD(self):  # noqa: N802
            state.requests.append(
                {
                    "path": self.path,
                    "host": self.headers.get("Host", ""),
                    "ua": self.headers.get("User-Agent", ""),
                    "scan": self.headers.get("X-ShadowTrace-Scan", ""),
                }
            )
            self._send(200, b"")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture()
def counting_server():
    state = _State()
    server = _make_server(state)
    yield server, state
    server.shutdown()
    server.server_close()


def _settings(port: int, **overrides):
    base = get_settings()
    allow = ((("127.0.0.1", port),) if not overrides.pop("no_allow", False) else ())
    return dataclasses.replace(
        base,
        scanning_enabled=overrides.pop("scanning_enabled", True),
        max_response_bytes=overrides.pop("max_response_bytes", 1024 * 1024),
        private_allowlist=allow,
    )


def _client(server, state, **kwargs):
    port = server.server_port
    scope = ScopePolicy.build(host="127.0.0.1", ports=[port])
    return SafeHttpClient(
        _settings(port, **{k: v for k, v in kwargs.items() if k in {"scanning_enabled", "max_response_bytes"}}),
        scope=scope,
        budget=kwargs.get("budget"),
        scan_id=kwargs.get("scan_id", "scan-123"),
        cancel_check=kwargs.get("cancel_check"),
        rate_per_second=kwargs.get("rate_per_second", 0),
        target_ports=kwargs.get("target_ports", ()),
        read_timeout=kwargs.get("read_timeout", 5.0),
        sleep=kwargs.get("sleep", lambda seconds: None),
        clock=kwargs.get("clock", time.monotonic),
    )


def test_request_identifies_scanner(counting_server):
    server, state = counting_server
    client = _client(server, state)
    response = client.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    assert response.status == 200
    assert response.text == '{"ok": true}'
    recorded = state.requests[-1]
    assert recorded["ua"].startswith("ShadowTrace/")
    assert "+http" in recorded["ua"]
    assert recorded["scan"] == "scan-123"


def test_budget_is_enforced(counting_server):
    server, state = counting_server
    budget = RequestBudget(limit=2)
    client = _client(server, state, budget=budget)
    base = f"http://127.0.0.1:{server.server_port}/ok"
    client.request("GET", base)
    client.request("GET", base)
    with pytest.raises(BudgetExceeded):
        client.request("GET", base)
    assert len(state.requests) == 2


def test_kill_switch_blocks_all_requests(counting_server):
    server, state = counting_server
    client = _client(server, state, scanning_enabled=False)
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    assert state.requests == []


def test_cancellation_blocks_new_requests(counting_server):
    server, state = counting_server
    client = _client(server, state, cancel_check=lambda: True)
    with pytest.raises(ScanCancelled):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    assert state.requests == []


def test_redirect_to_metadata_is_not_followed(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/redirect/metadata")
    assert len(state.requests) == 1


def test_cross_origin_redirect_is_blocked(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/redirect/cross")
    assert len(state.requests) == 1


def test_redirect_loop_terminates(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(TargetRequestError):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/redirect/loop")
    assert len(state.requests) <= 6


def test_body_limit_aborts_large_response(counting_server):
    server, state = counting_server
    client = _client(server, state, max_response_bytes=256 * 1024)
    with pytest.raises(ResponseTooLarge):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/big")


def test_header_limits_enforced(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(ResponseTooLarge):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/headers")


def test_compression_is_bounded(counting_server):
    server, state = counting_server
    client = _client(server, state, max_response_bytes=64 * 1024)
    with pytest.raises(ResponseTooLarge):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/gzip")


def test_read_timeout(counting_server):
    server, state = counting_server
    client = _client(server, state, read_timeout=0.2)
    with pytest.raises(ResponseTimeout):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/slow")


def test_rate_limit_uses_injected_sleep(counting_server):
    server, state = counting_server
    sleeps = []
    clock = {"now": 0.0}

    def fake_sleep(seconds):
        sleeps.append(seconds)
        clock["now"] += seconds

    client = SafeHttpClient(
        _settings(server.server_port),
        scope=ScopePolicy.build(host="127.0.0.1", ports=[server.server_port]),
        rate_per_second=1.0,
        sleep=fake_sleep,
        clock=lambda: clock["now"],
        connect_timeout=2.0,
        read_timeout=2.0,
    )
    base = f"http://127.0.0.1:{server.server_port}/ok"
    client.request("GET", base)
    client.request("GET", base)
    assert sleeps and sleeps[0] >= 0


def test_connection_is_pinned_to_validated_ip():
    """The Host header and SNI keep the hostname while the socket goes to the pinned IP."""

    class Resolver:
        def __init__(self):
            self.answers = ["127.0.0.1"]

        def resolve(self, host, port):
            return self.answers

    state = _State()
    server = _make_server(state)
    resolver = Resolver()
    settings = dataclasses.replace(
        get_settings(), private_allowlist=(("rebind.test", server.server_port),), max_response_bytes=1024 * 1024
    )
    client = SafeHttpClient(
        settings,
        resolver=resolver,
        scope=ScopePolicy.build(host="rebind.test", ports=[server.server_port]),
        rate_per_second=0,
    )
    # "rebind.test" is not resolvable via system DNS, so a successful request proves the socket
    # went to the validated address rather than a fresh lookup of the hostname.
    response = client.request("GET", f"http://rebind.test:{server.server_port}/ok")
    assert response.status == 200
    assert state.requests[-1]["host"].startswith("rebind.test")
    served = len(state.requests)
    # A rebinding answer is revalidated on every request: a flipped link-local (metadata) address
    # is refused even for an allow-listed host, so the target server never sees a second request.
    resolver.answers = ["169.254.169.254"]
    with pytest.raises((BlockedRequest, TargetRequestError)):
        client.request("GET", f"http://rebind.test:{server.server_port}/ok")
    assert len(state.requests) == served
    server.shutdown()
    server.server_close()


def test_scope_is_enforced(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{server.server_port + 1}/ok")
    assert state.requests == []


def test_target_declared_port_is_authorized(counting_server):
    """A port declared on the target record is allowed for an operator-permitted host.

    Note the operator allow-list entry: `_settings()` supplies it, and it must be there —
    a declared port relaxes the *port* rule only and can never authorize private space by
    itself (see `test_egress_guard.py`, which pins that).
    """
    server, state = counting_server
    port = server.server_port
    scope = ScopePolicy.build(host="127.0.0.1", ports=[port])
    client = SafeHttpClient(
        _settings(port),
        scope=scope,
        target_ports=(("127.0.0.1", port),),
        rate_per_second=0,
    )
    assert client.request("GET", f"http://127.0.0.1:{port}/ok").status == 200
    assert len(state.requests) == 1


def test_undeclared_port_is_blocked_even_for_the_target_host(counting_server):
    server, state = counting_server
    port = server.server_port
    client = SafeHttpClient(
        _settings(port),
        scope=ScopePolicy.build(host="127.0.0.1", ports=[port]),
        target_ports=(("127.0.0.1", port),),
        rate_per_second=0,
    )
    with pytest.raises(BlockedRequest):
        client.request("GET", "http://127.0.0.1:9/ok")
    assert state.requests == []


def test_target_ports_never_authorize_metadata(counting_server):
    server, _state = counting_server
    port = server.server_port

    class Resolver:
        def resolve(self, host, port):
            return ["169.254.169.254"]

    client = SafeHttpClient(
        _settings(port),
        resolver=Resolver(),
        scope=ScopePolicy.build(host="metadata.internal", ports=[port]),
        target_ports=(("metadata.internal", port),),
        rate_per_second=0,
    )
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://metadata.internal:{port}/latest/meta-data/")


# ------------------------------------------------------- unit-level coverage


def test_budget_accounting():
    budget = RequestBudget(3)
    assert budget.remaining == 3
    budget.consume()
    budget.consume()
    assert budget.remaining == 1
    budget.consume()
    assert budget.remaining == 0
    with pytest.raises(BudgetExceeded):
        budget.consume()


def test_response_data_helpers():
    from app.engine.safe_http import ResponseData

    plain = ResponseData(url="https://a.test/x", status=200, headers={"content-type": "Text/HTML; charset=utf-8"}, body=b"hi", elapsed_ms=1)
    assert plain.content_type == "text/html"
    assert plain.text == "hi"
    assert plain.body_size == 2

    latin = ResponseData(url="u", status=200, headers={"content-type": "text/plain; charset=iso-8859-1"}, body="é".encode("iso-8859-1"), elapsed_ms=1)
    assert latin.text == "é"

    bogus = ResponseData(url="u", status=200, headers={"content-type": "text/plain; charset=nonsense-charset"}, body=b"ok", elapsed_ms=1)
    assert bogus.text == "ok"  # unknown charset falls back to utf-8 instead of raising

    assert ResponseData(url="u", status=204, headers={}, body=b"", elapsed_ms=0).content_type == ""


def test_head_response_has_no_body(counting_server):
    server, state = counting_server
    client = _client(server, state)
    response = client.request("HEAD", f"http://127.0.0.1:{server.server_port}/ok")
    assert response.status == 200
    assert response.body == b""
    assert state.requests[-1]["path"] == "/ok"


def test_only_safe_methods_are_sent(counting_server):
    server, state = counting_server
    client = _client(server, state)
    for method in ("POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"):
        with pytest.raises(BlockedRequest):
            client.request(method, f"http://127.0.0.1:{server.server_port}/ok")
    assert state.requests == []


def test_https_target_with_plain_http_listener_is_a_target_error(counting_server):
    """A TLS client talking to a cleartext listener must fail closed, never fall back to HTTP."""
    server, state = counting_server
    port = server.server_port
    client = SafeHttpClient(
        _settings(port),
        scope=ScopePolicy.build(host="127.0.0.1", ports=[port]),
        target_ports=(("127.0.0.1", port),),
        rate_per_second=0,
    )
    with pytest.raises(TargetRequestError):
        client.request("GET", f"https://127.0.0.1:{port}/ok")


def test_redirect_loop_and_hop_limit(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(TargetRequestError):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/redirect/loop")
    assert len(state.requests) <= MAX_REDIRECTS + 1


def test_redirect_metadata_hop_is_blocked(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/redirect/metadata")
    # The metadata host was never contacted.
    assert all("169.254.169.254" not in request["host"] for request in state.requests)


def test_oversized_body_aborts_instead_of_truncating(counting_server):
    server, state = counting_server
    client = _client(server, state, max_response_bytes=1024)
    with pytest.raises(ResponseTooLarge):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/big")


def test_kill_switch_and_cancel_are_checked_before_connecting(counting_server):
    server, state = counting_server
    disabled = _client(server, state, scanning_enabled=False)
    with pytest.raises(BlockedRequest):
        disabled.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    cancelled = _client(server, state, cancel_check=lambda: True)
    with pytest.raises(ScanCancelled):
        cancelled.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    assert state.requests == []


def test_throttle_sleeps_between_requests(counting_server):
    server, state = counting_server
    slept: List[float] = []
    client = _client(server, state, rate_per_second=2, sleep=slept.append)
    client.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    client.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    assert slept and all(0 < value <= 5.0 for value in slept)


def test_header_size_limit_is_enforced(counting_server):
    server, state = counting_server
    client = _client(server, state)
    with pytest.raises(ResponseTooLarge):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/headers")


def test_decompression_bomb_is_capped(counting_server):
    server, state = counting_server
    client = _client(server, state, max_response_bytes=4096)
    with pytest.raises((ResponseTooLarge, TargetRequestError)):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/gzip")


def test_invalid_compressed_body_is_a_target_error(counting_server):
    server, state = counting_server
    client = _client(server, state)

    class Broken:
        """Feeds the client a body that claims gzip but is not."""

        def __init__(self):
            from app.engine.safe_http import ResponseData

            self.response = ResponseData(
                url="http://127.0.0.1/",
                status=200,
                headers={"content-encoding": "gzip", "content-type": "text/plain"},
                body=b"not gzip at all",
                elapsed_ms=1,
            )

    with pytest.raises(TargetRequestError):
        client._decode_body(b"not gzip at all", {"content-encoding": "gzip"})
    assert state.requests == []


def test_connection_failure_maps_to_target_error(counting_server):
    server, _state = counting_server
    client = _client(server, _state)
    dead_port = server.server_port + 2
    client.scope = ScopePolicy.build(host="127.0.0.1", ports=[dead_port])
    client.target_ports = (("127.0.0.1", dead_port),)
    # The destination is operator-allow-listed, so the request reaches the socket and the
    # refused connection is what gets mapped — the concern this test actually covers.
    client.settings = dataclasses.replace(
        client.settings, private_allowlist=(("127.0.0.1", dead_port),)
    )
    with pytest.raises(TargetRequestError):
        client.request("GET", f"http://127.0.0.1:{dead_port}/ok")


def test_read_timeout_maps_to_response_timeout(counting_server):
    server, state = counting_server
    client = _client(server, state, read_timeout=0.2)
    with pytest.raises(ResponseTimeout):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/slow")


def test_scope_mismatch_is_reported_as_blocked(counting_server):
    server, state = counting_server
    client = _client(server, state)
    client.scope = ScopePolicy.build(host="other.test", ports=[server.server_port])
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    assert state.requests == []


def test_default_timeout_in_pinned_connection(counting_server):
    """The pinned socket honours http.client's default-timeout sentinel."""
    import socket as socket_module

    from app.engine.safe_http import _PinnedHTTPConnection, _PinnedHTTPSConnection

    plain = _PinnedHTTPConnection("127.0.0.1", 1, "127.0.0.1", 3.0)
    called = {}
    original = socket_module.create_connection

    def fake(address, timeout=None, source_address=None):
        called["args"] = (address, timeout)
        raise OSError("stop here")

    socket_module.create_connection = fake
    try:
        with pytest.raises(OSError):
            plain._pinned_connect(("127.0.0.1", 1))
        assert called["args"][1] == 3.0  # falls back to the configured connect timeout
        tls = _PinnedHTTPSConnection("127.0.0.1", 1, "127.0.0.1", 4.0, __import__("ssl").create_default_context())
        called.clear()
        with pytest.raises(OSError):
            tls._pinned_connect(("127.0.0.1", 1))
        assert called["args"][1] == 4.0
    finally:
        socket_module.create_connection = original


def test_brotli_bodies_are_treated_as_opaque(counting_server):
    server, state = counting_server
    client = _client(server, state)
    body = b"\x1b\x02\x80compressed-brotli"
    assert client._decode_body(body, {"content-encoding": "br"}) == body
    assert client._decode_body(b"", {"content-encoding": "gzip"}) == b""
    assert client._decode_body(b"plain", {}) == b"plain"


def test_deflate_body_is_decoded(counting_server):
    import zlib

    server, state = counting_server
    client = _client(server, state)
    payload = zlib.compress(b'{"deflated": true}')
    assert client._decode_body(payload, {"content-encoding": "deflate"}) == b'{"deflated": true}'


def test_path_prefix_limits_what_is_fetched(counting_server):
    server, state = counting_server
    port = server.server_port
    client = SafeHttpClient(
        _settings(port),
        scope=ScopePolicy.build(host="127.0.0.1", ports=[port], path_prefixes=["/ok"]),
        target_ports=(("127.0.0.1", port),),
        rate_per_second=0,
    )
    # In-prefix paths are fetched, out-of-prefix paths are refused before any connection.
    assert client.request("GET", f"http://127.0.0.1:{port}/ok").status == 200
    served = len(state.requests)
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{port}/redirect/loop")
    assert len(state.requests) == served


def test_extra_headers_are_sanitised(counting_server):
    server, state = counting_server
    client = _client(server, state)
    client.request(
        "GET",
        f"http://127.0.0.1:{server.server_port}/ok",
        headers={
            "Host": "evil.test",
            "User-Agent": "attacker/1.0",
            "X-ShadowTrace-Scan": "spoofed",
            "X-Custom": "ok",
            "X-Too-Long": "a" * 1001,
        },
    )
    seen = state.requests[-1]
    assert seen["host"].startswith("127.0.0.1")
    assert seen["ua"].startswith("ShadowTrace/")
    assert seen["scan"] == "scan-123"


# ---------------------------------------------------------------- branch completeness
# The remaining tests exist to exercise the branches the specification counts: a client
# without a scope or budget, header-count caps, the total deadline, HTTPS downgrade,
# scope-limited redirects, TLS failures and socket cleanup.


def test_client_without_scope_or_budget_still_validates_the_destination(counting_server):
    server, state = counting_server
    port = server.server_port
    client = SafeHttpClient(_settings(port), scope=None, budget=None, rate_per_second=0)
    assert client.request("GET", f"http://127.0.0.1:{port}/ok").status == 200
    with pytest.raises(BlockedRequest):
        client.request("GET", f"http://127.0.0.1:{port + 1}/ok")  # allow-list is per port
    assert len(state.requests) == 1


def test_header_count_cap_is_enforced(counting_server):
    server, state = counting_server
    client = _client(server, state)
    # http.client aborts at 100 headers before the client sees them, so the internal cap is
    # asserted directly: it is the defence that survives a future HTTP library change.
    headers = [(f"x-pad-{index}", "v") for index in range(150)]
    with pytest.raises(ResponseTooLarge):
        client._check_headers(headers)
    assert state.requests == []


def test_total_deadline_is_checked_between_redirects(counting_server):
    server, state = counting_server
    ticks = iter([100.0, 10_000.0])
    client = _client(server, state, clock=lambda: next(ticks, 10_000.0))
    with pytest.raises(ResponseTimeout):
        client.request("GET", f"http://127.0.0.1:{server.server_port}/ok")
    assert state.requests == []  # the deadline fired before any socket was opened


def test_https_to_http_redirect_is_refused(counting_server, monkeypatch):
    server, state = counting_server
    port = server.server_port
    client = SafeHttpClient(_settings(port), scope=ScopePolicy.build(host="127.0.0.1", ports=[port]))
    downgrade = ResponseData(
        url=f"https://127.0.0.1:{port}/start",
        status=302,
        headers={"location": f"http://127.0.0.1:{port}/next"},
        body=b"",
        elapsed_ms=1,
    )
    monkeypatch.setattr(client, "_single_request", lambda *args, **kwargs: downgrade)
    with pytest.raises(BlockedRequest) as excinfo:
        client.request("GET", f"https://127.0.0.1:{port}/start")
    assert excinfo.value.reason == "https_downgrade"
    # The refusal is counted, so `policy_blocked` in the scan summary matches the
    # `crawl.error` events instead of under-reporting them.
    assert client.blocked_attempts == ["redirect_https_downgrade"]


def test_redirect_outside_the_path_scope_is_refused(counting_server, monkeypatch):
    server, _state = counting_server
    port = server.server_port
    scope = ScopePolicy.build(host="127.0.0.1", ports=[port], path_prefixes=["/api/"])
    client = SafeHttpClient(_settings(port), scope=scope)
    redirect = ResponseData(
        url=f"http://127.0.0.1:{port}/api/start",
        status=302,
        headers={"location": "/admin/panel"},
        body=b"",
        elapsed_ms=1,
    )
    monkeypatch.setattr(client, "_single_request", lambda *args, **kwargs: redirect)
    with pytest.raises(BlockedRequest) as excinfo:
        client.request("GET", f"http://127.0.0.1:{port}/api/start")
    assert excinfo.value.reason == "redirect_out_of_scope"
    assert client.blocked_attempts == ["redirect_out_of_scope"]


def test_tls_handshake_failure_is_reported_as_a_target_error(counting_server):
    server, _state = counting_server
    port = server.server_port
    client = SafeHttpClient(_settings(port), scope=ScopePolicy.build(host="127.0.0.1", ports=[port]))
    # The fixture speaks plain HTTP, so a TLS handshake against it must fail cleanly.
    with pytest.raises(TargetRequestError):
        client.request("GET", f"https://127.0.0.1:{port}/ok")


def test_certificate_verification_failure_is_reported(counting_server, monkeypatch):
    import ssl

    server, _state = counting_server
    port = server.server_port
    client = SafeHttpClient(_settings(port), scope=ScopePolicy.build(host="127.0.0.1", ports=[port]))

    class _Failing:
        sock = type("Sock", (), {"settimeout": lambda self, value: None})()

        def connect(self):
            raise ssl.SSLCertVerificationError("self-signed certificate")

        def close(self):
            return None

    monkeypatch.setattr(client, "_connection", lambda destination: _Failing())
    with pytest.raises(TargetRequestError):
        client.request("GET", f"https://127.0.0.1:{port}/ok")


def test_socket_cleanup_failure_does_not_mask_the_response(counting_server, monkeypatch):
    server, _state = counting_server
    port = server.server_port
    client = SafeHttpClient(_settings(port), scope=ScopePolicy.build(host="127.0.0.1", ports=[port]))

    class _BadClose:
        def __init__(self, inner):
            self.inner = inner

        @property
        def sock(self):  # http.client sets this during connect()
            return self.inner.sock

        def connect(self):
            return self.inner.connect()

        def request(self, *args, **kwargs):
            return self.inner.request(*args, **kwargs)

        def getresponse(self):
            return self.inner.getresponse()

        def close(self):
            raise OSError("socket already gone")

    original = client._connection
    monkeypatch.setattr(client, "_connection", lambda destination: _BadClose(original(destination)))
    assert client.request("GET", f"http://127.0.0.1:{port}/ok").status == 200
