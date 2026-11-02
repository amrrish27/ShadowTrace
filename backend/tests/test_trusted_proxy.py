"""`X-Forwarded-For` is honoured only when the socket peer is a configured proxy.

Behind nginx every request arrives from the proxy, so the client address used for
rate limiting and the audit log has to come from the forwarded header. If that header
were trusted from anyone, any client could pick its own rate-limit bucket and forge
the address recorded in the audit trail. `ST_TRUSTED_PROXIES` is the allow-list that
decides, and it accepts literal addresses or CIDR networks.
"""
from __future__ import annotations

import re

import pytest
from starlette.requests import Request

from app.config import get_settings, is_trusted_proxy, reset_settings_cache
from app.security.auth import client_ip


def _request(peer: str, forwarded: str | None = None) -> Request:
    headers = [(b"host", b"testserver")]
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/meta",
            "raw_path": b"/api/v1/meta",
            "query_string": b"",
            "headers": headers,
            "client": (peer, 51234),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


@pytest.fixture()
def trusted(monkeypatch):
    """Configure proxies for one test and restore the (empty) default afterwards."""
    def configure(*entries: str) -> None:
        monkeypatch.setenv("ST_TRUSTED_PROXIES", ",".join(entries))
        reset_settings_cache()

    yield configure
    monkeypatch.delenv("ST_TRUSTED_PROXIES", raising=False)
    reset_settings_cache()


def test_forwarded_header_is_ignored_when_no_proxy_is_configured():
    assert get_settings().trusted_proxies == ()
    assert client_ip(_request("203.0.113.9", "198.51.100.7")) == "203.0.113.9"


def test_forwarded_header_is_ignored_from_an_untrusted_peer(trusted):
    trusted("172.30.0.2")
    assert client_ip(_request("203.0.113.9", "198.51.100.7")) == "203.0.113.9"


def test_forwarded_header_is_honoured_from_a_trusted_peer(trusted):
    trusted("172.30.0.2")
    assert client_ip(_request("172.30.0.2", "198.51.100.7")) == "198.51.100.7"


def test_a_trusted_cidr_network_is_supported(trusted):
    trusted("172.30.0.0/24")
    assert client_ip(_request("172.30.0.9", "198.51.100.7")) == "198.51.100.7"
    assert client_ip(_request("172.31.0.9", "198.51.100.7")) == "172.31.0.9"


def test_a_spoofed_left_entry_does_not_win_over_the_real_one(trusted):
    """A client that prepends its own address must not be able to choose its identity.

    "spoofed, real" is what an appending proxy produces: the real client is the hop the
    proxy wrote, i.e. the RIGHTMOST untrusted entry.
    """
    trusted("172.30.0.2")
    assert client_ip(_request("172.30.0.2", "1.2.3.4, 198.51.100.7")) == "198.51.100.7"


def test_a_single_entry_is_returned(trusted):
    """The bundled nginx overwrites the header with $remote_addr, so this is the shape."""
    trusted("172.30.0.2")
    assert client_ip(_request("172.30.0.2", "198.51.100.7")) == "198.51.100.7"


def test_a_chain_of_two_trusted_proxies_resolves_to_the_client(trusted):
    """CDN/proxy -> our proxy -> app: skip both of ours from the right."""
    trusted("172.30.0.0/24", "10.0.0.5")
    assert client_ip(_request("172.30.0.2", "198.51.100.7, 10.0.0.5, 172.30.0.9")) == "198.51.100.7"


def test_a_chain_all_of_whose_hops_are_trusted_returns_the_origin(trusted):
    trusted("172.30.0.2", "10.0.0.0/8")
    assert client_ip(_request("172.30.0.2", "10.1.2.3, 10.0.0.5")) == "10.1.2.3"


@pytest.mark.parametrize(
    "header, expected",
    [
        ("not-an-ip", "172.30.0.2"),
        ("198.51.100.7, not-an-ip", "172.30.0.2"),
        ("198.51.100.7,,172.30.0.9", "172.30.0.2"),
        ("1" * 65, "172.30.0.2"),
        ("198.51.100.7, " + "9" * 65, "172.30.0.2"),
        ("198.51.100.7:443", "172.30.0.2"),
        ("example.test", "172.30.0.2"),
        (", ".join(["198.51.100.7"] * 20), "172.30.0.2"),
    ],
)
def test_malformed_or_oversized_chains_fall_back_to_the_peer(trusted, header, expected):
    """A header we cannot fully validate must not change the recorded address."""
    trusted("172.30.0.2")
    assert client_ip(_request("172.30.0.2", header)) == expected


def test_ipv6_hops_are_accepted(trusted):
    trusted("::1")
    assert client_ip(_request("::1", "2001:db8::5, ::1")) == "2001:db8::5"
    assert client_ip(_request("::1", "[2001:db8::5]")) == "2001:db8::5"


def test_a_malformed_trusted_entry_fails_closed(trusted):
    trusted("172.30.0.2/not-a-network", "172.30.0.256")
    assert client_ip(_request("172.30.0.2", "198.51.100.7")) == "172.30.0.2"


def test_an_empty_header_falls_back_to_the_peer(trusted):
    trusted("172.30.0.2")
    assert client_ip(_request("172.30.0.2", "")) == "172.30.0.2"
    assert client_ip(_request("172.30.0.2", "   ")) == "172.30.0.2"


def test_an_absurdly_long_header_value_is_rejected(trusted):
    trusted("172.30.0.2")
    assert client_ip(_request("172.30.0.2", "1" * 80)) == "172.30.0.2"


def test_a_missing_client_falls_back_to_unknown():
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/meta",
            "raw_path": b"/api/v1/meta",
            "query_string": b"",
            "headers": [(b"host", b"testserver")],
            "client": None,
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )
    assert client_ip(request) == "unknown"


@pytest.mark.parametrize(
    "peer, entries, expected",
    [
        ("172.30.0.2", ("172.30.0.2",), True),
        ("172.30.0.3", ("172.30.0.2",), False),
        ("172.30.0.3", ("172.30.0.0/24",), True),
        ("::1", ("::1",), True),
        ("::1", ("127.0.0.1",), False),
        ("", ("172.30.0.2",), False),
        ("172.30.0.2", (), False),
        ("unix-socket", ("unix-socket",), True),
    ],
)
def test_is_trusted_proxy_matrix(peer, entries, expected):
    assert is_trusted_proxy(peer, entries) is expected


def test_the_rate_limiter_uses_the_trusted_client_address(client, analyst_client, trusted):
    """Header spoofing must not open a fresh rate-limit bucket for the same client."""
    client, headers, _env = analyst_client
    trusted("testclient")
    from app.security import ratelimit

    ratelimit.limiter.reset()  # drop buckets recorded by the sign-in request
    first = client.get("/api/v1/meta/config", headers={**headers, "X-Forwarded-For": "198.51.100.7"})
    assert first.status_code == 200

    keys = list(ratelimit.limiter._events)  # noqa: SLF001 - the key is the assertion
    # The trusted peer's claim is what the limiter keys on: the bucket exists for the
    # forwarded address, not for "testclient".
    assert any(key.endswith(":198.51.100.7") for key in keys), keys
    assert not any(key.endswith(":testclient") for key in keys), keys


def test_an_untrusted_peer_cannot_pick_its_own_bucket(client, analyst_client):
    """Without a trusted proxy the forwarded header is ignored, so the bucket is the peer."""
    client, headers, _env = analyst_client
    from app.security import ratelimit

    ratelimit.limiter.reset()
    first = client.get("/api/v1/meta/config", headers={**headers, "X-Forwarded-For": "198.51.100.7"})
    assert first.status_code == 200
    keys = list(ratelimit.limiter._events)  # noqa: SLF001 - the key is the assertion
    assert any(key.endswith(":testclient") for key in keys), keys
    assert not any(key.endswith(":198.51.100.7") for key in keys), keys


# --------------------------------------------------- the proxy must not re-introduce append


NGINX = __import__("pathlib").Path(__file__).resolve().parent.parent.parent / "deploy" / "proxy" / "nginx.conf"


def _nginx_locations() -> dict[str, str]:
    """Every `location … { … }` block, keyed by its pattern (brace-matched)."""
    text = NGINX.read_text()
    blocks: dict[str, str] = {}
    for match in re.finditer(r"location\s+([^\s{]+)\s*\{", text):
        depth, index = 0, match.end() - 1
        while index < len(text):
            if text[index] == "{":
                depth += 1
            elif text[index] == "}":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        blocks[match.group(1)] = text[match.end() : index]
    return blocks


def test_nginx_never_appends_to_x_forwarded_for():
    """`$proxy_add_x_forwarded_for` would let a client prepend its own address."""
    offending = [
        line.strip()
        for line in NGINX.read_text().splitlines()
        if "proxy_add_x_forwarded_for" in line and not line.strip().startswith("#")
    ]
    assert offending == [], offending


def test_every_proxying_location_overwrites_x_forwarded_for():
    proxying = {name: body for name, body in _nginx_locations().items() if "proxy_pass" in body}
    assert proxying, "the nginx config must proxy at least one location"
    for name, body in proxying.items():
        headers = [line.strip() for line in body.splitlines() if "proxy_set_header X-Forwarded-For" in line]
        assert headers == ["proxy_set_header X-Forwarded-For $remote_addr;"], (name, headers)


def test_every_proxying_location_keeps_x_real_ip():
    for name, body in _nginx_locations().items():
        if "proxy_pass" not in body:
            continue
        assert "proxy_set_header X-Real-IP $remote_addr;" in body, name
