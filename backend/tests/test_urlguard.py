"""SSRF-01..SSRF-05: URL canonicalization and destination validation."""
from __future__ import annotations

import pytest

from app.engine.urlguard import (
    DEFAULT_PORTS,
    SystemResolver,
    _normalize_host,
    BlockedDestination,
    canonicalize,
    is_always_blocked,
    is_blocked_ip,
    validate_destination,
)


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def resolve(self, host, port):
        self.calls.append((host, port))
        if host in self.mapping:
            value = self.mapping[host]
            if isinstance(value, Exception):
                raise value
            return value
        return ["93.184.216.34"]


SYNTAX_BLOCKED_URLS = [
    "http://127.1/",
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    "http://0/",
    "http://user:pass@example.com/",
    "http://example.com\\@127.0.0.1/",
    "ftp://example.com/",
    "file:///etc/passwd",
    "gopher://example.com/",
    "javascript:alert(1)",
    "http://exa mple.com/",
    "http:///path",
    "//example.com/",
    "http://",
    "http://example.com/" + "a" * 3000,
]


@pytest.mark.parametrize("url", SYNTAX_BLOCKED_URLS)
def test_canonicalize_blocks_malformed_or_ambiguous_urls(url):
    with pytest.raises(BlockedDestination):
        canonicalize(url)


BLOCKED_DESTINATIONS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/api",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/",
    "http://172.16.4.4/",
    "http://192.168.1.1/",
    "http://100.64.0.1/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[64:ff9b::7f00:1]/",
    "http://[2002:7f00:0001::]/",
    "http://[fe80::1]/",
    "http://[fd00::1]/",
    "http://[2001:db8::1]/",
    "http://example.com:22/",
    "http://example.com:8080/",
]


@pytest.mark.parametrize("url", BLOCKED_DESTINATIONS)
def test_validate_destination_blocks_private_and_unusual_ports(url):
    host = url.split("://", 1)[1].split("/")[0]
    literal = host.split("@")[-1]
    resolver = FakeResolver({literal.strip("[]"): [literal.strip("[]")], "localhost": ["127.0.0.1"]})
    with pytest.raises(BlockedDestination):
        validate_destination(url, resolver)


def test_trailing_dot_and_case_are_normalized():
    canonical = canonicalize("HTTP://Example.COM./Path?q=1")
    assert canonical.host == "example.com"
    assert canonical.scheme == "http"
    assert canonical.port == 80
    assert canonical.path == "/Path"
    assert canonical.query == "q=1"


def test_idn_is_punycoded():
    canonical = canonicalize("https://bücher.example/pfad")
    assert canonical.host.startswith("xn--")


def test_metadata_hostnames_blocked_before_dns():
    resolver = FakeResolver({})
    with pytest.raises(BlockedDestination):
        validate_destination("http://metadata.google.internal/", resolver)
    assert resolver.calls == []


def test_public_host_allowed():
    resolver = FakeResolver({"example.com": ["93.184.216.34"]})
    approved = validate_destination("https://example.com/api", resolver)
    assert approved.addresses == ("93.184.216.34",)
    assert approved.url.host == "example.com"


def test_host_resolving_to_private_is_blocked():
    resolver = FakeResolver({"evil.example": ["10.1.2.3"]})
    with pytest.raises(BlockedDestination):
        validate_destination("http://evil.example/", resolver)


def test_mixed_public_and_private_answers_blocked():
    resolver = FakeResolver({"mixed.example": ["93.184.216.34", "192.168.0.10"]})
    with pytest.raises(BlockedDestination):
        validate_destination("http://mixed.example/", resolver)


def test_operator_allowlist_permits_exact_pair_only():
    resolver = FakeResolver({"127.0.0.1": ["127.0.0.1"], "127.0.0.2": ["127.0.0.2"]})
    approved = validate_destination(
        "http://127.0.0.1:8099/", resolver, private_allowlist=(("127.0.0.1", 8099),)
    )
    assert approved.addresses == ("127.0.0.1",)
    with pytest.raises(BlockedDestination):
        validate_destination("http://127.0.0.2:8099/", resolver, private_allowlist=(("127.0.0.1", 8099),))
    with pytest.raises(BlockedDestination):
        validate_destination("http://127.0.0.1:9000/", resolver, private_allowlist=(("127.0.0.1", 8099),))


@pytest.mark.parametrize(
    "address",
    [
        "0.0.0.0",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.2.5",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "::",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "2001:db8::1",
        "64:ff9b::10.0.0.1",
    ],
)
def test_blocked_addresses(address):
    assert is_blocked_ip(address) is not None


@pytest.mark.parametrize("address", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(address):
    assert is_blocked_ip(address) is None


# ---------------------------------------------------------------- coverage gaps


def test_canonical_url_properties():
    url = canonicalize("https://app.example.test:8443/api/v1/users?page=2")
    assert url.host_header == "app.example.test:8443"
    assert url.origin == "https://app.example.test:8443"
    assert url.request_target == "/api/v1/users?page=2"
    assert str(url) == "https://app.example.test:8443/api/v1/users?page=2"
    bare = canonicalize("https://app.example.test")
    assert bare.host_header == "app.example.test"
    assert bare.origin == "https://app.example.test"
    assert bare.request_target == "/"
    assert str(canonicalize("http://app.example.test:80/x")) == "http://app.example.test/x"


@pytest.mark.parametrize(
    "raw,reason",
    [
        ("", "empty_host"),
        (".", "empty_host"),
        ("a\\b", "backslash_host"),
        ("xn--\u00e9.example", "invalid_idna"),
        ("bad_host!", "invalid_host"),
    ],
)
def test_normalize_host_rejections(raw, reason):
    with pytest.raises(BlockedDestination) as excinfo:
        _normalize_host(raw)
    assert excinfo.value.reason == reason


def test_iptables_ids_are_normalized_to_their_canonical_form():
    assert _normalize_host("[::1]") == "[::1]"
    assert _normalize_host("ExAmPlE.Test.") == "example.test"
    assert _normalize_host("bücher.example") == "xn--bcher-kva.example"


def test_is_blocked_ip_classifies_every_family():
    assert is_blocked_ip("not-an-ip") == "unparseable_ip"
    assert is_blocked_ip("127.0.0.1") is not None
    assert is_blocked_ip("10.0.0.1") is not None
    assert is_blocked_ip("169.254.169.254") is not None
    assert is_blocked_ip("::ffff:127.0.0.1") is not None
    assert is_blocked_ip("64:ff9b::7f00:1") is not None      # NAT64 of 127.0.0.1
    assert is_blocked_ip("2002:7f00:0001::") is not None     # 6to4 of 127.0.0.1
    # Teredo carries the client address obfuscated; the server address decides routing.
    assert is_blocked_ip("2001:0000:4136:e378:8000:63bf:3fff:fdd2") is not None
    assert is_blocked_ip("93.184.216.34") is None
    assert is_blocked_ip("2606:2800:220:1:248:1893:25c8:1946") is None


def test_is_always_blocked_ignores_private_but_not_metadata():
    assert is_always_blocked("127.0.0.1") is None          # lab loopback is allowed
    assert is_always_blocked("10.0.0.5") is None
    assert is_always_blocked("169.254.169.254") is not None
    assert is_always_blocked("0.0.0.0") is not None
    assert is_always_blocked("224.0.0.1") is not None
    assert is_always_blocked("::") is not None
    assert is_always_blocked("::ffff:169.254.169.254") is not None
    assert is_always_blocked("nope") == "unparseable_ip"


def test_allowlist_requires_dns_records_and_public_metadata_guard():
    class Empty:
        def resolve(self, host, port):
            return []

    class Metadata:
        def resolve(self, host, port):
            return ["169.254.169.254"]

    with pytest.raises(BlockedDestination) as empty:
        validate_destination("http://lab.test:8099/x", Empty(), private_allowlist=(("lab.test", 8099),))
    assert empty.value.reason == "dns_no_records"
    with pytest.raises(BlockedDestination) as metadata:
        validate_destination("http://lab.test:8099/x", Metadata(), private_allowlist=(("lab.test", 8099),))
    assert metadata.value.reason == "blocked_address"


def test_public_resolution_requires_at_least_one_address():
    class Empty:
        def resolve(self, host, port):
            return []

    with pytest.raises(BlockedDestination) as excinfo:
        validate_destination("https://app.example.test/", Empty())
    assert excinfo.value.reason == "dns_no_records"


def test_system_resolver_returns_unique_addresses_and_raises_on_dns_failure(monkeypatch):
    import socket as socket_module

    resolver = SystemResolver()
    monkeypatch.setattr(
        socket_module,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket_module.AF_INET, socket_module.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket_module.AF_INET, socket_module.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
        ],
    )
    assert resolver.resolve("example.test", 443) == ["93.184.216.34"]

    def boom(*args, **kwargs):
        raise socket_module.gaierror("nope")

    monkeypatch.setattr(socket_module, "getaddrinfo", boom)
    with pytest.raises(BlockedDestination) as excinfo:
        resolver.resolve("missing.test", 443)
    assert excinfo.value.reason == "dns_failure"

    monkeypatch.setattr(socket_module, "getaddrinfo", lambda *args, **kwargs: [])
    with pytest.raises(BlockedDestination) as empty:
        resolver.resolve("empty.test", 443)
    assert empty.value.reason == "dns_no_records"


def test_scheme_and_port_defaults_are_consistent():
    assert DEFAULT_PORTS == {"http": 80, "https": 443}
    assert canonicalize("https://a.test:443/").port == 443
    assert canonicalize("http://a.test:80/").port == 80
    assert canonicalize("http://a.test:8080/").port == 8080

# ---------------------------------------------------------------- branch completeness
# These cases exist so every refusal branch in canonicalize()/is_blocked_ip() is asserted,
# not just covered incidentally by the corpus above.


def test_empty_and_non_string_urls_are_refused():
    for value in ("", None, 0):
        with pytest.raises(BlockedDestination) as excinfo:
            canonicalize(value)  # type: ignore[arg-type]
        assert excinfo.value.reason == "empty_url"


def test_control_characters_are_refused_before_parsing():
    with pytest.raises(BlockedDestination) as excinfo:
        canonicalize("http://app.example.test/\x00path")
    assert excinfo.value.reason == "control_characters"


def test_port_zero_is_refused():
    with pytest.raises(BlockedDestination) as excinfo:
        canonicalize("http://app.example.test:0/")
    assert excinfo.value.reason == "invalid_port"


def test_path_is_always_rooted():
    assert str(canonicalize("http://app.example.test")) == "http://app.example.test/"
    assert canonicalize("http://app.example.test/double").path == "/double"


def test_reserved_but_unlisted_addresses_are_not_globally_routable():
    # 5f00::/8 is not in the explicit blocklist, so the is_global/is_reserved fallback decides.
    assert is_blocked_ip("5f00::1") == "not_globally_routable"
    assert is_blocked_ip("192.31.196.1") is None  # a genuinely global, unlisted address
