"""URL canonicalization and destination validation (the first half of SSRF defence).

Rules implemented here (SSRF-01..SSRF-03):
* only http/https, no userinfo, no backslashes, no control characters;
* no ambiguous IP notations (decimal, octal, hex, short forms, trailing dot tricks);
* IDNA-normalized hostnames, lower-cased, trailing dot stripped;
* every resolved address must be globally routable; blocked ranges are enumerated
  explicitly, including IPv4-mapped, NAT64, 6to4 and Teredo forms;
* metadata hostnames are blocked by name before DNS.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from typing import Iterable, List, Optional, Protocol, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
DEFAULT_PORTS = {"http": 80, "https": 443}

METADATA_HOSTNAMES = {
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
    "169.254.169.254",
    "fd00:ec2::254",
}

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ALL_DIGITS_RE = re.compile(r"^[0-9]+$")
_HEX_ONLY_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
_NUMERIC_LABEL_RE = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Explicit blocked networks (SSRF-02).
_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",          # "this" network / unspecified
        "10.0.0.0/8",
        "100.64.0.0/10",      # carrier-grade NAT
        "127.0.0.0/8",        # loopback
        "169.254.0.0/16",     # link-local + cloud metadata
        "172.16.0.0/12",
        "192.0.0.0/24",       # IETF protocol assignments
        "192.0.2.0/24",       # documentation
        "192.88.99.0/24",     # 6to4 relay anycast
        "192.168.0.0/16",
        "198.18.0.0/15",      # benchmarking
        "198.51.100.0/24",    # documentation
        "203.0.113.0/24",     # documentation
        "224.0.0.0/4",        # multicast
        "240.0.0.0/4",        # reserved
        "255.255.255.255/32",
        "::/128",             # unspecified
        "::1/128",            # loopback
        "64:ff9b::/96",       # NAT64
        "64:ff9b:1::/48",
        "100::/64",           # discard
        "2001::/23",          # IETF protocol assignments (incl. Teredo 2001::/32)
        "2001:db8::/32",      # documentation
        "2002::/16",          # 6to4
        "fc00::/7",           # unique-local
        "fe80::/10",          # link-local
        "ff00::/8",           # multicast
        "::ffff:0:0/96",      # IPv4-mapped (checked explicitly as well)
    )
]


# Ranges that stay forbidden even for operator allow-listed lab targets: cloud metadata,
# link-local, multicast, unspecified and "this network" blocks. A host in the allow-list may
# reach loopback/private space (that is the point of lab mode) but never metadata endpoints.
_ALWAYS_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "fe80::/10",
        "ff00::/8",
        "2002::/16",
        "64:ff9b::/96",
        "::ffff:0:0/96",
    )
]


class BlockedDestination(Exception):
    """Raised for any URL that must not be fetched. Message is internal-only."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class CanonicalURL:
    scheme: str
    host: str          # lowercase punycode, no trailing dot
    port: int
    path: str
    query: str

    @property
    def host_header(self) -> str:
        if self.port == DEFAULT_PORTS[self.scheme]:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        default = DEFAULT_PORTS[self.scheme]
        suffix = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{self.host}{suffix}"

    @property
    def request_target(self) -> str:
        target = self.path or "/"
        if self.query:
            target = f"{target}?{self.query}"
        return target

    def __str__(self) -> str:
        return urlunsplit((self.scheme, self.host_header, self.path or "/", self.query, ""))


def _looks_like_numeric_host(host: str) -> bool:
    """True for decimal, hex, octal and short-form IPv4 notations."""
    if _ALL_DIGITS_RE.match(host) or _HEX_ONLY_RE.match(host):
        return True
    if "." in host:
        labels = host.split(".")
        return all(_NUMERIC_LABEL_RE.match(label) for label in labels) and any(label != "" for label in labels)
    return False


def _canonicalize_ip_literal(host: str) -> Optional[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Parse IPv4/IPv6 hosts, rejecting non-canonical IPv4 notations."""
    bare = host.strip("[]")
    try:
        return ipaddress.ip_address(bare)
    except ValueError:
        pass
    if _looks_like_numeric_host(bare):
        # decimal, hex, octal and short forms are refused outright
        raise BlockedDestination("non_canonical_ip")
    return None


def _normalize_host(raw_host: str) -> str:
    if not raw_host:
        raise BlockedDestination("empty_host")
    if raw_host.startswith("[") and raw_host.endswith("]"):
        return raw_host.lower()
    if "\\" in raw_host:
        raise BlockedDestination("backslash_host")
    host = raw_host.strip()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise BlockedDestination("empty_host")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise BlockedDestination("invalid_idna") from exc
    ascii_host = ascii_host.lower()
    ip_literal = _canonicalize_ip_literal(ascii_host)
    if ip_literal is None and not _HOSTNAME_RE.match(ascii_host):
        raise BlockedDestination("invalid_host")
    return ascii_host


def canonicalize(url: str) -> CanonicalURL:
    if not isinstance(url, str) or not url:
        raise BlockedDestination("empty_url")
    if len(url) > MAX_URL_LENGTH:
        raise BlockedDestination("url_too_long")
    if _CONTROL_RE.search(url):
        raise BlockedDestination("control_characters")
    if "\\" in url:
        raise BlockedDestination("backslash")
    if any(ch.isspace() for ch in url):
        raise BlockedDestination("whitespace")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise BlockedDestination("unparseable") from exc
    scheme = (parts.scheme or "").lower()
    if scheme not in DEFAULT_PORTS:
        raise BlockedDestination("scheme_not_allowed")
    if "@" in parts.netloc:
        raise BlockedDestination("userinfo_not_allowed")
    raw_host = parts.hostname or ""
    host = _normalize_host(raw_host)
    try:
        port = parts.port
    except ValueError as exc:
        raise BlockedDestination("invalid_port") from exc
    if port is None:
        port = DEFAULT_PORTS[scheme]
    if not (0 < port < 65536):
        raise BlockedDestination("invalid_port")
    if host.strip("[]") in METADATA_HOSTNAMES:
        raise BlockedDestination("metadata_hostname")
    # urlsplit() returns either "" or a path that already starts with "/", so the
    # request target only needs the empty case normalised.
    path = parts.path or "/"
    return CanonicalURL(scheme=scheme, host=host, port=port, path=path, query=parts.query)


def _embedded_v4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """Extract an embedded IPv4 address from mapped/NAT64/6to4/Teredo forms."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    packed = ip.packed
    if ip in ipaddress.ip_network("64:ff9b::/96"):
        return ipaddress.IPv4Address(packed[12:16])
    if ip in ipaddress.ip_network("2002::/16"):
        return ipaddress.IPv4Address(packed[2:6])
    if ip in ipaddress.ip_network("2001::/32"):  # Teredo embeds the server + obfuscated client
        return ipaddress.IPv4Address(bytes(b ^ 0xFF for b in packed[12:16]))
    return None


def is_blocked_ip(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> Optional[str]:
    """Return a reason string when an address is not globally routable."""
    try:
        address = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    except ValueError:
        return "unparseable_ip"
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_v4(address)
        if embedded is not None and is_blocked_ip(embedded):
            return "embedded_ipv4_blocked"
    for network in _BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
            return f"blocked_network:{network}"
    if not address.is_global or address.is_private or address.is_reserved:
        return "not_globally_routable"
    return None


def is_always_blocked(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> Optional[str]:
    """Return a reason when an address is forbidden even for allow-listed lab targets."""
    try:
        address = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    except ValueError:
        return "unparseable_ip"
    if isinstance(address, ipaddress.IPv6Address):
        embedded = _embedded_v4(address)
        if embedded is not None and is_always_blocked(embedded):
            return "embedded_ipv4_blocked"
    for network in _ALWAYS_BLOCKED_NETWORKS:
        if address.version == network.version and address in network:
            return f"always_blocked_network:{network}"
    return None


class Resolver(Protocol):
    def resolve(self, host: str, port: int) -> Sequence[str]: ...


_RESOLVER_EXECUTOR: Optional[ThreadPoolExecutor] = None


def _get_resolver_executor() -> ThreadPoolExecutor:
    global _RESOLVER_EXECUTOR
    if _RESOLVER_EXECUTOR is None:
        _RESOLVER_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="dns-resolve")
    return _RESOLVER_EXECUTOR


class SystemResolver:
    """Real DNS resolution with every A/AAAA record collected, enforcing hard timeout."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def resolve(self, host: str, port: int) -> Sequence[str]:
        executor = _get_resolver_executor()
        future = executor.submit(socket.getaddrinfo, host, port, proto=socket.IPPROTO_TCP)
        try:
            infos = future.result(timeout=self.timeout)
        except FutureTimeoutError as exc:
            raise BlockedDestination("dns_timeout") from exc
        except socket.gaierror as exc:
            raise BlockedDestination("dns_failure") from exc
        addresses: List[str] = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise BlockedDestination("dns_no_records")
        return addresses


@dataclass(frozen=True)
class ApprovedDestination:
    url: CanonicalURL
    addresses: Tuple[str, ...]


def validate_destination(
    url: str,
    resolver: Resolver,
    *,
    private_allowlist: Iterable[Tuple[str, int]] = (),
    declared_ports: Iterable[Tuple[str, int]] = (),
    lab_grants: Iterable[Tuple[str, int]] = (),
) -> ApprovedDestination:
    """Canonicalize, resolve and validate.

    Two *separate* permissions are involved, and conflating them is what made an
    earlier revision unsafe:

    * ``private_allowlist`` — operator configuration (`ST_PRIVATE_ALLOWLIST`). This is
      the **only** way to reach loopback, RFC1918 or otherwise non-public space, and it
      grants exactly one host:port pair, never a range. Cloud-metadata and link-local
      addresses stay blocked even here (`is_always_blocked`).
    * ``declared_ports`` — the ports the *target record* says are authorized. This only
      relaxes the **port** rule (so `https://api.example.com:8443` works without an
      operator entry). It must never relax the **address** rule: a target declared by a
      user is not an operator trust decision.
    * ``lab_grants`` — pairs the caller has already verified as *operator-authorized lab
      destinations* (`security/labgrant.py`: an HMAC issued by the API while the operator
      allow-list contained the pair). Like ``private_allowlist`` this permits that exact
      pair only; it is computed by the scanning process from a signed, target-bound
      record, and it is never populated from user input.

    Every resolved address must therefore be public unless the pair is in
    ``private_allowlist`` or in a verified ``lab_grants`` set.
    """
    canonical = canonicalize(url)
    pair = (canonical.host, canonical.port)
    operator_grant = {(h.lower().strip("[]"), int(p)) for h, p in private_allowlist}
    lab_grant = {(h.lower().strip("[]"), int(p)) for h, p in lab_grants}
    declared = {(h.lower().strip("[]"), int(p)) for h, p in declared_ports}
    private_grant = operator_grant | lab_grant
    if canonical.port not in DEFAULT_PORTS.values() and pair not in private_grant and pair not in declared:
        raise BlockedDestination("port_not_allowed")
    addresses = list(resolver.resolve(canonical.host, canonical.port))
    if not addresses:
        raise BlockedDestination("dns_no_records")
    permitted_private = pair in private_grant
    for address in addresses:
        if is_always_blocked(address):
            raise BlockedDestination("blocked_address")
        if not permitted_private and is_blocked_ip(address):
            raise BlockedDestination("blocked_address")
    return ApprovedDestination(url=canonical, addresses=tuple(addresses))


def same_origin(left: CanonicalURL, right: CanonicalURL) -> bool:
    return left.scheme == right.scheme and left.host == right.host and left.port == right.port
