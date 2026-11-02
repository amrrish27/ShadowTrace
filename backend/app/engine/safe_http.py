"""SafeHttpClient — the only component allowed to make outbound requests.

Controls:
* every URL goes through :mod:`urlguard` (scheme, notation, IDNA, DNS, IP ranges)
  and the :class:`ScopePolicy`;
* connections are pinned to the validated IP while the Host header, SNI and
  certificate verification use the original hostname (defeats DNS rebinding);
* redirects are manual, at most five hops, re-validated and same-origin only;
  HTTPS-to-HTTP downgrades are refused;
* hard limits on time, headers, bytes and decompression ratio;
* scan budget, per-host rate limit, cooperative cancellation and a global kill
  switch are checked before every request;
* TLS verification is always on (there is no ``verify=False`` path);
* failures return uniform, non-revealing messages.
"""
from __future__ import annotations

import http.client
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urljoin

from ..config import Settings
from .scope import ScopePolicy
from .urlguard import (
    ApprovedDestination,
    BlockedDestination,
    CanonicalURL,
    Resolver,
    SystemResolver,
    canonicalize,
    same_origin,
    validate_destination,
)

VERSION = "1.0.0"
MAX_REDIRECTS = 5
MAX_HEADER_COUNT = 100
MAX_HEADER_BYTES = 32 * 1024
ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS"}
READ_CHUNK = 16 * 1024


class ScanError(Exception):
    """Base class for scan-time failures. ``category`` is user-safe."""

    category = "internal"

    def __init__(self, message: str = "Scan request failed.") -> None:
        self.message = message
        super().__init__(message)


#: Why a request was refused, in words an operator can act on. The reason codes are
#: policy identifiers (never secrets), so they may be logged and shown; the hints exist
#: because "policy_blocked" alone is exactly the message that made the original lab
#: failure hard to diagnose.
POLICY_HINTS = {
    "blocked_address": (
        "the destination resolves to a private, loopback or reserved address that no "
        "operator allow-list entry covers"
    ),
    "port_not_allowed": "the port is not in the target's authorized ports or the operator allow-list",
    "dns_no_records": "the hostname did not resolve to any address",
    "dns_timeout": "the DNS query timed out",
    "scheme_not_allowed": "only http and https are supported",
    "metadata_hostname": "cloud metadata and link-local destinations are always refused",
    "kill_switch": "scanning is disabled by the operator (ST_SCANNING_ENABLED=false)",
    "method_not_allowed": "only GET, HEAD and OPTIONS are ever sent",
    "host_out_of_scope": "the URL is outside the target's host scope",
    "port_out_of_scope": "the URL is outside the target's port scope",
    "path_out_of_scope": "the URL is outside the target's path scope",
    "cross_origin_redirect": "the target redirected to a different origin",
    "redirect_out_of_scope": "the redirect left the target's scope",
    "https_downgrade": "the target redirected from HTTPS to cleartext HTTP",
    "redirect_blocked_address": "the target redirected to a non-public address",
}


class BlockedRequest(ScanError):
    category = "policy_blocked"

    def __init__(self, reason: str) -> None:
        self.reason = reason  # policy identifier: safe to log, never a secret
        super().__init__("Request blocked by scanning policy.")
        self.hint = POLICY_HINTS.get(reason, "")

    @property
    def detail(self) -> str:
        return reason_detail(self.reason)


def reason_detail(reason: str) -> str:
    hint = POLICY_HINTS.get(reason, "")
    return f"{reason}: {hint}" if hint else reason


class BudgetExceeded(ScanError):
    category = "policy_blocked"

    def __init__(self) -> None:
        super().__init__("The scan request budget is exhausted.")


class ScanCancelled(ScanError):
    category = "cancelled"

    def __init__(self) -> None:
        super().__init__("The scan was cancelled.")


class TargetRequestError(ScanError):
    category = "target_error"

    def __init__(self, message: str = "The target did not respond successfully.") -> None:
        super().__init__(message)


class ResponseTooLarge(ScanError):
    category = "target_error"

    def __init__(self) -> None:
        super().__init__("The target response exceeded the configured size limit.")


class ResponseTimeout(ScanError):
    category = "timeout"

    def __init__(self) -> None:
        super().__init__("The target did not respond within the time limit.")


@dataclass
class RequestBudget:
    limit: int
    used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def consume(self) -> int:
        with self._lock:
            if self.used >= self.limit:
                raise BudgetExceeded()
            self.used += 1
            return self.used

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


@dataclass
class ResponseData:
    url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    elapsed_ms: int
    redirects: List[str] = field(default_factory=list)
    method: str = "GET"

    @property
    def content_type(self) -> str:
        return (self.headers.get("content-type") or "").split(";")[0].strip().lower()

    @property
    def text(self) -> str:
        charset = "utf-8"
        raw = self.headers.get("content-type", "")
        if "charset=" in raw:
            charset = raw.split("charset=")[-1].split(";")[0].strip().strip('"') or "utf-8"
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def body_size(self) -> int:
        return len(self.body)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a pre-validated IP while keeping the original host for Host/SNI."""

    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = pinned_ip
        # http.client stores create_connection on the instance; shadow it with the pinned version.
        self._create_connection = self._pinned_connect  # type: ignore[assignment]

    def _pinned_connect(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        if timeout is None or timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
            timeout = self.timeout
        return socket.create_connection((self._pinned_ip, self.port), timeout, source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, pinned_ip: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._create_connection = self._pinned_connect  # type: ignore[assignment]

    def _pinned_connect(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        if timeout is None or timeout is socket._GLOBAL_DEFAULT_TIMEOUT:
            timeout = self.timeout
        return socket.create_connection((self._pinned_ip, self.port), timeout, source_address)


class SafeHttpClient:
    def __init__(
        self,
        settings: Settings,
        *,
        resolver: Optional[Resolver] = None,
        target_ports: Sequence[Tuple[str, int]] = (),
        lab_grants: Optional[Sequence[Tuple[str, int]]] = None,
        scope: Optional[ScopePolicy] = None,
        budget: Optional[RequestBudget] = None,
        scan_id: str = "",
        cancel_check: Optional[Callable[[], bool]] = None,
        rate_per_second: float = 10.0,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        total_timeout: float = 30.0,
        max_bytes: Optional[int] = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        # (host, port) pairs from the approved target record. The target is the
        # authorization for its own non-standard ports, so a scan does not need an
        # operator-wide allow-list entry for every port a target declares. Cloud
        # metadata and other always-blocked ranges stay blocked regardless.
        self.target_ports = tuple(sorted({(host.lower(), int(port)) for host, port in target_ports}))
        # Verified lab grants (security/labgrant.py): only ever populated by the scanner
        # from a signed, target-bound record — never from request input.
        self.lab_grants = tuple(
            sorted({(host.lower(), int(port)) for host, port in (lab_grants or ())})
        )
        self.resolver = resolver or SystemResolver()
        self.scope = scope
        self.budget = budget
        self.scan_id = scan_id
        self.cancel_check = cancel_check or (lambda: False)
        self.min_interval = 0.0 if rate_per_second <= 0 else 1.0 / rate_per_second
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.total_timeout = total_timeout
        self.max_bytes = max_bytes or settings.max_response_bytes
        self.clock = clock
        self.sleep = sleep
        self._last_request_at: Dict[str, float] = {}
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.contact_url = f"{settings.base_url.rstrip('/')}/security"
        self.blocked_attempts: List[str] = []

    # -- helpers ---------------------------------------------------------
    def _user_agent(self) -> str:
        return f"ShadowTrace/{VERSION} (+{self.contact_url})"

    def _preflight(self, raw_url: str) -> ApprovedDestination:
        if not self.settings.scanning_enabled:
            raise BlockedRequest("kill_switch")
        if self.cancel_check():
            raise ScanCancelled()
        try:
            canonical = canonicalize(raw_url)
        except BlockedDestination as exc:
            self.blocked_attempts.append(exc.reason)
            raise BlockedRequest(exc.reason) from exc
        if self.scope is not None:
            allowed, reason = self.scope.check(canonical)
            if not allowed:
                raise BlockedRequest(reason)
        if self.budget is not None:
            self.budget.consume()
        try:
            # Three distinct permissions, never merged (see validate_destination):
            #   private_allowlist -> operator config; the direct operator grant
            #   target_ports      -> the target's own ports; relaxes the port rule only,
            #                        because a user-declared target is not an operator
            #                        trust decision
            #   lab_grants        -> operator-authorized lab destinations, already verified
            #                        as a signed target-bound grant by the scanner. Empty
            #                        for every target that is not an approved lab target.
            return validate_destination(
                raw_url,
                self.resolver,
                private_allowlist=self.settings.private_allowlist,
                declared_ports=self.target_ports,
                lab_grants=self.lab_grants,
            )
        except BlockedDestination as exc:
            self.blocked_attempts.append(exc.reason)
            raise BlockedRequest(exc.reason) from exc

    def _throttle(self, host: str) -> None:
        if self.min_interval <= 0:
            return
        last = self._last_request_at.get(host)
        current = self.clock()
        if last is not None:
            wait = self.min_interval - (current - last)
            if wait > 0:
                self.sleep(min(wait, 5.0))
        self._last_request_at[host] = self.clock()

    def _connection(self, destination: ApprovedDestination) -> http.client.HTTPConnection:
        canonical = destination.url
        pinned_ip = destination.addresses[0]
        if canonical.scheme == "https":
            return _PinnedHTTPSConnection(canonical.host, canonical.port, pinned_ip, self.connect_timeout, self._ssl_context)
        return _PinnedHTTPConnection(canonical.host, canonical.port, pinned_ip, self.connect_timeout)

    def _read_bounded(self, response: http.client.HTTPResponse) -> bytes:
        """Read at most ``max_bytes``; exceeding it aborts with ResponseTooLarge.

        Aborting (rather than truncating) keeps memory bounded and guarantees that
        no finding is ever derived from a partially-read document.
        """
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = response.read(READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            if total > self.max_bytes:
                raise ResponseTooLarge()
            chunks.append(chunk)
        return b"".join(chunks)

    def _decode_body(self, body: bytes, headers: Mapping[str, str]) -> bytes:
        encoding = (headers.get("content-encoding") or "").lower().strip()
        if not body or encoding not in {"gzip", "deflate", "br"}:
            return body
        if encoding == "br":
            # Brotli is not negotiated (we only advertise gzip/deflate); treat as opaque.
            return body
        try:
            if encoding == "gzip":
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            else:
                decompressor = zlib.decompressobj()
            out = decompressor.decompress(body, self.max_bytes + 1)
            if len(out) > self.max_bytes:
                raise ResponseTooLarge()
            return out
        except zlib.error as exc:
            raise TargetRequestError("The target sent an invalid compressed response.") from exc

    def _check_headers(self, header_items: Sequence[Tuple[str, str]]) -> Dict[str, str]:
        if len(header_items) > MAX_HEADER_COUNT:
            raise ResponseTooLarge()
        total = sum(len(k) + len(v) + 4 for k, v in header_items)
        if total > MAX_HEADER_BYTES:
            raise ResponseTooLarge()
        merged: Dict[str, str] = {}
        for key, value in header_items:
            lower = key.lower()
            merged[lower] = f"{merged[lower]}, {value}" if lower in merged else value
        return merged

    # -- request ---------------------------------------------------------
    def request(self, method: str, url: str, *, headers: Optional[Mapping[str, str]] = None) -> ResponseData:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise BlockedRequest("method_not_allowed")
        started = self.clock()
        deadline = started + self.total_timeout
        hops: List[str] = []
        current_url = url
        # Bounded by MAX_REDIRECTS: the redirect branch raises once the hop list is full,
        # so this loop always returns from inside rather than falling out.
        while True:
            if self.clock() > deadline:
                raise ResponseTimeout()
            destination = self._preflight(current_url)
            self._throttle(destination.url.host)
            response = self._single_request(method, destination, headers, deadline)
            location = response.headers.get("location", "")
            if response.status in {301, 302, 303, 307, 308} and location:
                if len(hops) >= MAX_REDIRECTS:
                    raise TargetRequestError("The target redirected too many times.")
                next_url = urljoin(str(destination.url), location)
                try:
                    next_canonical = canonicalize(next_url)
                except BlockedDestination as exc:
                    self.blocked_attempts.append(f"redirect_{exc.reason}")
                    raise BlockedRequest(f"redirect_{exc.reason}") from exc
                # Every refused redirect is recorded, not just the ones canonicalize()
                # rejected. `policy_blocked` has to equal the number of refusals the event
                # log shows, otherwise the scan summary under-reports the boundary that
                # was actually enforced.
                if destination.url.scheme == "https" and next_canonical.scheme == "http":
                    self.blocked_attempts.append("redirect_https_downgrade")
                    raise BlockedRequest("https_downgrade")
                if not same_origin(destination.url, next_canonical):
                    self.blocked_attempts.append("redirect_cross_origin")
                    raise BlockedRequest("cross_origin_redirect")
                if self.scope is not None and not self.scope.check(next_canonical)[0]:
                    self.blocked_attempts.append("redirect_out_of_scope")
                    raise BlockedRequest("redirect_out_of_scope")
                hops.append(next_url)
                current_url = next_url
                continue
            response.redirects = hops
            return response

    def _single_request(
        self,
        method: str,
        destination: ApprovedDestination,
        extra_headers: Optional[Mapping[str, str]],
        deadline: float,
    ) -> ResponseData:
        canonical: CanonicalURL = destination.url
        connection = self._connection(destination)
        started = self.clock()
        try:
            connection.connect()
            remaining = max(0.5, min(self.read_timeout, deadline - self.clock()))
            connection.sock.settimeout(remaining)  # type: ignore[union-attr]
            request_headers = {
                "User-Agent": self._user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/json,text/javascript,application/javascript;q=0.9,*/*;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            }
            if self.scan_id:
                request_headers["X-ShadowTrace-Scan"] = self.scan_id[:64]
            for key, value in (extra_headers or {}).items():
                if key.lower() in {"host", "connection", "user-agent", "x-shadowtrace-scan", "content-length"}:
                    continue
                if len(value) <= 1000:
                    request_headers[key] = value
            connection.request(method, canonical.request_target, headers=request_headers)
            raw = connection.getresponse()
            headers = self._check_headers(raw.getheaders())
            body = b""
            if method != "HEAD":
                body = self._read_bounded(raw)
                body = self._decode_body(body, headers)
            elapsed_ms = int((self.clock() - started) * 1000)
            return ResponseData(
                url=str(canonical),
                status=raw.status,
                headers=headers,
                body=body,
                elapsed_ms=elapsed_ms,
                method=method,
            )
        except (ResponseTooLarge, BlockedRequest):
            raise
        except (socket.timeout, TimeoutError) as exc:
            raise ResponseTimeout() from exc
        except ssl.SSLCertVerificationError as exc:
            raise TargetRequestError("The target's TLS certificate could not be verified.") from exc
        except ssl.SSLError as exc:
            raise TargetRequestError("The target's TLS handshake failed.") from exc
        except (ConnectionError, OSError, http.client.HTTPException) as exc:
            raise TargetRequestError() from exc
        finally:
            try:
                connection.close()
            # Rationale: closing a dead socket must never mask the real error
            except Exception:  # nosec B110
                pass
