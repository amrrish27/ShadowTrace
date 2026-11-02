"""Authentication, session management, CSRF and RBAC.

* Opaque session tokens in an HttpOnly cookie; only hashes are stored.
* Sliding idle expiry plus an absolute expiry; rotation on login; revocation on
  logout and password change.
* CSRF: per-session token in a readable cookie + ``X-CSRF-Token`` header, plus an
  Origin check on every state-changing request.
* Authorization: role hierarchy + organization scoping applied in every query.
"""
from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from fastapi import Request, Response

from ..config import get_settings, is_trusted_proxy
from ..db import now
from . import audit
from .errors import ApiError, not_found
from .tokens import generate_token, hash_token

SESSION_COOKIE = "st_session"
CSRF_COOKIE = "st_csrf"
CSRF_HEADER = "x-csrf-token"
ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True)
class AuthContext:
    user_id: str
    org_id: str
    role: str
    email: str
    name: str
    session_id: str
    csrf_token: str

    @property
    def rank(self) -> int:
        return ROLE_RANK.get(self.role, 0)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


# Longest single address we accept in X-Forwarded-For (an IPv6 literal is 45 chars).
MAX_FORWARDED_ENTRY = 64
# Bound the work a hostile header can cause; real chains are 1-3 hops.
MAX_FORWARDED_HOPS = 16


def _forwarded_hops(forwarded: str) -> Optional[List[str]]:
    """Parse X-Forwarded-For into validated addresses, or None when it is malformed.

    Every entry must be a bare IP literal; anything else (a hostname, an address with a
    port, an empty segment, a value longer than `MAX_FORWARDED_ENTRY`, too many hops)
    makes the whole header untrustworthy, and the caller falls back to the socket peer.
    """
    entries = forwarded.split(",")
    if len(entries) > MAX_FORWARDED_HOPS:
        return None
    hops: List[str] = []
    for raw in entries:
        entry = raw.strip()
        if not entry or len(entry) > MAX_FORWARDED_ENTRY:
            return None
        candidate = entry.strip("[]")  # tolerate bracketed IPv6, e.g. "[2001:db8::1]"
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return None
        hops.append(candidate)
    return hops


def client_ip(request: Request) -> str:
    """The client address: the socket peer, or the last untrusted X-Forwarded-For hop.

    Two independent checks keep this unspoofable (SEC-RL-04):

    * the header is only looked at when the **socket peer** is a configured proxy
      (`ST_TRUSTED_PROXIES`, literal addresses or CIDR networks), and
    * the chain is walked from the **right** — the hop nearest to us — skipping entries
      that are themselves trusted proxies, so the address returned is the first one our
      own infrastructure did not write. Reading the leftmost entry instead would return
      whatever a client put there first.

    A malformed or oversized header falls back to the socket peer: a bad header must never
    be able to *change* the address the rate limiter and the audit log record. nginx is
    configured to overwrite this header with `$remote_addr` as well, so in the bundled
    deployment it contains exactly one value.
    """
    settings = get_settings()
    peer = request.client.host if request.client else ""
    if not is_trusted_proxy(peer, settings.trusted_proxies):
        return peer or "unknown"
    forwarded = request.headers.get("x-forwarded-for", "")
    if not forwarded:
        return peer or "unknown"
    hops = _forwarded_hops(forwarded)
    if hops is None:
        return peer or "unknown"
    for hop in reversed(hops):
        if not is_trusted_proxy(hop, settings.trusted_proxies):
            return hop
    # Every hop is one of our proxies (a proxy calling itself); the leftmost is the origin.
    return hops[0]


def create_session(
    conn: sqlite3.Connection,
    *,
    user_id: str,
    request: Request,
    response: Response,
    rotate: bool = True,
) -> str:
    settings = get_settings()
    token = generate_token()
    csrf = generate_token(24)
    timestamp = now()
    session_id = hash_token(token)[:32]
    conn.execute(
        """
        INSERT INTO sessions (id, user_id, token_hash, csrf_token, created_at, last_seen_at,
                              idle_expires_at, absolute_expires_at, ip, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            user_id,
            hash_token(token),
            csrf,
            timestamp,
            timestamp,
            timestamp + settings.session_idle_seconds,
            timestamp + settings.session_absolute_seconds,
            client_ip(request)[:64],
            (request.headers.get("user-agent") or "")[:200],
        ),
    )
    secure = settings.cookie_secure or (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").lower() == "https"
    )
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_absolute_seconds,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=settings.session_absolute_seconds,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )
    if rotate:
        # Session fixation defence: any previously presented session is revoked.
        old = request.cookies.get(SESSION_COOKIE)
        if old:
            conn.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (timestamp, hash_token(old)),
            )
    return session_id


def clear_session_cookies(response: Response, request: Optional[Request] = None) -> None:
    secure = get_settings().cookie_secure
    if request is not None:
        secure = secure or (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").lower() == "https"
        )
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, samesite="strict")


def revoke_session(conn: sqlite3.Connection, session_id: str) -> None:
    conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (now(), session_id))


def revoke_all_sessions(conn: sqlite3.Connection, user_id: str, *, except_session: Optional[str] = None) -> None:
    if except_session:
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND id <> ?",
            (now(), user_id, except_session),
        )
    else:
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (now(), user_id)
        )


Origin = Tuple[str, str, int]
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_origin(value: str) -> Optional[Origin]:
    """Normalise ``scheme://host[:port]`` to a comparable tuple, or None if it is not one.

    Returning None for anything that is not a bare web origin is deliberate: ``null``
    (sandboxed iframes, ``file://``), a bare hostname, or a value carrying a path, query,
    userinfo or fragment is never a legitimate browser Origin header, so it must not be
    able to match anything. Default ports are folded, so ``https://h`` == ``https://h:443``.
    """
    if not value:
        return None
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return None
    if parts.path not in {"", "/"} or parts.query or parts.fragment or "@" in parts.netloc:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:  # e.g. "http://host:not-a-port"
        return None
    return scheme, host, port or _DEFAULT_PORTS[scheme]


def request_origin(request: Request) -> Optional[Origin]:
    """The origin this request was *addressed to*, from the Host header and the scheme.

    The Host header has already been validated against `ST_ALLOWED_HOSTS` by
    `HostAllowlistMiddleware` before routing, so it cannot name a host we do not serve.
    `X-Forwarded-Proto` is honoured only when the socket peer is a configured trusted
    proxy (SEC-RL-04 rules); otherwise the connection's own scheme is used.
    """
    settings = get_settings()
    host = request.headers.get("host", "")
    scheme = (request.url.scheme or "http").lower()
    peer = request.client.host if request.client else ""
    if is_trusted_proxy(peer, settings.trusted_proxies):
        forwarded_proto = request.headers.get("x-forwarded-proto", "").strip().lower()
        if forwarded_proto in _DEFAULT_PORTS:
            scheme = forwarded_proto
    return _parse_origin(f"{scheme}://{host}")


def _origin_allowed(origin: str, request: Optional[Request] = None) -> bool:
    """Is this Origin acceptable for a state-changing request?

    Three ways to pass, all equally narrow:

    * it is one of the configured `ST_CORS_ORIGINS`, or `ST_BASE_URL` — the deployment's
      published origin;
    * it is **the origin this request was addressed to** (same-origin), which is the case a
      cookie-authenticated SPA always produces. A cross-site attacker cannot forge it: the
      browser sets Origin from the requesting document, and the Host header it is compared
      against is allow-listed.

    Anything else — a foreign site, `null`, a malformed value — is refused. This is not a
    relaxation of CSRF: same-origin requests are by definition not cross-site forgeries,
    and they are the only ones a first-party page can make.
    """
    candidate = _parse_origin(origin)
    if candidate is None:
        return False
    settings = get_settings()
    configured = tuple(settings.cors_origins) + (settings.base_url,)
    if any(_parse_origin(entry) == candidate for entry in configured):
        return True
    if request is None:
        return False
    return request_origin(request) == candidate


def authenticate(conn: sqlite3.Connection, request: Request, *, check_csrf: bool = True) -> AuthContext:
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token or len(token) > 256:
        raise ApiError(401, "unauthenticated", "Authentication is required.")
    row = conn.execute(
        """
        SELECT s.id AS session_id, s.csrf_token, s.idle_expires_at, s.absolute_expires_at, s.revoked_at,
               u.id AS user_id, u.org_id, u.role, u.email, u.name, u.is_active
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (hash_token(token),),
    ).fetchone()
    timestamp = now()
    if row is None or row["revoked_at"] is not None:
        raise ApiError(401, "unauthenticated", "Authentication is required.")
    if row["idle_expires_at"] < timestamp or row["absolute_expires_at"] < timestamp:
        conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (timestamp, row["session_id"]))
        raise ApiError(401, "session_expired", "Your session has expired. Please sign in again.")
    if not row["is_active"]:
        raise ApiError(403, "forbidden", "This account is disabled.")

    if check_csrf and request.method.upper() not in SAFE_METHODS:
        header = request.headers.get(CSRF_HEADER, "")
        if not header or header != row["csrf_token"]:
            raise ApiError(403, "csrf_failed", "The request could not be verified.")
        origin = request.headers.get("origin", "")
        if origin and not _origin_allowed(origin, request):
            raise ApiError(403, "csrf_failed", "The request could not be verified.")

    # Sliding idle window, refreshed at most once a minute to limit writes.
    if timestamp - int(row["idle_expires_at"]) + get_settings().session_idle_seconds > 60:
        conn.execute(
            "UPDATE sessions SET last_seen_at = ?, idle_expires_at = ? WHERE id = ?",
            (timestamp, timestamp + get_settings().session_idle_seconds, row["session_id"]),
        )

    context = AuthContext(
        user_id=row["user_id"],
        org_id=row["org_id"],
        role=row["role"],
        email=row["email"],
        name=row["name"],
        session_id=row["session_id"],
        csrf_token=row["csrf_token"],
    )
    request.state.auth = context
    return context


def require_role(context: AuthContext, minimum: str) -> None:
    if context.rank < ROLE_RANK[minimum]:
        raise ApiError(403, "forbidden", "You do not have permission to perform this action.")


def require_any(context: AuthContext, roles: Iterable[str]) -> None:
    if context.role not in set(roles):
        raise ApiError(403, "forbidden", "You do not have permission to perform this action.")


# The table name is never caller-controlled: `scoped()` rejects anything outside
# SCOPED_TABLES before this statement is formatted. Only the row id is bound.
SCOPED_TABLES = frozenset(
    {
        "targets",
        "scans",
        "baselines",
        "endpoints",
        "findings",
        "invitations",
        "triage_records",
        "report_exports",
    }
)

SCOPED_SELECT_SQL = "SELECT * FROM {table} WHERE id = ? AND org_id = ?"


def scoped(conn: sqlite3.Connection, table: str, object_id: str, org_id: str) -> sqlite3.Row:
    """Fetch an object inside the caller's organization or return 404."""
    if table not in SCOPED_TABLES:
        raise ValueError("unscoped table access denied")
    row = conn.execute(SCOPED_SELECT_SQL.format(table=table), (object_id, org_id)).fetchone()
    if row is None:
        raise not_found()
    return row


def audit_login(
    conn: sqlite3.Connection,
    request: Request,
    *,
    email: str,
    user_id: Optional[str],
    org_id: Optional[str],
    success: bool,
    reason: str = "",
) -> None:
    audit.record(
        conn,
        action="auth.login_success" if success else "auth.login_failed",
        actor_type="user" if success and user_id else "anonymous",
        actor_id=user_id,
        org_id=org_id,
        ip=client_ip(request),
        details={"email": email[:254], "reason": reason[:80]},
        durable=True,
    )


def set_security_cookie_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def user_public(row: Dict[str, object]) -> Dict[str, object]:
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "created_at": row["created_at"],
        "last_login_at": row.get("last_login_at"),
    }
