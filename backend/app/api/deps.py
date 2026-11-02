"""Shared API dependencies and route-policy metadata."""
from __future__ import annotations

import sqlite3
from typing import Iterator, Optional

from fastapi import Depends, Request

from ..db import db
from ..security.auth import AuthContext, authenticate, client_ip, require_role
from ..security.errors import ApiError
from ..security.ratelimit import enforce


def get_conn() -> Iterator[sqlite3.Connection]:
    with db() as conn:
        yield conn


def current_auth(
    request: Request, conn: sqlite3.Connection = Depends(get_conn)
) -> AuthContext:
    context: Optional[AuthContext] = getattr(request.state, "auth", None)
    if context is not None:
        return context
    return authenticate(conn, request)


def require(minimum: str):
    def dependency(auth: AuthContext = Depends(current_auth)) -> AuthContext:
        require_role(auth, minimum)
        return auth

    return dependency


def policy_guard(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> None:
    """Enforce :data:`ROUTE_POLICY` before any request body is parsed.

    Route-level dependencies run before FastAPI validates the payload, so an
    under-privileged caller always receives a 403 instead of learning whether a
    body it may not submit is well-formed.  A route that is missing from the
    policy fails closed; the authorization-matrix test also fails, so a new route
    cannot ship without an explicit minimum role.
    """
    route = request.scope.get("route")
    template = getattr(route, "path", "") or ""
    key = f"{request.method.upper()} {template}"
    minimum = ROUTE_POLICY.get(key)
    if minimum is None:
        raise ApiError(403, "forbidden", "You do not have permission to perform this action.")
    if minimum == "public":
        return
    context: Optional[AuthContext] = getattr(request.state, "auth", None)
    if context is None:
        context = authenticate(conn, request)
    require_role(context, minimum)


def rate_limit(category: str):
    def dependency(request: Request) -> None:
        allowed, retry_after = enforce(client_ip(request), category)
        if not allowed:
            raise ApiError(
                429,
                "rate_limited",
                "Too many requests. Please retry later.",
                headers={"Retry-After": str(retry_after)},
            )

    return dependency


def rate_limit_account(category: str, account: str):
    allowed, retry_after = enforce(account[:254].lower(), category)
    if not allowed:
        raise ApiError(
            429,
            "rate_limited",
            "Too many requests. Please retry later.",
            headers={"Retry-After": str(retry_after)},
        )


# Minimum role per API route. The authorization-matrix test fails when a route
# is missing from this map, so a new route cannot silently skip the matrix.
ROUTE_POLICY = {
    "GET /api/v1/health": "public",
    "GET /api/v1/meta/rules": "viewer",
    "GET /api/v1/meta/config": "viewer",
    "POST /api/v1/auth/login": "public",
    "POST /api/v1/auth/logout": "viewer",
    "GET /api/v1/auth/me": "viewer",
    "POST /api/v1/auth/change-password": "viewer",
    "POST /api/v1/auth/accept-invite": "public",
    "GET /api/v1/users": "admin",
    "POST /api/v1/users/invite": "admin",
    "PATCH /api/v1/users/{user_id}": "admin",
    "GET /api/v1/dashboard/overview": "viewer",
    "GET /api/v1/targets": "viewer",
    "POST /api/v1/targets": "analyst",
    "GET /api/v1/targets/{target_id}": "viewer",
    "DELETE /api/v1/targets/{target_id}": "admin",
    "POST /api/v1/targets/{target_id}/approve": "admin",
    "POST /api/v1/targets/{target_id}/verify": "analyst",
    "GET /api/v1/targets/{target_id}/baselines": "viewer",
    "POST /api/v1/targets/{target_id}/baselines": "analyst",
    "POST /api/v1/targets/{target_id}/har": "analyst",
    "GET /api/v1/scans": "viewer",
    "POST /api/v1/scans": "analyst",
    "GET /api/v1/scans/{scan_id}": "viewer",
    "POST /api/v1/scans/{scan_id}/start": "analyst",
    "POST /api/v1/scans/{scan_id}/cancel": "analyst",
    "DELETE /api/v1/scans/{scan_id}": "analyst",
    "GET /api/v1/scans/{scan_id}/events": "viewer",
    "GET /api/v1/scans/{scan_id}/endpoints": "viewer",
    "GET /api/v1/scans/{scan_id}/findings": "viewer",
    "GET /api/v1/scans/{scan_id}/comparison": "viewer",
    "GET /api/v1/scans/{scan_id}/export": "viewer",
    "GET /api/v1/endpoints": "viewer",
    "GET /api/v1/endpoints/{endpoint_id}": "viewer",
    "GET /api/v1/findings": "viewer",
    "GET /api/v1/findings/{finding_id}": "viewer",
    "POST /api/v1/findings/{finding_id}/triage": "analyst",
    "PATCH /api/v1/targets/{target_id}": "analyst",
    "POST /api/v1/scans/{scan_id}/retry": "analyst",
    "GET /api/v1/admin/audit": "admin",
    "GET /api/v1/admin/settings": "admin",
    "GET /api/v1/admin/workers": "admin",
    # Training lab. Reads are viewer-level because they change nothing; every mutating
    # lab action is admin-only *and* re-checked in the handler (defence in depth).
    "GET /api/v1/lab/status": "viewer",
    "GET /api/v1/lab/scenarios": "viewer",
    "GET /api/v1/lab/mappings": "viewer",
    "POST /api/v1/lab/start": "admin",
    "POST /api/v1/lab/stop": "admin",
    "POST /api/v1/lab/restart": "admin",
    "POST /api/v1/lab/reset": "admin",
    "POST /api/v1/lab/target": "analyst",
    "POST /api/v1/lab/scan": "analyst",
}
