"""Authentication routes: login, logout, me, password change, invitation acceptance."""
from __future__ import annotations

import sqlite3
from typing import Dict

from fastapi import APIRouter, Depends, Request, Response

from ..db import now
from ..security import audit
from ..security.auth import (
    AuthContext,
    _origin_allowed,
    audit_login,
    clear_session_cookies,
    client_ip,
    create_session,
    revoke_all_sessions,
    revoke_session,
)
from ..security.errors import ApiError
from ..security.passwords import hash_password, validate_password, verify_password, WeakPassword
from ..security.ratelimit import enforce
from ..security.tokens import hash_token
from .deps import current_auth, get_conn, rate_limit
from .schemas import AcceptInviteRequest, ChangePasswordRequest, LoginRequest

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _user_payload(row: sqlite3.Row) -> Dict[str, object]:
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "org_id": row["org_id"],
    }


@router.post("/login")
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    conn: sqlite3.Connection = Depends(get_conn),
    _ip_limit=Depends(rate_limit("login_ip")),
) -> Dict[str, object]:
    # Login CSRF: a cross-site form post must not be able to sign a victim into an
    # attacker-controlled account. SameSite=Strict already covers modern browsers; this
    # keeps the login route consistent with every other state-changing endpoint.
    origin = request.headers.get("origin", "")
    if origin and not _origin_allowed(origin, request):
        raise ApiError(403, "csrf_failed", "The request could not be verified.")
    allowed, retry_after = enforce(payload.email.lower(), "login_account")
    if not allowed:
        # A refused attempt must leave a trace. Otherwise the operator cannot tell "never
        # tried" from "rate limited", and the 401 that preceded it is the only evidence --
        # which is exactly the ambiguity that made a password problem look like a lockout.
        audit.record(
            conn,
            action="auth.login_rate_limited",
            org_id=None,
            actor_type="anonymous",
            ip=client_ip(request),
            details={"email": payload.email[:254], "retry_after": int(retry_after)},
            durable=True,
        )
        raise ApiError(429, "rate_limited", "Too many attempts. Please retry later.", headers={"Retry-After": str(retry_after)})
    row = conn.execute("SELECT * FROM users WHERE email = ?", (payload.email.lower(),)).fetchone()
    password_ok = verify_password(payload.password, row["password_hash"] if row else None)
    if row is None or not password_ok or not row["is_active"]:
        audit_login(conn, request, email=payload.email, user_id=row["id"] if row else None, org_id=row["org_id"] if row else None, success=False, reason="invalid_credentials")
        raise ApiError(401, "invalid_credentials", "Email or password is incorrect.")
    conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now(), row["id"]))
    create_session(conn, user_id=row["id"], request=request, response=response, rotate=True)
    audit_login(conn, request, email=payload.email, user_id=row["id"], org_id=row["org_id"], success=True)
    audit.record(conn, action="session.created", org_id=row["org_id"], actor_type="user", actor_id=row["id"], ip=client_ip(request))
    return {"user": _user_payload(row)}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    revoke_session(conn, auth.session_id)
    clear_session_cookies(response)
    audit.record(conn, action="auth.logout", org_id=auth.org_id, actor_type="user", actor_id=auth.user_id, ip=client_ip(request))
    return {"ok": True}


@router.get("/me")
def me(auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)) -> Dict[str, object]:
    row = conn.execute(
        "SELECT id, email, name, role, org_id, created_at, last_login_at FROM users WHERE id = ?", (auth.user_id,)
    ).fetchone()
    return {
        "user": _user_payload(row),
        "csrf_token": auth.csrf_token,
        "organization": conn.execute("SELECT id, name FROM organizations WHERE id = ?", (auth.org_id,)).fetchone()["name"],
    }


@router.post("/change-password")
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (auth.user_id,)).fetchone()
    if not verify_password(payload.current_password, row["password_hash"]):
        audit.record(
            conn,
            action="auth.password_change_failed",
            org_id=auth.org_id,
            actor_type="user",
            actor_id=auth.user_id,
            ip=client_ip(request),
            durable=True,
        )
        raise ApiError(400, "invalid_password", "The current password is incorrect.")
    try:
        validate_password(payload.new_password, email=auth.email, name=auth.name)
    except WeakPassword as exc:
        raise ApiError(422, "weak_password", str(exc))
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(payload.new_password), auth.user_id))
    revoke_all_sessions(conn, auth.user_id, except_session=auth.session_id)
    audit.record(conn, action="auth.password_changed", org_id=auth.org_id, actor_type="user", actor_id=auth.user_id, ip=client_ip(request))
    return {"ok": True}


@router.post("/accept-invite")
def accept_invite(
    payload: AcceptInviteRequest,
    request: Request,
    response: Response,
    conn: sqlite3.Connection = Depends(get_conn),
    _ip_limit=Depends(rate_limit("login_ip")),
) -> Dict[str, object]:
    token_hash = hash_token(payload.token)
    invitation = conn.execute(
        "SELECT * FROM invitations WHERE token_hash = ? AND accepted_at IS NULL", (token_hash,)
    ).fetchone()
    if invitation is None or int(invitation["expires_at"]) < now():
        raise ApiError(400, "invalid_invitation", "This invitation is invalid or has expired.")
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (invitation["email"],)).fetchone():
        raise ApiError(409, "conflict", "An account with this email already exists.")
    try:
        validate_password(payload.password, email=invitation["email"])
    except WeakPassword as exc:
        raise ApiError(422, "weak_password", str(exc))
    from ..db import new_id

    user_id = new_id()
    conn.execute(
        """
        INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (user_id, invitation["org_id"], invitation["email"], payload.name, invitation["role"], hash_password(payload.password), now()),
    )
    conn.execute("UPDATE invitations SET accepted_at = ? WHERE id = ?", (now(), invitation["id"]))
    audit.record(conn, action="auth.invitation_accepted", org_id=invitation["org_id"], actor_type="user", actor_id=user_id, ip=client_ip(request))
    create_session(conn, user_id=user_id, request=request, response=response, rotate=False)
    return {"ok": True, "user": {"id": user_id, "email": invitation["email"], "name": payload.name, "role": invitation["role"], "org_id": invitation["org_id"]}}
