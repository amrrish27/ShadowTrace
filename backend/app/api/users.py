"""User and invitation administration (admin-only)."""
from __future__ import annotations

import sqlite3
from typing import Dict

from fastapi import APIRouter, Depends, Request

from ..db import new_id, now
from ..security import audit
from ..security.auth import AuthContext, client_ip, require_role, user_public
from ..security.errors import ApiError
from ..security.tokens import generate_token, hash_token
from .deps import current_auth, get_conn, rate_limit
from .schemas import InviteRequest, UserUpdateRequest

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get("")
def list_users(
    auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    require_role(auth, "admin")
    rows = conn.execute(
        "SELECT id, email, name, role, is_active, created_at, last_login_at FROM users WHERE org_id = ? ORDER BY created_at",
        (auth.org_id,),
    ).fetchall()
    return {"users": [user_public(dict(row)) for row in rows]}


@router.post("/invite")
def invite_user(
    payload: InviteRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
    _limit=Depends(rate_limit("invite")),
) -> Dict[str, object]:
    require_role(auth, "admin")
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (payload.email,)).fetchone():
        raise ApiError(409, "conflict", "A user with this email already exists.")
    token = generate_token()
    invitation_id = new_id()
    conn.execute(
        """
        INSERT INTO invitations (id, org_id, email, role, token_hash, invited_by, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (invitation_id, auth.org_id, payload.email, payload.role, hash_token(token), auth.user_id, now(), now() + 7 * 86400),
    )
    audit.record(
        conn,
        action="user.invited",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="invitation",
        object_id=invitation_id,
        ip=client_ip(request),
        details={"email": payload.email, "role": payload.role},
    )
    # No mail transport is configured in this deployment: the single-use token is
    # returned to the inviting admin to deliver out of band, and only its hash is stored.
    return {"id": invitation_id, "email": payload.email, "role": payload.role, "token": token, "expires_in": 7 * 86400}


@router.patch("/{user_id}")
def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "admin")
    row = conn.execute(
        "SELECT id, role, is_active FROM users WHERE id = ? AND org_id = ?", (user_id, auth.org_id)
    ).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "The requested resource was not found.")
    new_role = payload.role if payload.role is not None else str(row["role"])
    new_active = payload.is_active if payload.is_active is not None else bool(row["is_active"])
    if user_id == auth.user_id and (new_role != auth.role or not new_active):
        raise ApiError(409, "conflict", "You cannot change your own role or disable your own account.")
    if str(row["role"]) == "admin" and (new_role != "admin" or not new_active):
        admins = conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE org_id = ? AND role = 'admin' AND is_active = 1 AND id <> ?",
            (auth.org_id, user_id),
        ).fetchone()["n"]
        if int(admins) == 0:
            raise ApiError(409, "conflict", "At least one active administrator must remain.")
    conn.execute("UPDATE users SET role = ?, is_active = ? WHERE id = ? AND org_id = ?", (new_role, 1 if new_active else 0, user_id, auth.org_id))
    if new_role != str(row["role"]):
        conn.execute("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL", (now(), user_id))
    audit.record(
        conn,
        action="user.role_changed" if new_role != str(row["role"]) else "user.updated",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="user",
        object_id=user_id,
        ip=client_ip(request),
        details={"from_role": row["role"], "to_role": new_role, "is_active": new_active},
    )
    refreshed = conn.execute(
        "SELECT id, email, name, role, is_active, created_at, last_login_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return {"user": user_public(dict(refreshed))}
