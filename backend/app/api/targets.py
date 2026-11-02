"""Target registration, authorization, baselines and HAR import."""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from typing import Dict, Iterable, Optional

from fastapi import APIRouter, Depends, Header, Request

from ..db import new_id, now
from ..engine.extractors.har_extract import parse_har
from ..engine.extractors.specs import documented_signatures, is_openapi
from ..engine.parsers import UnsafeDocument, parse_yaml_or_json
from ..engine.safe_http import SafeHttpClient, ScanError
from ..engine.scope import ScopePolicy
from ..engine.urlguard import BlockedDestination, CanonicalURL, canonicalize, is_blocked_ip
from ..security import audit
from ..security.auth import AuthContext, client_ip, require_role
from ..security.errors import ApiError
from ..security.labgrant import grant_for_target
from ..security.tokens import verification_token
from ..config import Settings, get_settings
from .deps import current_auth, get_conn, rate_limit
from .schemas import (
    ApproveTargetRequest,
    BaselineRequest,
    TargetCreateRequest,
    TargetUpdateRequest,
)

router = APIRouter(prefix="/api/v1/targets", tags=["targets"])

VERIFICATION_PATH = "/.well-known/shadowtrace-verification.txt"

# Names that always resolve to loopback and can never be operator-allow-listed by accident.
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}


def is_private_host(host: str) -> bool:
    """True when a target host is loopback, RFC1918, link-local or otherwise non-public.

    Only IP literals and the well-known loopback names can be decided here without DNS;
    a name that *resolves* to private space is caught by the scan-time address check in
    `engine.urlguard.validate_destination`, which is the enforcing control.
    """
    candidate = host.strip().strip("[]").lower().rstrip(".")
    if candidate in _LOOPBACK_NAMES:
        return True
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return is_blocked_ip(address) is not None


def _normalized_prefixes(prefixes: Optional[Iterable[object]]) -> tuple:
    """Order-insensitive comparison key for path prefixes.

    Mirrors ``ScopePolicy.build`` (trailing slash trimmed, ``"" -> "/"``) so that a cosmetic
    difference -- ``"/app/"`` versus ``"/app"``, or a reordered list -- does not look like a
    change of scope and needlessly drop an approval.
    """
    return tuple(sorted({str(item).rstrip("/") or "/" for item in (prefixes or [])}))


def _target_payload(row: sqlite3.Row) -> Dict[str, object]:
    return {
        "id": row["id"],
        "name": row["name"],
        "base_url": row["base_url"],
        "host": row["host"],
        "scheme": row["scheme"],
        "ports": json.loads(row["ports"]),
        "path_prefixes": json.loads(row["path_prefixes"]),
        "authorization_mode": row["authorization_mode"],
        "authorization_status": row["authorization_status"],
        "justification": row["justification"],
        "attestation": row["attestation"],
        "verification_token": row["verification_token"],
        "created_at": row["created_at"],
        "verified_at": row["verified_at"],
        "limits": json.loads(row["limits"] or "{}"),
        # `lab_grant` itself never leaves the server: the UI only needs to know whether
        # this target is reachable for the scanner.
        "lab_granted": bool(row["lab_grant"]) if "lab_grant" in row.keys() else False,
        "scan_ready": str(row["authorization_status"]) == "approved",
    }


def _get_scoped_target(conn: sqlite3.Connection, target_id: str, org_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM targets WHERE id = ? AND org_id = ?", (target_id, org_id)).fetchone()
    if row is None:
        raise ApiError(404, "not_found", "The requested resource was not found.")
    return row


@router.get("")
def list_targets(auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)) -> Dict[str, object]:
    rows = conn.execute("SELECT * FROM targets WHERE org_id = ? ORDER BY created_at DESC", (auth.org_id,)).fetchall()
    return {"targets": [_target_payload(row) for row in rows]}


@router.post("")
def create_target(
    payload: TargetCreateRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "analyst")
    settings = get_settings()
    try:
        canonical = canonicalize(payload.base_url)
    except BlockedDestination as exc:
        if exc.reason == "metadata_hostname":
            # Name the rule instead of the generic URL error: this is a deliberate refusal
            # of a link-local/cloud-metadata destination, and it cannot be allow-listed.
            raise ApiError(
                422,
                "invalid_target",
                "Cloud metadata and link-local destinations can never be a scan target.",
            ) from exc
        raise ApiError(422, "invalid_target", "The target URL is not a canonical http(s) URL.") from exc
    if canonical.port not in payload.ports:
        raise ApiError(422, "invalid_target", "The base URL port must be included in the authorized ports.")
    existing = conn.execute(
        "SELECT id FROM targets WHERE org_id = ? AND host = ?", (auth.org_id, canonical.host)
    ).fetchone()
    if existing is not None:
        raise ApiError(409, "conflict", "A target with this host already exists in your organization.")
    token = verification_token()
    allowlisted = (canonical.host, canonical.port) in set(settings.private_allowlist)
    if payload.authorization_mode == "lab_allowlist" and not settings.lab_enabled:
        raise ApiError(
            422,
            "invalid_target",
            "Lab targets are disabled on this deployment (ST_LAB_ENABLED=false). "
            "Enable the training lab or use an approved production target.",
        )
    if payload.authorization_mode == "lab_allowlist" and not allowlisted:
        raise ApiError(
            422,
            "invalid_target",
            "This host is not on the operator lab allow-list (ST_PRIVATE_ALLOWLIST); "
            f"add {canonical.host}:{canonical.port} in the API and worker environment.",
        )
    # A private destination is an operator decision. Without an ST_PRIVATE_ALLOWLIST entry
    # it is refused here, for every authorization mode, instead of being created and then
    # blocked request-by-request at scan time (and it must never be a way to reach
    # loopback or internal services — see engine/urlguard.validate_destination).
    if not allowlisted and is_private_host(canonical.host):
        raise ApiError(
            422,
            "invalid_target",
            "Private and loopback destinations require an operator ST_PRIVATE_ALLOWLIST entry; "
            "this host is not listed.",
        )
    if payload.authorization_mode == "admin" and not auth.is_admin:
        raise ApiError(403, "forbidden", "Only administrators can self-approve targets.")
    approved = payload.authorization_mode == "lab_allowlist" or (
        payload.authorization_mode == "admin" and auth.is_admin
    )
    target_id = new_id()
    timestamp = now()
    # A lab grant is the scanner's proof that an *operator* (not a tenant admin) authorized
    # this exact private host:port. It is issued only for an approved lab target whose pair
    # is in ST_PRIVATE_ALLOWLIST, and it is signed so the worker can verify it instead of
    # trusting the row. Without it the worker would refuse the destination as policy_blocked.
    lab_grant = (
        grant_for_target(
            conn,
            target_id=target_id,
            scheme=canonical.scheme,
            host=canonical.host,
            port=canonical.port,
            secret=settings.secret_key,
            allowlist=settings.private_allowlist,
        )
        if payload.authorization_mode == "lab_allowlist" and approved
        else None
    )
    conn.execute(
        """
        INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes, authorization_mode,
                             authorization_status, attestation, justification, verification_token, verified_at,
                             verified_by, created_by, created_at, limits, lab_grant, lab_grant_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            target_id,
            auth.org_id,
            payload.name,
            payload.base_url,
            canonical.host,
            canonical.scheme,
            json.dumps(payload.ports),
            json.dumps(payload.path_prefixes),
            payload.authorization_mode,
            "approved" if approved else "pending",
            payload.attestation,
            payload.justification,
            token,
            timestamp if approved else None,
            auth.user_id if approved else None,
            auth.user_id,
            timestamp,
            json.dumps({"max_requests": 300, "max_pages": 12, "max_seconds": 300}),
            lab_grant,
            timestamp if lab_grant else None,
        ),
    )
    audit.record(
        conn,
        action="target.created",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="target",
        object_id=target_id,
        ip=client_ip(request),
        details={
            "host": canonical.host,
            "mode": payload.authorization_mode,
            "status": "approved" if approved else "pending",
            "attestation_present": bool(payload.attestation),
        },
    )
    row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return {"target": _target_payload(row)}


@router.get("/{target_id}")
def get_target(
    target_id: str, auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    row = _get_scoped_target(conn, target_id, auth.org_id)
    return {"target": _target_payload(row)}


def _validate_target_origin(
    *, base_url: str, ports: list, path_prefixes: list, mode: str, settings: "Settings"
) -> CanonicalURL:
    """Shared creation/edit validation. Raises ApiError; returns the canonical URL.

    Editing a target is as security-sensitive as creating one: it can repoint an approved
    target at a different host, add ports or widen the path scope. Everything is therefore
    re-validated with exactly the same rules.
    """
    try:
        canonical = canonicalize(base_url)
    except BlockedDestination as exc:
        if exc.reason == "metadata_hostname":
            raise ApiError(
                422,
                "invalid_target",
                "Cloud metadata and link-local destinations can never be a scan target.",
            ) from exc
        raise ApiError(422, "invalid_target", "The target URL is not a canonical http(s) URL.") from exc
    if canonical.port not in ports:
        raise ApiError(422, "invalid_target", "The base URL port must be included in the authorized ports.")
    allowlisted = (canonical.host, canonical.port) in set(settings.private_allowlist)
    if mode == "lab_allowlist" and not settings.lab_enabled:
        raise ApiError(
            422,
            "invalid_target",
            "Lab targets are disabled on this deployment (ST_LAB_ENABLED=false).",
        )
    if mode == "lab_allowlist" and not allowlisted:
        raise ApiError(
            422,
            "invalid_target",
            "This host is not on the operator lab allow-list (ST_PRIVATE_ALLOWLIST).",
        )
    if not allowlisted and is_private_host(canonical.host):
        raise ApiError(
            422,
            "invalid_target",
            "Private and loopback destinations require an operator ST_PRIVATE_ALLOWLIST entry; "
            "this host is not listed.",
        )
    for prefix in path_prefixes:
        if not str(prefix).startswith("/") or ".." in str(prefix):
            raise ApiError(422, "invalid_target", "Path prefixes must start with / and must not contain ..")
    return canonical


@router.patch("/{target_id}")
def update_target(
    target_id: str,
    payload: "TargetUpdateRequest",
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    """Edit an authorized target. Re-validates every security-relevant field."""
    require_role(auth, "analyst")
    row = _get_scoped_target(conn, target_id, auth.org_id)
    settings = get_settings()
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        raise ApiError(400, "bad_request", "No changes were supplied.")
    if "authorization_mode" in fields and fields["authorization_mode"] != row["authorization_mode"]:
        require_role(auth, "admin")
    active = conn.execute(
        "SELECT COUNT(*) AS n FROM scans WHERE target_id = ? AND state IN ('queued','running','cancelling')",
        (target_id,),
    ).fetchone()["n"]
    name = fields.get("name", row["name"])
    base_url = fields.get("base_url", row["base_url"]).rstrip("/")
    ports = sorted({int(p) for p in fields.get("ports", json.loads(row["ports"]))})
    if not ports or len(ports) > 4 or any(p < 1 or p > 65535 for p in ports):
        raise ApiError(422, "invalid_target", "ports must be one to four valid TCP ports")
    prefixes = fields.get("path_prefixes", json.loads(row["path_prefixes"]))
    mode = fields.get("authorization_mode", row["authorization_mode"])
    canonical = _validate_target_origin(
        base_url=base_url, ports=ports, path_prefixes=prefixes, mode=mode, settings=settings
    )
    if int(active) and (canonical.host != row["host"] or ports != json.loads(row["ports"])):
        raise ApiError(409, "conflict", "Cancel active scans before changing the host or ports.")
    duplicate = conn.execute(
        "SELECT id FROM targets WHERE org_id = ? AND host = ? AND id != ?",
        (auth.org_id, canonical.host, target_id),
    ).fetchone()
    if duplicate is not None:
        raise ApiError(409, "conflict", "Another target already uses this host.")
    approved = str(row["authorization_status"]) == "approved"
    if mode != row["authorization_mode"]:
        approved = mode == "lab_allowlist" or (mode == "admin" and auth.is_admin)

    # --- approval is bound to the scope that was reviewed ---------------------
    # Every field below decides *what gets attacked*. Editing one of them makes the previous
    # approval describe a different origin, so it must not carry over: an analyst could
    # otherwise repoint an admin-approved target at any host and keep the approval, then scan
    # it (BUG-20). Any port-set change counts, including removals -- fail closed, and say so.
    previous_ports = sorted({int(port) for port in json.loads(row["ports"])})
    previous_prefixes = _normalized_prefixes(json.loads(row["path_prefixes"]))
    scope_changed = (
        canonical.host != str(row["host"])
        or canonical.scheme != str(row["scheme"])
        or ports != previous_ports
        or _normalized_prefixes(prefixes) != previous_prefixes
    )
    # A lab target is the one exception: `_validate_target_origin` re-checks it against the
    # operator's ST_PRIVATE_ALLOWLIST on every edit, so the allow-list -- not this row -- is
    # what authorises the destination. Nothing else may skip re-approval.
    approval_revoked = scope_changed and mode != "lab_allowlist"
    if approval_revoked:
        approved = False
    lab_grant = (
        grant_for_target(
            conn,
            target_id=target_id,
            scheme=canonical.scheme,
            host=canonical.host,
            port=canonical.port,
            secret=settings.secret_key,
            allowlist=settings.private_allowlist,
        )
        if mode == "lab_allowlist" and approved
        else None
    )
    # A verification/approval stamp describes one origin, so it goes with the old scope.
    verified_at = None if scope_changed else row["verified_at"]
    verified_by = None if scope_changed else row["verified_by"]
    conn.execute(
        """
        UPDATE targets SET name = ?, base_url = ?, host = ?, scheme = ?, ports = ?, path_prefixes = ?,
                           authorization_mode = ?, authorization_status = ?, lab_grant = ?, lab_grant_at = ?,
                           justification = ?, verified_at = ?, verified_by = ?
        WHERE id = ? AND org_id = ?
        """,
        (
            name,
            base_url,
            canonical.host,
            canonical.scheme,
            json.dumps(ports),
            json.dumps(prefixes),
            mode,
            "approved" if approved else "pending",
            lab_grant,
            now() if lab_grant else None,
            fields.get("justification", row["justification"]),
            verified_at,
            verified_by,
            target_id,
            auth.org_id,
        ),
    )
    if approval_revoked:
        # Its own action, so an operator can alert on it: "an approved origin changed and
        # the approval did not follow" is exactly the event the old code failed to raise.
        audit.record(
            conn,
            action="target.approval_revoked",
            org_id=auth.org_id,
            actor_type="user",
            actor_id=auth.user_id,
            object_type="target",
            object_id=target_id,
            ip=client_ip(request),
            details={
                "from": {
                    "host": str(row["host"]),
                    "scheme": str(row["scheme"]),
                    "ports": previous_ports,
                    "path_prefixes": list(previous_prefixes),
                },
                "to": {
                    "host": canonical.host,
                    "scheme": canonical.scheme,
                    "ports": ports,
                    "path_prefixes": sorted(_normalized_prefixes(prefixes)),
                },
                "mode": mode,
                "reason": "security scope changed; administrator approval required again",
            },
        )
    audit.record(
        conn,
        action="target.updated",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="target",
        object_id=target_id,
        ip=client_ip(request),
        details={
            "changed": sorted(fields),
            "host": canonical.host,
            "ports": ports,
            "mode": mode,
            "lab_granted": bool(lab_grant),
            "scope_changed": scope_changed,
            "approval_revoked": approval_revoked,
        },
    )
    refreshed = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return {"target": _target_payload(refreshed)}


@router.delete("/{target_id}")
def delete_target(
    target_id: str,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "admin")
    row = _get_scoped_target(conn, target_id, auth.org_id)
    active = conn.execute(
        "SELECT COUNT(*) AS n FROM scans WHERE target_id = ? AND state IN ('queued','running','cancelling')",
        (target_id,),
    ).fetchone()["n"]
    if int(active):
        raise ApiError(409, "conflict", "Cancel active scans before deleting this target.")
    conn.execute("DELETE FROM targets WHERE id = ? AND org_id = ?", (target_id, auth.org_id))
    audit.record(
        conn,
        action="target.deleted",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="target",
        object_id=str(row["id"]),
        ip=client_ip(request),
        details={"host": row["host"]},
    )
    return {"ok": True}


@router.post("/{target_id}/approve")
def approve_target(
    target_id: str,
    payload: ApproveTargetRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "admin")
    row = _get_scoped_target(conn, target_id, auth.org_id)
    settings = get_settings()
    lab_grant = (
        grant_for_target(
            conn,
            target_id=target_id,
            scheme=str(row["scheme"]),
            host=str(row["host"]),
            port=canonicalize(str(row["base_url"])).port,
            secret=settings.secret_key,
            allowlist=settings.private_allowlist,
        )
        if str(row["authorization_mode"]) == "lab_allowlist"
        else None
    )
    conn.execute(
        "UPDATE targets SET authorization_status = 'approved', justification = ?, verified_at = ?, "
        "verified_by = ?, lab_grant = ?, lab_grant_at = ? WHERE id = ? AND org_id = ?",
        (
            payload.justification,
            now(),
            auth.user_id,
            lab_grant,
            now() if lab_grant else None,
            target_id,
            auth.org_id,
        ),
    )
    audit.record(
        conn,
        action="target.approved",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="target",
        object_id=target_id,
        ip=client_ip(request),
        details={"host": row["host"], "justification": payload.justification},
    )
    refreshed = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return {"target": _target_payload(refreshed)}


@router.post("/{target_id}/verify")
def verify_target(
    target_id: str,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "analyst")
    row = _get_scoped_target(conn, target_id, auth.org_id)
    settings = get_settings()
    ports = json.loads(row["ports"])
    scope = ScopePolicy.build(host=str(row["host"]), ports=[int(port) for port in ports])
    verification_url = f"{row['scheme']}://{row['host']}:{int(ports[0])}{VERIFICATION_PATH}" if int(ports[0]) not in (80, 443) else f"{row['scheme']}://{row['host']}{VERIFICATION_PATH}"
    client = SafeHttpClient(settings, scope=scope)
    verified = False
    try:
        response = client.request("GET", verification_url)
        if response.status == 200:
            body = response.text.strip()[:200]
            verified = body == str(row["verification_token"])
    except ScanError:
        verified = False
    # Publishing the challenge proves *control of the host*. That is the whole contract of
    # `ownership` mode, and only of it: an `admin` or `lab_allowlist` target is authorised by
    # an operator, so passing the challenge may not substitute for that decision. Without
    # this, a repointed admin target that has just dropped to `pending` could be re-approved
    # by the analyst who repointed it -- the token is visible in the target payload.
    mode = str(row["authorization_mode"])
    self_approved = verified and mode == "ownership"
    if self_approved:
        conn.execute(
            "UPDATE targets SET authorization_status = 'approved', verified_at = ?, verified_by = ? WHERE id = ? AND org_id = ?",
            (now(), auth.user_id, target_id, auth.org_id),
        )
    audit.record(
        conn,
        action="target.ownership_checked",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="target",
        object_id=target_id,
        ip=client_ip(request),
        details={
            "verified": verified,
            "host": row["host"],
            "mode": mode,
            "self_approved": self_approved,
        },
    )
    refreshed = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return {
        "verified": verified,
        "self_approved": self_approved,
        "requires_admin_approval": verified and not self_approved,
        "target": _target_payload(refreshed),
    }


@router.get("/{target_id}/baselines")
def list_baselines(
    target_id: str, auth: AuthContext = Depends(current_auth), conn: sqlite3.Connection = Depends(get_conn)
) -> Dict[str, object]:
    _get_scoped_target(conn, target_id, auth.org_id)
    rows = conn.execute(
        "SELECT id, source, source_ref, endpoint_count, created_at FROM baselines WHERE target_id = ? AND org_id = ? ORDER BY created_at DESC",
        (target_id, auth.org_id),
    ).fetchall()
    return {
        "baselines": [
            {
                "id": row["id"],
                "source": row["source"],
                "source_ref": row["source_ref"],
                "endpoint_count": row["endpoint_count"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


@router.post("/{target_id}/baselines")
def create_baseline(
    target_id: str,
    payload: BaselineRequest,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
) -> Dict[str, object]:
    require_role(auth, "analyst")
    _get_scoped_target(conn, target_id, auth.org_id)  # 404 unless the target is in this org
    if payload.source == "url":
        if not payload.url:
            raise ApiError(422, "invalid_baseline", "A specification URL is required.")
        client = SafeHttpClient(get_settings())
        try:
            response = client.request("GET", payload.url)
        except ScanError as exc:
            raise ApiError(422, "invalid_baseline", "The specification could not be fetched safely.") from exc
        if response.status != 200:
            raise ApiError(422, "invalid_baseline", "The specification URL did not return HTTP 200.")
        text = response.text[:4_000_000]
        source_ref = payload.url[:500]
    else:
        if not payload.content:
            raise ApiError(422, "invalid_baseline", "Specification content is required.")
        text = payload.content
        source_ref = "upload"
    try:
        document = parse_yaml_or_json(text)
    except UnsafeDocument as exc:
        raise ApiError(422, "invalid_baseline", "The specification could not be parsed safely.") from exc
    if not is_openapi(document):
        raise ApiError(422, "invalid_baseline", "The document is not an OpenAPI 2.x/3.x specification.")
    signatures = documented_signatures(document)
    if not signatures:
        raise ApiError(422, "invalid_baseline", "The specification documents no operations.")
    baseline_id = new_id()
    conn.execute(
        """
        INSERT INTO baselines (id, org_id, target_id, source, source_ref, spec, endpoint_count, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (baseline_id, auth.org_id, target_id, payload.source, source_ref, text[:4_000_000], len(signatures), auth.user_id, now()),
    )
    audit.record(
        conn,
        action="baseline.created",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="baseline",
        object_id=baseline_id,
        ip=client_ip(request),
        details={"target_id": target_id, "endpoints": len(signatures), "source": payload.source},
    )
    return {"id": baseline_id, "endpoint_count": len(signatures), "source": payload.source, "target_id": target_id}


@router.post("/{target_id}/har")
async def import_har(
    target_id: str,
    request: Request,
    auth: AuthContext = Depends(current_auth),
    conn: sqlite3.Connection = Depends(get_conn),
    x_har_name: Optional[str] = Header(default=None, alias="X-Har-Name"),
    _limit=Depends(rate_limit("api")),
) -> Dict[str, object]:
    require_role(auth, "analyst")
    target = _get_scoped_target(conn, target_id, auth.org_id)
    raw = await request.body()
    if not raw:
        raise ApiError(422, "invalid_har", "The HAR body is empty.")
    if len(raw) > get_settings().max_upload_bytes:
        raise ApiError(413, "payload_too_large", "The HAR file is too large.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(415, "unsupported_media_type", "The HAR file must be UTF-8 JSON.") from exc
    har = parse_har(
        text,
        source_name=(x_har_name or "upload.har")[:120],
        base_url=str(target["base_url"]),
        policy_hosts=(str(target["host"]),),
    )
    if har.entries_total == 0:
        raise ApiError(422, "invalid_har", "The upload is not a HAR 1.2 document with entries.")
    import_id = new_id()
    conn.execute(
        """
        INSERT INTO har_imports (id, org_id, target_id, name, entries, entry_count, created_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            import_id,
            auth.org_id,
            target_id,
            (x_har_name or "upload.har")[:120],
            json.dumps(har.redacted_entries, separators=(",", ":")),
            har.entries_total,
            auth.user_id,
            now(),
        ),
    )
    audit.record(
        conn,
        action="har.imported",
        org_id=auth.org_id,
        actor_type="user",
        actor_id=auth.user_id,
        object_type="har_import",
        object_id=import_id,
        ip=client_ip(request),
        details={"entries": har.entries_total, "in_scope": har.entries_in_scope, "out_of_scope": har.entries_out_of_scope},
    )
    return {
        "id": import_id,
        "entries_total": har.entries_total,
        "entries_in_scope": har.entries_in_scope,
        "entries_out_of_scope": har.entries_out_of_scope,
        "entries_dropped": har.entries_dropped,
        "endpoints_found": len(har.result.endpoints),
    }
