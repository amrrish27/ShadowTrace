"""Signed lab grants: how an approved lab target becomes reachable by the scanner.

Background
----------
Round 7 removed a real vulnerability: the scanner used to treat *any* port declared on a
target record as permission to reach a private address, so an organization admin could
point the scanner at ``127.0.0.1`` or RFC1918 space and read the responses. After that fix
the only way to reach a non-public destination was the operator's ``ST_PRIVATE_ALLOWLIST``
— correct for the *scanner*, but it left a gap: the API process knew that a target was an
operator-authorized lab target and the worker process did not, so an approved
``http://127.0.0.1:8099`` target produced ``policy_blocked`` on every request whenever the
worker's environment lacked the same allow-list entry. That is a configuration-drift
footgun, and it blocked the intended single-machine demo.

A lab grant closes that gap without reopening the hole:

* The API issues a grant **only** while the operator allow-list in the API process still
  contains the exact ``host:port``, the target is ``approved`` and its mode is
  ``lab_allowlist``. An organization admin cannot mint one: creating a private target
  without the operator entry is refused (422) before a grant is considered.
* The grant is an HMAC over ``target_id|scheme|host|port`` keyed with ``ST_SECRET_KEY``,
  so it cannot be forged from a row copied out of another deployment, and it is bound to
  a single target — it cannot be replayed for another host or port.
* The scanner verifies the signature against the target row at scan time. Anything that
  does not verify is ignored, and the request falls back to the ordinary policy, which
  blocks it.
* Revocation is real: :func:`sync_grants` recomputes every grant against the allow-list
  currently in force at API startup (and on demand via ``POST /api/v1/admin/lab/sync``).
  A grant that no longer matches is cleared, so removing the allow-list entry stops the
  next scan.

Metadata and link-local addresses are still refused *before* a grant is consulted
(``urlguard.is_always_blocked``), for every target including the lab.
"""
from __future__ import annotations

import hmac
import json
import logging
from hashlib import sha256
from typing import Dict, Iterable, Optional, Tuple

from ..db import now

log = logging.getLogger("shadowtrace.labgrant")

SCHEMES = {"http", "https"}

__all__ = [
    "grant_message",
    "grant_signature",
    "verify_grant",
    "parse_ports",
    "lab_grant_ports",
    "grant_for_target",
    "sync_grants",
]


def _norm_host(host: object) -> str:
    return str(host or "").strip().lower().strip("[]")


def grant_message(target_id: str, scheme: str, host: str, port: int) -> str:
    """Canonical message a grant signs. Deliberately narrow: one target, one origin."""
    return f"lab-v1|{target_id}|{scheme.lower()}|{_norm_host(host)}|{int(port)}"


def grant_signature(secret: str, target_id: str, scheme: str, host: str, port: int) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        grant_message(target_id, scheme, host, port).encode("utf-8"),
        sha256,
    ).hexdigest()


def verify_grant(
    secret: str,
    signature: Optional[str],
    target_id: str,
    scheme: str,
    host: str,
    port: int,
) -> bool:
    """Constant-time check. An empty secret or signature never verifies."""
    if not signature or not secret:
        return False
    return hmac.compare_digest(grant_signature(secret, target_id, scheme, host, port), str(signature))


def parse_ports(raw: object) -> Tuple[int, ...]:
    """Read the JSON port list off a target row, tolerating a malformed value."""
    try:
        values = json.loads(str(raw or "[]"))
    except (TypeError, ValueError):
        return ()
    ports = []
    for value in values if isinstance(values, list) else []:
        try:
            ports.append(int(value))
        except (TypeError, ValueError):
            continue
    return tuple(ports)


def lab_grant_ports(
    target: Dict[str, object], secret: str, scheme: Optional[str] = None
) -> Tuple[Tuple[str, int], ...]:
    """The ``(host, port)`` pairs this target row may legitimately reach privately.

    This is the single gate the scanner consults. It returns an empty tuple — never an
    exception — so a malformed or tampered row degrades to "no grant", which the egress
    policy then blocks.
    """
    if str(target.get("authorization_mode") or "") != "lab_allowlist":
        return ()
    if str(target.get("authorization_status") or "") != "approved":
        return ()
    signature = target.get("lab_grant")
    if not signature:
        return ()
    target_id = str(target.get("id") or "")
    host = _norm_host(target.get("host"))
    target_scheme = str(scheme or target.get("scheme") or "").lower()
    if not target_id or not host or target_scheme not in SCHEMES:
        return ()
    granted: list[Tuple[str, int]] = []
    for port in parse_ports(target.get("ports")):
        if verify_grant(secret, str(signature), target_id, target_scheme, host, port):
            granted.append((host, port))
    return tuple(granted)


def grant_for_target(
    conn,
    *,
    target_id: str,
    scheme: str,
    host: str,
    port: int,
    secret: str,
    allowlist: Iterable[Tuple[str, int]],
) -> Optional[str]:
    """Compute the grant to store for a target, or ``None`` when it is not authorized.

    The allow-list is the API process's operator configuration. When it does not contain
    the exact pair, no grant exists — the target stays reachable only through ordinary
    policy (which blocks non-public destinations).
    """
    allowed = {(_norm_host(h), int(p)) for h, p in allowlist}
    if (_norm_host(host), int(port)) not in allowed:
        return None
    return grant_signature(secret, target_id, scheme, host, port)


def sync_grants(conn, *, secret: str, allowlist: Iterable[Tuple[str, int]]) -> Dict[str, int]:
    """Reconcile every stored grant with the operator allow-list currently in force.

    Called at API startup and by ``POST /api/v1/admin/lab/sync``. Returns counters so the
    operator (and the tests) can see what changed.
    """
    allowed = {(_norm_host(h), int(p)) for h, p in allowlist}
    issued = 0
    cleared = 0
    rows = conn.execute(
        "SELECT id, scheme, host, ports, authorization_mode, authorization_status FROM targets"
    ).fetchall()
    for row in rows:
        host = _norm_host(row["host"])
        scheme = str(row["scheme"]).lower()
        eligible = str(row["authorization_mode"]) == "lab_allowlist" and str(
            row["authorization_status"]
        ) == "approved"
        port = next((p for p in parse_ports(row["ports"]) if (host, p) in allowed), None)
        if not eligible or port is None:
            cleared += conn.execute(
                "UPDATE targets SET lab_grant = NULL, lab_grant_at = NULL "
                "WHERE id = ? AND lab_grant IS NOT NULL",
                (row["id"],),
            ).rowcount
            continue
        signature = grant_signature(secret, str(row["id"]), scheme, host, port)
        existing = conn.execute(
            "SELECT lab_grant FROM targets WHERE id = ?", (row["id"],)
        ).fetchone()
        if existing is not None and existing["lab_grant"] == signature:
            continue
        conn.execute(
            "UPDATE targets SET lab_grant = ?, lab_grant_at = ? WHERE id = ?",
            (signature, now(), row["id"]),
        )
        issued += 1
    conn.commit()
    if issued or cleared:
        log.info("lab_grants_synced issued=%s cleared=%s", issued, cleared)
    return {"issued": issued, "cleared": cleared, "allowlist_entries": len(allowed)}
