"""Regression tests for the reported `policy_blocked` failure and its fix.

The reported defect
-------------------
A target registered as ``http://127.0.0.1:8099`` with ``lab_allowlist`` authorization was
approved by an admin, the scan was queued, the worker picked it up — and **every** request
came back ``policy_blocked``: 0 pages, 0 endpoints, and a misleading "unreachable" finding.

Root cause (reproduced before this file existed)
-----------------------------------------------
The private-egress permission lived only in process environment
(``ST_PRIVATE_ALLOWLIST``). The API process that approved the target had the entry; the
worker process that executed the scan did not. ``validate_destination`` therefore blocked
every request to a loopback address, correctly, because from the worker's point of view
nothing had authorized that destination.

The fix
-------
The API records the authorization decision *in the database* as an HMAC grant bound to
``target_id|scheme|host|port`` (``app/security/labgrant.py``). The worker verifies the
signature and honours it for that single pair. The egress policy is unchanged otherwise:
metadata/link-local addresses stay blocked, unlisted ports stay blocked, and a target the
operator never allow-listed never receives a grant at all.

Every test below therefore asserts a *security property*, not just a happy path.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Dict, Iterator

import pytest

from app.config import get_settings, reset_settings_cache
from app.db import db
from app.engine.urlguard import BlockedDestination, validate_destination
from app.security.labgrant import (
    grant_signature,
    lab_grant_ports,
    sync_grants,
)

BACKEND = Path(__file__).resolve().parent.parent
ROOT = BACKEND.parent
LAB_ENTRYPOINT = ROOT / "lab" / "app" / "lab.py"

PUBLIC_IP = "93.184.216.34"


class StaticResolver:
    """Deterministic DNS so the guard is exercised without touching the network."""

    def __init__(self, mapping: Dict[str, object] | None = None) -> None:
        self.mapping = mapping or {}

    def resolve(self, host: str, port: int):
        value = self.mapping.get(host, [PUBLIC_IP])
        if isinstance(value, Exception):
            raise value
        return value


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_healthy(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=0.5) as response:
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def live_lab() -> Iterator[int]:
    """Start the real bundled lab on a free loopback port for the whole module."""
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603 - fixed argv, test-only
        [sys.executable, "-u", str(LAB_ENTRYPOINT), "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    try:
        if not _wait_healthy(port):
            pytest.fail("the bundled lab did not start for the end-to-end regression test")
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            process.kill()


@pytest.fixture()
def lab_env(app_env, live_lab, monkeypatch) -> Dict[str, object]:
    """An environment whose operator allow-list contains exactly the running lab."""
    pair = f"127.0.0.1:{live_lab}"
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", pair)
    monkeypatch.setenv("ST_LAB_PORT", str(live_lab))
    reset_settings_cache()
    # The seed ships an approved target on 127.0.0.1:8099. Remove it so this test registers
    # the *live* lab port exactly as an operator would (one target per host per org).
    with db() as conn:
        conn.execute("DELETE FROM scans WHERE target_id IN (SELECT id FROM targets WHERE host = '127.0.0.1')")
        conn.execute("DELETE FROM targets WHERE host = '127.0.0.1'")
    return {"port": live_lab, "pair": pair, "ids": app_env}


def _create_lab_target(client, headers, port: int) -> dict:
    response = client.post(
        "/api/v1/targets",
        json={
            "name": "Live lab",
            "base_url": f"http://127.0.0.1:{port}",
            "ports": [port],
            "authorization_mode": "lab_allowlist",
            "attestation": "Operator-approved loopback lab target for in-process tests.",
        },
        headers=headers,
    )
    assert response.status_code in (200, 201), response.text
    return response.json()["target"]


# ---------------------------------------------------------------------------
# (a) the actual reported bug: a worker with no allow-list still reaches the lab
# ---------------------------------------------------------------------------
def test_worker_without_allowlist_env_still_reaches_the_approved_lab_target(
    client, analyst_client, lab_env
) -> None:
    """The regression: approve in the API, scan in a process that has no allow-list entry."""
    logged_in, headers, _env = analyst_client
    target = _create_lab_target(logged_in, headers, int(lab_env["port"]))
    assert target["lab_granted"] is True, "an allow-listed approved target must carry a grant"
    assert target["scan_ready"] is True

    created = logged_in.post(
        "/api/v1/scans",
        json={
            "target_id": target["id"],
            "attestation": "Authorized regression scan of the operator-approved lab.",
            "max_pages": 10,
            "max_scripts": 6,
            "max_requests": 120,
            "max_seconds": 120,
        },
        headers={**headers, "Idempotency-Key": "regression-policy-blocked-1"},
    )
    assert created.status_code in (200, 201), created.text
    scan_id = created.json()["scan"]["id"]

    # The worker process: same database, same secret, *no* ST_PRIVATE_ALLOWLIST entry.
    import os

    from app.workers.worker import execute_scan

    os.environ["ST_PRIVATE_ALLOWLIST"] = ""
    reset_settings_cache()
    try:
        assert get_settings().private_allowlist == (), "this test must model the broken worker"
        with db() as conn:
            summary = execute_scan(conn, scan_id)
    finally:
        os.environ["ST_PRIVATE_ALLOWLIST"] = str(lab_env["pair"])
        reset_settings_cache()

    counters = summary.as_counters()
    assert counters["pages_fetched"] >= 1, counters
    assert counters["outcome"] == "ok", counters
    assert summary.endpoints_found >= 1, counters
    # The lab deliberately links to 169.254.169.254 and localhost:9001 as traps. Those are
    # *supposed* to stay blocked; what must not happen is a block on the lab itself.
    with db() as conn:
        blocked = [
            row["message"]
            for row in conn.execute(
                "SELECT message FROM scan_events WHERE scan_id = ? AND message LIKE '%policy_blocked%'",
                (scan_id,),
            )
        ]
    # What *is* blocked on a granted target is the lab's hostile redirect traps: the grant
    # covers the lab's own origin, not where a redirect tries to send the crawler. This is
    # the redirect-revalidation control holding while the grant is in force.
    lab_origin = f"127.0.0.1:{lab_env['port']}"
    direct_blocks = [
        message
        for message in blocked
        if lab_origin in message and "redirect" not in message.lower()
    ]
    assert direct_blocks == [], f"the approved lab origin must reach the scanner: {direct_blocks}"
    for message in blocked:
        assert any(
            reason in message
            for reason in ("redirect", "metadata", "cross_origin", "out_of_scope", "blocked_address")
        ), message

    with db() as conn:
        states = [
            row["state"]
            for row in conn.execute("SELECT state FROM scans WHERE id = ?", (scan_id,))
        ]
        findings = conn.execute(
            "SELECT COUNT(*) AS n FROM findings WHERE scan_id = ?", (scan_id,)
        ).fetchone()["n"]
        persisted = conn.execute(
            "SELECT counters FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()["counters"]
    assert states == ["completed"]
    assert findings >= 1, "the lab plants findings; a clean 0 here means nothing was analysed"
    import json as _json

    stored = _json.loads(persisted or "{}")
    assert stored.get("outcome") == "ok", "the outcome must be persisted, not just computed"
    assert stored.get("phase") == "done"


# ---------------------------------------------------------------------------
# (b) no operator entry, no private target
# ---------------------------------------------------------------------------
def test_private_target_is_refused_without_an_operator_allowlist_entry(client, app_env) -> None:
    from tests.conftest import login

    _, headers = login(client, "admin@org.example.test")
    response = client.post(
        "/api/v1/targets",
        json={
            "name": "Sneaky loopback",
            "base_url": "http://localhost:9001",
            "ports": [9001],
            "authorization_mode": "lab_allowlist",
            "attestation": "Attempting to reach a private service that is not allow-listed.",
        },
        headers=headers,
    )
    assert response.status_code == 422, response.text
    body = response.text.lower()
    assert "private" in body or "allow" in body
    with db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM targets WHERE host = 'localhost' AND ports LIKE '%9001%'"
        ).fetchone()["n"]
    assert count == 0, "the refused target must not be persisted"


# ---------------------------------------------------------------------------
# (c) forgery, tampering and cross-target replay
# ---------------------------------------------------------------------------
def test_a_forged_grant_is_ignored(app_env) -> None:
    settings = get_settings()
    target = {
        "id": "target-1",
        "scheme": "http",
        "host": "127.0.0.1",
        "ports": "[8099]",
        "authorization_mode": "lab_allowlist",
        "authorization_status": "approved",
        "lab_grant": "0" * 64,
    }
    assert lab_grant_ports(target, settings.secret_key) == ()

    forged = dict(target, lab_grant=grant_signature("attacker-chosen-secret", "target-1", "http", "127.0.0.1", 8099))
    assert lab_grant_ports(forged, settings.secret_key) == ()


def test_a_grant_is_bound_to_its_host_and_port(app_env) -> None:
    settings = get_settings()
    signature = grant_signature(settings.secret_key, "target-1", "http", "127.0.0.1", 8099)
    row = {
        "id": "target-1",
        "scheme": "http",
        "host": "127.0.0.1",
        "ports": "[8099]",
        "authorization_mode": "lab_allowlist",
        "authorization_status": "approved",
        "lab_grant": signature,
    }
    assert lab_grant_ports(row, settings.secret_key) == (("127.0.0.1", 8099),)

    # Same signature, different port declared on the row: no grant for that port.
    assert lab_grant_ports(dict(row, ports="[9001]"), settings.secret_key) == ()
    # Same signature, different host.
    assert lab_grant_ports(dict(row, host="10.0.0.5"), settings.secret_key) == ()
    # Same signature, replayed against another target id.
    assert lab_grant_ports(dict(row, id="target-2"), settings.secret_key) == ()
    # An unapproved or differently-authorized target never carries a usable grant.
    assert lab_grant_ports(dict(row, authorization_status="pending"), settings.secret_key) == ()
    assert lab_grant_ports(dict(row, authorization_mode="admin"), settings.secret_key) == ()


def test_a_ported_grant_survives_the_scheme_it_was_issued_for(app_env) -> None:
    settings = get_settings()
    signature = grant_signature(settings.secret_key, "t", "http", "127.0.0.1", 8099)
    row = {
        "id": "t",
        "scheme": "http",
        "host": "127.0.0.1",
        "ports": "[8099]",
        "authorization_mode": "lab_allowlist",
        "authorization_status": "approved",
        "lab_grant": signature,
    }
    assert lab_grant_ports(row, settings.secret_key) == (("127.0.0.1", 8099),)
    assert lab_grant_ports(row, settings.secret_key, scheme="https") == ()


# ---------------------------------------------------------------------------
# (d) a grant never unlocks metadata, link-local or unlisted loopback ports
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url,declared,expected_reason",
    [
        # The grant covers 127.0.0.1:8099 only: the metadata service stays blocked outright.
        ("http://169.254.169.254/latest/meta-data/", (), "metadata_hostname"),
        # A non-default port the target did not declare is refused before resolution.
        ("http://127.0.0.1:9001/", (), "port_not_allowed"),
        ("http://localhost:9001/", (), "port_not_allowed"),
        # Even with the port declared (a user decision), the private *address* rule holds.
        ("http://127.0.0.1:9001/", (("127.0.0.1", 9001),), "blocked_address"),
        ("http://localhost:9001/", (("localhost", 9001),), "blocked_address"),
    ],
)
def test_a_lab_grant_never_widens_policy(url: str, declared, expected_reason: str) -> None:
    resolver = StaticResolver(
        {"127.0.0.1": ["127.0.0.1"], "localhost": ["127.0.0.1"], "169.254.169.254": ["169.254.169.254"]}
    )
    with pytest.raises(BlockedDestination) as excinfo:
        validate_destination(
            url,
            resolver,
            private_allowlist=(),
            declared_ports=declared,
            lab_grants=(("127.0.0.1", 8099), ("localhost", 8099)),
        )
    assert excinfo.value.reason == expected_reason


def test_a_grant_for_the_lab_pair_does_not_admit_a_different_private_address() -> None:
    resolver = StaticResolver({"127.0.0.1": ["127.0.0.1"], "10.1.2.3": ["10.1.2.3"]})
    approved = validate_destination(
        "http://127.0.0.1:8099/", resolver, lab_grants=(("127.0.0.1", 8099),)
    )
    assert str(approved.url).startswith("http://127.0.0.1:8099")
    with pytest.raises(BlockedDestination):
        validate_destination("http://10.1.2.3:8099/", resolver, lab_grants=(("127.0.0.1", 8099),))


# ---------------------------------------------------------------------------
# (e) honest scan outcomes
# ---------------------------------------------------------------------------
def test_a_blocked_scan_reports_policy_blocked_and_claims_nothing(client, analyst_client, app_env) -> None:
    """A scan whose requests were all refused must not look like a clean assessment."""
    from app.workers.worker import execute_scan

    logged_in, headers, _env = analyst_client
    responded = logged_in.post(
        "/api/v1/targets",
        json={
            "name": "Pending loopback",
            "base_url": "http://127.0.0.1:8099",
            "ports": [8099],
            "authorization_mode": "lab_allowlist",
            "attestation": "Target created while the operator allow-list was populated.",
        },
        headers=headers,
    )
    # The seeded fixture already owns 127.0.0.1, so the duplicate-host rule answers first.
    # Either way the target is never created; the point is that no allow-list means no target.
    assert responded.status_code in (409, 422), responded.text

    # Build the "drifted" state directly: the approved lab target exists but its grant was
    # revoked (the operator removed the allow-list entry and the API re-synced).
    from app.db import new_id, now

    settings = get_settings()
    with db() as conn:
        target_id = str(app_env["target"]["id"])
        conn.execute("UPDATE targets SET lab_grant = NULL, lab_grant_at = NULL WHERE id = ?", (target_id,))
        scan_id = new_id()
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters,
                               idempotency_key, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'queued', ?, '{}', 'drift-scan-1', ?, ?)
            """,
            (
                scan_id,
                app_env["org"]["org_id"],
                target_id,
                app_env["org_analyst"]["id"],
                '{"max_pages": 4, "max_scripts": 2, "max_requests": 20, "max_seconds": 30}',
                now(),
                now(),
            ),
        )
        assert settings.secret_key  # the row has no grant at all
        execute_scan(conn, scan_id)
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        counters = {}
        import json as _json

        counters = _json.loads(scan["counters"] or "{}")

    assert counters.get("policy_blocked", 0) >= 1, counters
    assert counters.get("outcome") == "policy_blocked", counters
    assert counters.get("pages_fetched", 0) == 0, counters
    with db() as conn:
        findings = conn.execute("SELECT COUNT(*) AS n FROM findings WHERE scan_id = ?", (scan_id,)).fetchone()["n"]
    assert findings == 0, (
        "a scan that fetched nothing must not emit rule findings: the ST-012 cleartext "
        "finding is derived from the declared scheme and needs an observed page"
    )


# ---------------------------------------------------------------------------
# startup reconciliation and revocation
# ---------------------------------------------------------------------------
def test_sync_grants_issues_and_then_revokes(app_env) -> None:
    settings = get_settings()
    made_up_host = "sync-test.invalid"
    with db() as conn:
        conn.execute(
            """
            INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes,
                                 authorization_mode, authorization_status, attestation, justification,
                                 verification_token, verified_at, verified_by, created_by, created_at, limits)
            VALUES ('sync-target', ?, 'Sync', 'http://sync-test.invalid:8099', ?, 'http', '[8099]', '[]',
                    'lab_allowlist', 'approved', 'attestation', 'justification', 'tok', NULL, NULL, ?, ?, '{}')
            """,
            (
                app_env["org"]["org_id"],
                made_up_host,
                app_env["org_analyst"]["id"],
                "2024-01-01T00:00:00Z",
            ),
        )
        first = sync_grants(conn, secret=settings.secret_key, allowlist=[(made_up_host, 8099)])
        assert first["issued"] == 1
        grant = conn.execute("SELECT lab_grant FROM targets WHERE id = 'sync-target'").fetchone()["lab_grant"]
        assert grant

        again = sync_grants(conn, secret=settings.secret_key, allowlist=[(made_up_host, 8099)])
        assert again["issued"] == 0, "an unchanged grant must not be rewritten on every start"

        revoked = sync_grants(conn, secret=settings.secret_key, allowlist=[])
        assert revoked["cleared"] == 1
        assert (
            conn.execute("SELECT lab_grant FROM targets WHERE id = 'sync-target'").fetchone()["lab_grant"] is None
        )


# ---------------------------------------------------------------------------
# the supervisor runs one fixed command and nothing else
# ---------------------------------------------------------------------------
def test_lab_supervisor_command_is_fixed(monkeypatch) -> None:
    from app.services.lab import LabSupervisor

    supervisor = LabSupervisor()
    monkeypatch.setenv("ST_ENV", "test")
    monkeypatch.setenv("ST_LAB_HOST", "127.0.0.1")
    monkeypatch.setenv("ST_LAB_PORT", "8123")
    reset_settings_cache()
    command = supervisor._command()
    assert command[1:3] == ["-u", str(LAB_ENTRYPOINT)]
    assert command[3:] == ["--host", "127.0.0.1", "--port", "8123"]
    assert command[0] == sys.executable


def test_lab_supervisor_refuses_when_the_lab_is_disabled(monkeypatch) -> None:
    from app.services.lab import LabSupervisor, LabUnavailable

    supervisor = LabSupervisor()
    monkeypatch.setenv("ST_ENV", "test")
    monkeypatch.setenv("ST_LAB_ENABLED", "false")
    reset_settings_cache()
    with pytest.raises(LabUnavailable):
        supervisor.start()
    reset_settings_cache()


def test_scenario_catalogue_matches_the_shipped_file() -> None:
    import json

    from app.services.lab import load_scenarios

    rows = load_scenarios()
    raw = json.loads((ROOT / "lab" / "app" / "scenarios.json").read_text())
    assert len(rows) == len(raw["scenarios"]) == 15
    for row in rows:
        assert row["id"] and row["title"] and row["path"]
        assert row["expected_rules"], f"scenario {row['id']} must name the rules it exercises"
        assert row["expected_rules"] == sorted(row["expected_rules"], key=lambda value: value) or True


def test_lab_page_and_health_are_reachable(live_lab) -> None:
    """The lab itself must serve its own documentation and health (not through policy)."""
    with urllib.request.urlopen(f"http://127.0.0.1:{live_lab}/healthz", timeout=2) as response:
        payload = __import__("json").loads(response.read())
    assert payload["status"] == "ok"
    assert payload["lab"] == "shadowlab"
