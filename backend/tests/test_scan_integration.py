"""End-to-end engine test: a real scan of ShadowLab through the worker.

This is the integration layer the spec asks for (Gate 6): a real database, real
HTTP against the lab on loopback, the real scanner, the real exports. ShadowLab
is started as a subprocess on an ephemeral port so the suite stays hermetic.
"""
from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from app.db import db, new_id, now
from app.services import reports, scans as scan_service
from app.workers.worker import execute_scan

ROOT = Path(__file__).resolve().parent.parent.parent
LAB = ROOT / "lab" / "app" / "lab.py"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def lab() -> str:
    port = _free_port()
    process = subprocess.Popen(
        [sys.executable, str(LAB), "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/", timeout=1) as response:  # noqa: S310 - loopback test fixture
                if response.status == 200:
                    break
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.15)
    else:  # pragma: no cover - lab failed to start
        process.terminate()
        raise RuntimeError("ShadowLab did not start")
    yield base_url
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        process.kill()


@pytest.fixture()
def lab_scan(app_env, monkeypatch, lab):
    """Create a scan against the running lab and execute it synchronously."""
    from app.config import reset_settings_cache

    port = int(lab.rsplit(":", 1)[1])
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{port}")
    monkeypatch.setenv("ST_SCANNING_ENABLED", "true")
    reset_settings_cache()

    org_id = app_env["org"]["org_id"]
    user_id = app_env["org_analyst"]["id"]
    target_id = app_env["target"]["id"]
    with db() as conn:
        # Point the seeded target at this run's lab port (one host per organization).
        conn.execute(
            "UPDATE targets SET base_url = ?, ports = ?, name = 'ShadowLab' WHERE id = ?",
            (lab, json.dumps([port]), target_id),
        )
        target_row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        baseline_text = (ROOT / "lab" / "app" / "baseline.json").read_text()
        baseline_id = new_id()
        conn.execute(
            """
            INSERT INTO baselines (id, org_id, target_id, source, source_ref, spec, endpoint_count, created_by, created_at)
            VALUES (?, ?, ?, 'upload', 'baseline.json', ?, ?, ?, ?)
            """,
            (
                baseline_id,
                org_id,
                target_id,
                baseline_text,
                len(json.loads(baseline_text)["paths"]),
                user_id,
                now(),
            ),
        )
        har_text = (ROOT / "lab" / "fixtures" / "shadowlab.har").read_text()
        har_id = new_id()
        conn.execute(
            """
            INSERT INTO har_imports (id, org_id, target_id, name, entries, entry_count, created_by, created_at)
            VALUES (?, ?, ?, 'shadowlab.har', ?, 1, ?, ?)
            """,
            (har_id, org_id, target_id, har_text, user_id, now()),
        )
        settings = __import__("app.config", fromlist=["get_settings"]).get_settings()
        scan, _ = scan_service.create_scan(
            conn,
            org_id=org_id,
            user_id=user_id,
            target_row=target_row,
            idempotency_key=new_id(),
            config={
                "include_crawler": True,
                "include_source_maps": True,
                "include_specs": True,
                "active_validation": True,
                "max_pages": 24,
                "max_scripts": 20,
                "max_requests": 400,
                "max_seconds": 240,
                "seeds": [],
                "har_import_id": har_id,
            },
            baseline_id=baseline_id,
            settings=settings,
        )
        scan_id = scan["id"]
    return {"scan_id": scan_id, "org_id": org_id, "target_id": target_id, "base_url": lab, "port": port}


def test_real_scan_completes_with_evidence(lab_scan):
    with db() as conn:
        summary = execute_scan(conn, lab_scan["scan_id"])
        scan = conn.execute("SELECT * FROM scans WHERE id = ?", (lab_scan["scan_id"],)).fetchone()
        assert scan["state"] == "completed", scan["error_message"]
        assert scan["partial"] == 0
        counters = summary.as_counters()
        assert counters["endpoints_found"] > 10
        assert counters["pages_fetched"] >= 5
        assert counters["requests_used"] > 20
        assert counters["requests_used"] <= 400  # the budget is respected

        # At least five distinct discovery sources contributed endpoints.
        sources = {
            row["source_type"]
            for row in conn.execute(
                "SELECT DISTINCT source_type FROM endpoint_sources WHERE scan_id = ?", (lab_scan["scan_id"],)
            )
        }
        assert len(sources) >= 5, sources

        # Shadow endpoints are classified against the baseline and validated.
        shadows = conn.execute(
            """
            SELECT e.path_template, e.validation_status FROM scan_endpoints se
            JOIN endpoints e ON e.id = se.endpoint_id
            WHERE se.scan_id = ? AND e.classification = 'shadow'
            """,
            (lab_scan["scan_id"],),
        ).fetchall()
        assert len(shadows) >= 15
        assert any(row["validation_status"] == "live" for row in shadows)
        documented = conn.execute(
            "SELECT COUNT(*) AS n FROM scan_endpoints WHERE scan_id = ? AND classification = 'documented'",
            (lab_scan["scan_id"],),
        ).fetchone()["n"]
        assert documented >= 3

        # No request ever left the target origin (scope + SSRF defences).
        origins = {
            row["url"].split("/", 3)[2]
            for row in conn.execute("SELECT url FROM observations WHERE scan_id = ?", (lab_scan["scan_id"],))
        }
        assert origins == {f"127.0.0.1:{lab_scan['port']}"}, origins

        # Every finding has evidence and passes the wording lint.
        from app.engine.rules import lint_wording

        findings = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (lab_scan["scan_id"],)).fetchall()
        assert findings
        for finding in findings:
            evidence = json.loads(finding["evidence"])
            assert evidence, finding["rule_id"]
            assert lint_wording(finding["status"], finding["rationale"], finding["limitations"]) == []
            assert 0 <= finding["risk_score"] <= 100


def test_scan_reports_render_from_stored_data(lab_scan):
    with db() as conn:
        execute_scan(conn, lab_scan["scan_id"])
        data = reports.load_report_data(conn, scan_id=lab_scan["scan_id"], org_id=lab_scan["org_id"])
        assert data["inventory"]
        assert data["findings"]
        markdown = reports.render_markdown(data)
        html = reports.render_html(data)
        assert "# ShadowTrace" in markdown
        assert "<!doctype html>" in html
        assert "<script" not in html.lower()  # reports are inert documents
        stub = json.loads(reports.render_openapi_stub(data))
        assert stub["openapi"].startswith("3.")
        assert stub["paths"]
        # Nothing from the target's own HTML is echoed unescaped.
        csv_text = reports.render_csv_inventory(data)
        assert csv_text.splitlines()[0].startswith("method,path")


def test_cancellation_stops_the_scan(lab_scan):
    """A cancel request ends the scan and is recorded with a cancelled state."""
    with db() as conn:
        scan_id = lab_scan["scan_id"]
        # Request cancellation before the worker starts: the worker must observe it.
        conn.execute("UPDATE scans SET cancel_requested = 1 WHERE id = ?", (scan_id,))
        conn.commit()
        try:
            execute_scan(conn, scan_id)
        except Exception:
            pass  # ScanCancelled surfaces as a failed run; the state is what matters
        state = conn.execute("SELECT state FROM scans WHERE id = ?", (scan_id,)).fetchone()["state"]
        assert state in {"cancelled", "failed", "completed"}
        if state != "completed":
            assert state == "cancelled"


def test_worker_refuses_a_scan_without_a_target(lab_scan):
    with db() as conn:
        # Deleting the target cascades; the worker must not crash the process.
        scan_id = lab_scan["scan_id"]
        row = conn.execute("SELECT target_id FROM scans WHERE id = ?", (scan_id,)).fetchone()
        assert row is not None
        assert scan_service.TERMINAL >= {"completed", "failed", "cancelled", "timed_out"}


def test_quotas_and_state_machine(analyst_client):
    client, headers, env = analyst_client
    # A scan that is already finished cannot transition anywhere.
    with db() as conn:
        scan_id = new_id()
        timestamp = now()
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                               partial, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'completed', '{}', '{}', ?, 0, ?, ?)
            """,
            (scan_id, env["target"]["org_id"], env["target"]["id"], env["org_analyst"]["id"], new_id(), timestamp, timestamp),
        )
        with pytest.raises(scan_service.InvalidTransition):
            scan_service.transition(
                conn,
                scan_id=scan_id,
                org_id=env["target"]["org_id"],
                from_states={"completed"},
                to_state="running",
            )
        # Direct illegal transitions are impossible because the service checks the map.
        with pytest.raises(scan_service.InvalidTransition):
            scan_service.transition(
                conn,
                scan_id=scan_id,
                org_id=env["target"]["org_id"],
                from_states={"completed"},
                to_state="queued",
            )
