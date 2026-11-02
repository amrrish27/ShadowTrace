"""Scan objects, inventory, findings, triage, comparison and the six export formats.

A completed scan is seeded directly so the tests stay offline and deterministic;
the scanner itself is covered by the lab evaluation harness.
"""
from __future__ import annotations

import csv
import io
import json

import pytest

from app.db import db, new_id, now


def _seed_scan(env) -> dict:
    org_id = env["target"]["org_id"]
    target_id = env["target"]["id"]
    user_id = env["org_analyst"]["id"]
    scan_id = new_id()
    timestamp = now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                               partial, created_at, started_at, finished_at, updated_at)
            VALUES (?, ?, ?, ?, 'completed', ?, ?, 'seed-idempotency-key', 0, ?, ?, ?, ?)
            """,
            (
                scan_id,
                org_id,
                target_id,
                user_id,
                json.dumps({"max_pages": 12, "active_validation": True}),
                json.dumps(
                    {
                        "endpoints": 3,
                        "endpoints_shadow": 2,
                        "endpoints_documented": 1,
                        "validated": 3,
                        "findings": 2,
                        "requests": 9,
                    }
                ),
                timestamp,
                timestamp,
                timestamp,
                timestamp,
            ),
        )
        conn.execute(
            "INSERT INTO scan_events (scan_id, ts, level, kind, message) VALUES (?, ?, 'info', 'scan.started', 'seeded')",
            (scan_id, timestamp),
        )
        endpoints = []
        for index, (method, path, classification, status) in enumerate(
            [
                ("GET", "/api/v1/users", "documented", "live"),
                ("GET", "/api/v1/internal/reports", "shadow", "live"),
                ("GET", "/api/v1/admin/export", "shadow", "auth_required"),
            ]
        ):
            endpoint_id = new_id()
            endpoints.append(endpoint_id)
            conn.execute(
                """
                INSERT INTO endpoints (id, org_id, target_id, host, method, path_template, query_template,
                                       classification, validation_status, response_status, fingerprint,
                                       first_seen_at, last_seen_at, first_seen_scan, last_seen_scan, origin)
                VALUES (?, ?, ?, '127.0.0.1', ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, 'http://127.0.0.1:8099')
                """,
                (
                    endpoint_id,
                    org_id,
                    target_id,
                    method,
                    path,
                    classification,
                    status,
                    200 if status == "live" else 401,
                    f"{method}|127.0.0.1|{path}|",
                    timestamp,
                    timestamp,
                    scan_id,
                    scan_id,
                ),
            )
            conn.execute(
                "INSERT INTO scan_endpoints (scan_id, endpoint_id, validation_status, classification) VALUES (?, ?, ?, ?)",
                (scan_id, endpoint_id, status, classification),
            )
            conn.execute(
                """
                INSERT INTO endpoint_sources (endpoint_id, scan_id, source_type, source_url, location, method, snippet, extractor, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    endpoint_id,
                    scan_id,
                    "javascript" if index else "openapi",
                    "http://127.0.0.1:8099/app.js",
                    "line 12",
                    method,
                    "fetch('/api/v1/users')",
                    "fetch",
                    timestamp,
                ),
            )
            conn.execute(
                """
                INSERT INTO observations (id, scan_id, endpoint_id, url, method, status_code, content_type,
                                          content_length, elapsed_ms, headers, snippet, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, 'application/json', 42, 5, '{"content-type": "application/json"}', ?, ?)
                """,
                (
                    new_id(),
                    scan_id,
                    endpoint_id,
                    f"http://127.0.0.1:8099{path}",
                    method,
                    200 if status == "live" else 401,
                    '[{"id": 1}]',
                    timestamp,
                ),
            )
        finding_ids = []
        for endpoint_id, rule_id, title, severity, confidence, status, score in (
            (endpoints[1], "ST-001", "Undocumented endpoint is reachable", "medium", "high", "confirmed", 49.6),
            (endpoints[2], "ST-003", "Debug or management endpoint exposed", "high", "high", "confirmed", 69.6),
        ):
            finding_id = new_id()
            finding_ids.append(finding_id)
            conn.execute(
                """
                INSERT INTO findings (id, org_id, target_id, scan_id, endpoint_id, rule_id, title, severity,
                                      confidence, status, exposure, risk_score, fingerprint, rationale,
                                      limitations, remediation, evidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0.7, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    org_id,
                    target_id,
                    scan_id,
                    endpoint_id,
                    rule_id,
                    title,
                    severity,
                    confidence,
                    status,
                    score,
                    f"{rule_id}|{endpoint_id}",
                    "Seeded rationale for the export test.",
                    "Seeded limitations.",
                    "Seeded remediation.",
                    json.dumps(
                        {
                            "request": {"method": "GET", "url": f"http://127.0.0.1:8099{rule_id}"},
                            "reproduction": f"curl -s {rule_id}",
                            "captured": "seeded",
                        }
                    ),
                    timestamp,
                ),
            )
    return {"scan_id": scan_id, "endpoints": endpoints, "findings": finding_ids}


@pytest.fixture()
def seeded(analyst_client):
    """Each test gets its own database (tmp_path), so the scan is seeded per test."""
    client, headers, env = analyst_client
    return client, headers, env, _seed_scan(env)


def test_scan_list_and_detail(seeded):
    client, headers, env, data = seeded
    listing = client.get("/api/v1/scans", headers=headers).json()
    assert any(item["id"] == data["scan_id"] for item in listing["scans"])
    detail = client.get(f"/api/v1/scans/{data['scan_id']}", headers=headers).json()["scan"]
    assert detail["state"] == "completed"
    assert detail["target_name"] == "Alpha"
    assert detail["counters"]["endpoints"] == 3
    events = client.get(f"/api/v1/scans/{data['scan_id']}/events", headers=headers).json()
    assert events["events"][0]["kind"] == "scan.started"
    assert client.get("/api/v1/scans/does-not-exist", headers=headers).status_code == 404


def test_scan_endpoints_filters_and_sort(seeded):
    client, headers, env, data = seeded
    body = client.get(f"/api/v1/scans/{data['scan_id']}/endpoints", headers=headers).json()
    assert body["total"] == 3
    only_shadow = client.get(
        f"/api/v1/scans/{data['scan_id']}/endpoints", params={"classification": "shadow"}, headers=headers
    ).json()
    assert only_shadow["total"] == 2
    sorted_desc = client.get(
        f"/api/v1/scans/{data['scan_id']}/endpoints", params={"sort": "path", "order": "desc"}, headers=headers
    ).json()
    paths = [row["path_template"] for row in sorted_desc["endpoints"]]
    assert paths == sorted(paths, reverse=True)
    # Unknown sort keys fall back to the default column instead of injecting SQL.
    fallback = client.get(
        f"/api/v1/scans/{data['scan_id']}/endpoints", params={"sort": "bogus"}, headers=headers
    )
    assert fallback.status_code == 200


def test_scan_findings_and_detail(seeded):
    client, headers, env, data = seeded
    body = client.get(f"/api/v1/scans/{data['scan_id']}/findings", headers=headers).json()
    assert body["total"] == 2
    assert body["findings"][0]["severity"] == "high"  # ordered by risk score
    by_rule = client.get(
        f"/api/v1/scans/{data['scan_id']}/findings", params={"rule": "ST-001"}, headers=headers
    ).json()
    assert by_rule["total"] == 1
    detail = client.get(f"/api/v1/findings/{data['findings'][1]}", headers=headers).json()
    assert detail["finding"]["rule_id"] == "ST-003"
    evidence = detail["finding"]["evidence"]
    assert "reproduction" in evidence
    assert client.get("/api/v1/findings/nope", headers=headers).status_code == 404


def test_finding_triage_requires_reason_and_analyst(seeded):
    client, headers, env, data = seeded
    finding_id = data["findings"][0]
    short = client.post(f"/api/v1/findings/{finding_id}/triage", json={"status": "fixed", "reason": "x"}, headers=headers)
    assert short.status_code == 422
    ok = client.post(
        f"/api/v1/findings/{finding_id}/triage",
        json={"status": "accepted_risk", "reason": "Documented internal tooling, risk accepted by owner."},
        headers=headers,
    )
    assert ok.status_code == 200
    filtered = client.get(
        f"/api/v1/scans/{data['scan_id']}/findings", params={"status": "accepted_risk"}, headers=headers
    ).json()
    assert filtered["total"] == 1
    # Triage history is append-only.
    with db() as conn:
        history = conn.execute("SELECT status, reason FROM triage_history ORDER BY id").fetchall()
    assert [row["status"] for row in history] == ["accepted_risk"]


def test_inventory_aggregate_views(seeded):
    client, headers, env, data = seeded
    endpoints = client.get("/api/v1/endpoints", headers=headers).json()
    assert endpoints["total"] >= 3
    findings = client.get("/api/v1/findings", headers=headers).json()
    assert findings["total"] >= 2
    overview = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert overview["endpoints"]["total"] == 3
    assert overview["endpoints"]["shadow"] == 2
    assert overview["findings_by_severity"]["high"] == 1
    assert overview["scans_by_state"]["completed"] == 1
    assert "scan_timeline" in overview


def test_scan_comparison(seeded):
    client, headers, env, data = seeded
    comparison = client.get(f"/api/v1/scans/{data['scan_id']}/comparison", headers=headers).json()
    assert set(comparison) >= {"new", "removed", "changed"}


@pytest.mark.parametrize(
    "fmt,content_type,marker",
    [
        ("json", "application/json", '"findings"'),
        ("csv_inventory", "text/csv", "method,path,host,classification"),
        ("csv_findings", "text/csv", "rule,severity,confidence"),
        ("markdown", "text/markdown", "# ShadowTrace"),
        ("html", "text/html", "<!doctype html>"),
        ("openapi_stub", "application/json", '"openapi"'),
    ],
)
def test_exports(seeded, fmt, content_type, marker):
    client, headers, env, data = seeded
    response = client.get(f"/api/v1/scans/{data['scan_id']}/export", params={"format": fmt}, headers=headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(content_type)
    assert "attachment;" in response.headers.get("content-disposition", "")
    assert marker in response.text
    assert len(response.content) > 100


@pytest.mark.parametrize("fmt", ["json", "csv_inventory", "csv_findings", "markdown", "html", "openapi_stub"])
def test_export_filename_carries_an_extension(seeded, fmt):
    """A download named "shadowtrace-<id>-json" has no type, so a browser or mail client
    cannot open it. Found by the Playwright journey; every format names a real file."""
    client, headers, env, data = seeded
    response = client.get(f"/api/v1/scans/{data['scan_id']}/export", params={"format": fmt}, headers=headers)
    assert response.status_code == 200
    disposition = response.headers["content-disposition"]
    filename = disposition.split("filename=", 1)[1].strip('"')
    assert filename.startswith("shadowtrace-")
    assert filename.rsplit(".", 1)[-1] in {"json", "csv", "md", "html"}, filename


def test_export_json_is_complete_and_machine_readable(seeded):
    client, headers, env, data = seeded
    payload = json.loads(
        client.get(f"/api/v1/scans/{data['scan_id']}/export", params={"format": "json"}, headers=headers).text
    )
    assert payload["scan"]["id"] == data["scan_id"]
    assert len(payload["inventory"]) == 3
    assert len(payload["findings"]) == 2


def test_csv_exports_are_rfc4180_parseable(seeded):
    client, headers, env, data = seeded
    inventory = client.get(
        f"/api/v1/scans/{data['scan_id']}/export", params={"format": "csv_inventory"}, headers=headers
    ).text
    rows = list(csv.DictReader(io.StringIO(inventory)))
    assert len(rows) == 3
    assert {"method", "path", "host", "classification", "validation_status"} <= set(rows[0])
    findings = client.get(
        f"/api/v1/scans/{data['scan_id']}/export", params={"format": "csv_findings"}, headers=headers
    ).text
    finding_rows = list(csv.DictReader(io.StringIO(findings)))
    assert len(finding_rows) == 2
    assert {"rule", "severity", "confidence", "risk_score", "triage"} <= set(finding_rows[0])


def test_html_export_escapes_untrusted_values(seeded):
    client, headers, env, data = seeded
    with db() as conn:
        conn.execute(
            "UPDATE endpoints SET path_template = ? WHERE id = ?",
            ("/api/v1/<script>alert(1)</script>", data["endpoints"][0]),
        )
    html = client.get(f"/api/v1/scans/{data['scan_id']}/export", params={"format": "html"}, headers=headers).text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_unknown_export_format_is_rejected(seeded):
    client, headers, env, data = seeded
    response = client.get(f"/api/v1/scans/{data['scan_id']}/export", params={"format": "../../etc/passwd"}, headers=headers)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_format"


def test_exports_are_audited(seeded):
    client, headers, env, data = seeded
    client.get(f"/api/v1/scans/{data['scan_id']}/export", params={"format": "markdown"}, headers=headers)
    with db() as conn:
        exports = conn.execute("SELECT format FROM report_exports WHERE scan_id = ?", (data["scan_id"],)).fetchall()
        audit_rows = conn.execute("SELECT details FROM audit_log WHERE action = 'report.exported'").fetchall()
    assert "markdown" in [row["format"] for row in exports]
    assert any('"format": "markdown"' in row["details"].replace(" ", "") or "markdown" in row["details"] for row in audit_rows)


def test_scan_creation_requires_idempotency_and_valid_target(analyst_client):
    client, headers, env = analyst_client
    payload = {
        "target_id": env["target"]["id"],
        "attestation": "I am authorized to scan this lab target.",
        "max_pages": 5,
    }
    missing = client.post("/api/v1/scans", json=payload, headers=headers)
    assert missing.status_code == 422
    created = client.post("/api/v1/scans", json=payload, headers={**headers, "Idempotency-Key": "test-key-0001"})
    assert created.status_code == 201
    scan = created.json()["scan"]
    assert scan["state"] == "queued"
    replay = client.post("/api/v1/scans", json=payload, headers={**headers, "Idempotency-Key": "test-key-0001"})
    assert replay.status_code == 201
    assert replay.json()["scan"]["id"] == scan["id"]
    # Cancelling a queued scan moves it to cancelled, and it cannot be started afterwards.
    cancel = client.post(f"/api/v1/scans/{scan['id']}/cancel", headers=headers)
    assert cancel.status_code == 200
    assert client.get(f"/api/v1/scans/{scan['id']}", headers=headers).json()["scan"]["state"] == "cancelled"
    start = client.post(f"/api/v1/scans/{scan['id']}/start", headers=headers)
    assert start.status_code in {409, 400}


def test_start_accepts_a_scan_a_worker_has_already_claimed(analyst_client):
    """`POST /scans/{id}/start` must not race the worker.

    A reviewer reported a one-off 404 here while a worker was polling. The route only
    reads the row, so once the worker has promoted the scan to `running` (or finished
    it) the honest answers are 200 and 409 — never 404, which is reserved for an id that
    does not exist in the caller's organization.
    """
    client, headers, env = analyst_client
    payload = {
        "target_id": env["target"]["id"],
        "attestation": "I am authorized to scan this lab target.",
        "max_pages": 5,
    }
    created = client.post("/api/v1/scans", json=payload, headers={**headers, "Idempotency-Key": "start-race-1"})
    assert created.status_code == 201
    scan_id = created.json()["scan"]["id"]

    for state in ("running", "cancelling"):
        with db() as conn:
            conn.execute("UPDATE scans SET state = ? WHERE id = ?", (state, scan_id))
        started = client.post(f"/api/v1/scans/{scan_id}/start", headers=headers)
        assert started.status_code == 200, (state, started.text)
        assert started.json()["scan"]["state"] == state

    with db() as conn:
        conn.execute("UPDATE scans SET state = 'completed' WHERE id = ?", (scan_id,))
    finished = client.post(f"/api/v1/scans/{scan_id}/start", headers=headers)
    assert finished.status_code == 409
    assert finished.json()["error"]["code"] == "invalid_transition"

    unknown = client.post("/api/v1/scans/" + "0" * 32 + "/start", headers=headers)
    assert unknown.status_code == 404


def test_scan_creation_rejects_short_attestation_and_bad_limits(analyst_client):
    client, headers, env = analyst_client
    bad = client.post(
        "/api/v1/scans",
        json={"target_id": env["target"]["id"], "attestation": "short", "max_pages": 5000},
        headers={**headers, "Idempotency-Key": "test-key-0002"},
    )
    assert bad.status_code == 422


def test_targets_crud_and_approval(admin_client, monkeypatch):
    client, headers, env = admin_client
    from app.config import reset_settings_cache

    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", "localhost:8099")
    reset_settings_cache()
    created = client.post(
        "/api/v1/targets",
        json={
            "name": "Beta Lab",
            "base_url": "http://localhost:8099",
            "ports": [8099],
            "authorization_mode": "lab_allowlist",
            "attestation": "Operator-owned lab target used for the automated test suite.",
            "justification": "Automated regression testing of the scanner.",
        },
        headers=headers,
    )
    assert created.status_code in {200, 201}, created.text
    target_id = created.json()["target"]["id"]
    assert client.get(f"/api/v1/targets/{target_id}", headers=headers).json()["target"]["authorization_status"] == "approved"
    assert client.post(f"/api/v1/targets/{target_id}/verify", headers=headers).status_code in {200, 409}
    assert client.delete(f"/api/v1/targets/{target_id}", headers=headers).status_code == 200
    assert client.get(f"/api/v1/targets/{target_id}", headers=headers).status_code == 404
    reset_settings_cache()


def test_target_outside_allowlist_is_refused(analyst_client, monkeypatch):
    client, headers, env = analyst_client
    from app.config import reset_settings_cache

    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", "")
    reset_settings_cache()
    response = client.post(
        "/api/v1/targets",
        json={
            "name": "Public Site",
            "base_url": "https://example.com",
            "authorization_mode": "lab_allowlist",
            "attestation": "Attempting to add a target that is not allow-listed.",
            "justification": "Should be refused by the lab allow-list check.",
        },
        headers=headers,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_target"
    reset_settings_cache()
