"""Tests for baseline upload, HAR upload, and baseline selection in scan creation."""
from __future__ import annotations

import json
import pytest

from app.db import db, new_id, now


MINIMAL_SPEC = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "Test Baseline", "version": "1.0.0"},
        "paths": {
            "/api/v1/items": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/api/v1/items/{itemId}": {"get": {"responses": {"200": {"description": "ok"}}}},
        },
    }
)


def test_baseline_upload_and_listing(analyst_client):
    client, headers, env = analyst_client
    target_id = env["target"]["id"]

    # Upload valid OpenAPI baseline
    res = client.post(
        f"/api/v1/targets/{target_id}/baselines",
        json={"source": "upload", "content": MINIMAL_SPEC},
        headers=headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["endpoint_count"] == 2
    baseline_id = data["id"]

    # List baselines
    list_res = client.get(f"/api/v1/targets/{target_id}/baselines", headers=headers)
    assert list_res.status_code == 200
    baselines = list_res.json()["baselines"]
    assert any(b["id"] == baseline_id and b["endpoint_count"] == 2 for b in baselines)


def test_scan_creation_with_baseline_dropdown(analyst_client):
    client, headers, env = analyst_client
    target_id = env["target"]["id"]

    # Upload a baseline first
    res = client.post(
        f"/api/v1/targets/{target_id}/baselines",
        json={"source": "upload", "content": MINIMAL_SPEC},
        headers=headers,
    )
    assert res.status_code == 200
    baseline_id = res.json()["id"]

    # Create scan referencing this baseline_id
    scan_res = client.post(
        "/api/v1/scans",
        json={
            "target_id": target_id,
            "baseline_id": baseline_id,
            "include_crawler": False,
            "include_specs": False,
            "include_source_maps": False,
            "active_validation": False,
            "max_pages": 4,
            "max_scripts": 2,
            "max_requests": 50,
            "max_seconds": 60,
            "seeds": [],
            "attestation": "Authorized testing.",
        },
        headers={**headers, "Idempotency-Key": f"test-baseline-dropdown-{now()}"},
    )
    assert scan_res.status_code in {200, 201}, scan_res.text
    scan = scan_res.json()["scan"]
    assert scan["target_id"] == target_id

    # Verify baseline is linked in DB
    with db() as conn:
        row = conn.execute("SELECT baseline_id FROM scans WHERE id = ?", (scan["id"],)).fetchone()
        assert row is not None
        assert row["baseline_id"] == baseline_id


def test_har_upload_and_import(analyst_client):
    client, headers, env = analyst_client
    target_id = env["target"]["id"]

    har = json.dumps(
        {
            "log": {
                "version": "1.2",
                "entries": [
                    {"request": {"method": "GET", "url": "http://127.0.0.1:8099/api/v1/items"}},
                ],
            }
        }
    )
    res = client.post(
        f"/api/v1/targets/{target_id}/har",
        content=har,
        headers={**headers, "X-Har-Name": "ui_upload.har"},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["entries_in_scope"] == 1
    assert data["endpoints_found"] >= 1
