"""Dashboard overview contract and behaviour.

The overview is the page the UI lands on after sign-in, so it has two jobs: never omit a key
the frontend types declare, and never leak another organization's rows. Both are asserted
here, plus the exact ``recent_findings`` shape that used to be missing.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.db import db, new_id, now

from .test_api_scan_objects import _seed_scan

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "frontend" / "src" / "__fixtures__" / "overview.contract.json"
CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

FINDING_KEYS = {
    "id",
    "rule_id",
    "title",
    "severity",
    "confidence",
    "status",
    "risk_score",
    "fingerprint",
    "created_at",
    "triage_status",
    "endpoint_method",
    "endpoint_path",
}


@pytest.fixture()
def seeded(analyst_client):
    client, headers, env = analyst_client
    return client, headers, env, _seed_scan(env)


def test_overview_returns_exactly_the_contract_keys(analyst_client):
    """The frontend type and the API must agree; the shared fixture is the source of truth."""
    client, headers, _env = analyst_client
    response = client.get("/api/v1/dashboard/overview", headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert sorted(payload) == sorted(CONTRACT["keys"]), "dashboard contract drifted from overview.contract.json"
    assert sorted(payload) == sorted(CONTRACT["empty"])


def test_overview_on_an_empty_organization_has_zeroed_buckets(analyst_client):
    client, headers, _env = analyst_client
    with db() as conn:  # conftest seeds one approved target; this test wants a blank org
        conn.execute("DELETE FROM targets")
    payload = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert payload == CONTRACT["empty"], "the empty-state payload must stay JSON-identical to the fixture"


def test_overview_recent_findings_is_an_empty_list_before_any_scan(analyst_client):
    """Regression: a missing key crashed the dashboard with 'reading length' on undefined."""
    client, headers, _env = analyst_client
    payload = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert "recent_findings" in payload
    assert payload["recent_findings"] == []


def test_overview_returns_recent_findings_with_endpoint_context(seeded):
    client, headers, _env, data = seeded
    payload = client.get("/api/v1/dashboard/overview", headers=headers).json()
    findings = payload["recent_findings"]
    assert len(findings) == 2
    for finding in findings:
        assert set(finding) == FINDING_KEYS
        assert finding["severity"] in {"critical", "high", "medium", "low", "info"}
        assert isinstance(finding["risk_score"], float)
        assert finding["endpoint_method"] in {"GET", "POST"}
        assert finding["endpoint_path"].startswith("/")
    # Highest risk first, so the panel shows the most urgent item.
    assert [item["risk_score"] for item in findings] == sorted(
        (item["risk_score"] for item in findings), reverse=True
    )
    assert findings[0]["rule_id"] == "ST-003"
    assert payload["findings_by_severity"]["high"] == 1
    assert sum(payload["findings_by_severity"].values()) == 2


def test_overview_recent_findings_is_capped_and_ordered(analyst_client):
    client, headers, env = analyst_client
    _seed_scan(env)
    org_id = env["target"]["org_id"]
    target_id = env["target"]["id"]
    with db() as conn:
        endpoint_id = conn.execute("SELECT id FROM endpoints LIMIT 1").fetchone()["id"]
        for index, score in enumerate([10.0, 90.0, 50.0, 70.0, 30.0, 80.0, 20.0]):
            conn.execute(
                """
                INSERT INTO findings (id, org_id, scan_id, target_id, endpoint_id, rule_id, title, severity,
                                      confidence, status, exposure, risk_score, fingerprint, rationale,
                                      limitations, remediation, evidence, created_at)
                VALUES (?, ?, ?, ?, ?, 'ST-001', ?, 'medium', 'high', 'confirmed', 0.0, ?, ?, '', '', '', '{}', ?)
                """,
                (
                    new_id(),
                    org_id,
                    conn.execute("SELECT id FROM scans LIMIT 1").fetchone()["id"],
                    target_id,
                    endpoint_id,
                    f"Cap probe {index}",
                    score,
                    f"GET|127.0.0.1|/api/cap/{index}|",
                    now() + index,
                ),
            )
    from app.api.dashboard import RECENT_FINDINGS_LIMIT

    payload = client.get("/api/v1/dashboard/overview", headers=headers).json()
    scores = [item["risk_score"] for item in payload["recent_findings"]]
    assert len(scores) == RECENT_FINDINGS_LIMIT
    assert scores == sorted(scores, reverse=True)
    assert scores[0] == 90.0 and 10.0 not in scores


def test_overview_never_leaks_another_organization_findings(seeded):
    """Tenant isolation: the other org sees its own (empty) dashboard, not this one's rows."""
    client, headers, _env, _data = seeded
    mine = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert mine["recent_findings"], "precondition: the seeded org has findings"

    from .conftest import login

    _csrf, other_headers = login(client, "analyst@other.example.test")
    theirs = client.get("/api/v1/dashboard/overview", headers=other_headers).json()
    assert theirs["recent_findings"] == []
    assert theirs["findings_by_severity"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    assert theirs["endpoints"]["total"] == 0
    assert theirs["targets"]["total"] == 0


def test_overview_is_readable_by_every_role_but_not_anonymously(client, app_env):
    from .conftest import login

    assert client.get("/api/v1/dashboard/overview").status_code == 401
    for email in ("viewer@org.example.test", "analyst@org.example.test", "admin@org.example.test"):
        _csrf, headers = login(client, email)
        assert client.get("/api/v1/dashboard/overview", headers=headers).status_code == 200, email


def test_overview_triage_counts_follow_the_finding_triage_state(seeded):
    client, headers, _env, data = seeded
    before = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert before["triage"]["open"] == 2

    client.post(
        f"/api/v1/findings/{data['findings'][0]}/triage",
        json={"status": "false_positive", "reason": "Documented internal tool after review."},
        headers=headers,
    )
    after = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert after["triage"]["open"] == 1
    assert after["triage"]["false_positive"] == 1
    # The recent list reflects the same triage state as the findings list.
    triaged = {item["id"]: item["triage_status"] for item in after["recent_findings"]}
    assert triaged[data["findings"][0]] == "false_positive"


def test_overview_aggregates_targets_scans_and_sources(seeded):
    client, headers, _env, data = seeded
    payload = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert payload["scans_by_state"] == {"completed": 1}
    assert payload["targets"] == {"total": 1, "approved": 1}
    assert payload["source_breakdown"]
    assert set(payload["source_breakdown"][0]) == {"source", "endpoints"}
    assert payload["recent_scans"] and payload["recent_scans"][0]["id"] == data["scan_id"]
    assert set(payload["recent_scans"][0]) == {
        "id",
        "state",
        "created_at",
        "finished_at",
        "counters",
        "target_name",
    }
    assert isinstance(payload["recent_scans"][0]["counters"], dict)
    assert payload["scan_timeline"]


def test_endpoint_counts_use_the_per_scan_classification_not_the_endpoint_row(seeded):
    """`endpoints.classification` is per-upsert; the dashboard must show the inventory truth."""
    client, headers, _env, data = seeded
    payload = client.get("/api/v1/dashboard/overview", headers=headers).json()
    # _seed_scan writes classification on both the endpoint and the scan link.
    assert payload["endpoints"] == {"total": 3, "shadow": 2, "documented": 1, "zombie": 0}


def test_endpoint_counts_survive_a_later_scan_without_a_baseline(analyst_client):
    """A follow-up scan with no baseline writes "unknown"; it must not wipe the dashboard counts."""
    client, headers, env = analyst_client
    data = _seed_scan(env)
    org_id = env["target"]["org_id"]
    target_id = env["target"]["id"]
    with db() as conn:
        second_scan = new_id()
        conn.execute(
            """
            INSERT INTO scans (id, org_id, target_id, created_by, state, config, counters, idempotency_key,
                               partial, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'completed', '{}', '{}', 'no-baseline-scan', 0, ?, ?)
            """,
            (second_scan, org_id, target_id, env["org_analyst"]["id"], now() + 100, now() + 100),
        )
        for endpoint_id in data["endpoints"]:
            conn.execute(
                "UPDATE endpoints SET last_seen_scan = ? WHERE id = ?", (second_scan, endpoint_id)
            )
            conn.execute(
                """
                INSERT INTO scan_endpoints (scan_id, endpoint_id, validation_status, classification)
                VALUES (?, ?, 'unvalidated', 'unknown')
                """,
                (second_scan, endpoint_id),
            )
    payload = client.get("/api/v1/dashboard/overview", headers=headers).json()
    assert payload["endpoints"]["total"] == 3
    assert payload["endpoints"]["shadow"] == 2
    assert payload["endpoints"]["documented"] == 1
    assert len(payload["recent_scans"]) == 2


def test_endpoint_counts_are_zero_for_an_organization_without_endpoints(analyst_client):
    client, headers, env = analyst_client
    from .conftest import login

    _csrf, other_headers = login(client, "analyst@other.example.test")
    payload = client.get("/api/v1/dashboard/overview", headers=other_headers).json()
    assert payload["endpoints"] == {"total": 0, "shadow": 0, "documented": 0, "zombie": 0}
