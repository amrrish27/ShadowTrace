"""Reconciliation, risk scoring and rule-registry tests."""
from __future__ import annotations

import pytest

from app.engine.reconciler import (
    build_baseline,
    collapse,
    compare_scans,
    legacy_version_hint,
    match_key,
    reconcile,
)
from app.engine.risk import (
    CONFIDENCE_ORDER,
    SEVERITY_ORDER,
    confidence_rank,
    exposure_factor,
    risk_score,
    severity_rank,
)
from app.engine.rules import (
    CERTAINTY_PHRASES,
    ENDPOINT_RULES,
    evaluate_endpoint,
    lint_wording,
    rules_documentation,
)
from app.engine.scan_rules import SCAN_RULES, ScanFacts, cleartext_http, legacy_api, soft_404, zombie_endpoint
from app.engine.types import RuleInput

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "Lab API", "version": "1.0.0"},
    "paths": {
        "/api/v1/users": {"get": {"summary": "list"}},
        "/api/v1/users/{id}": {"get": {}, "delete": {}},
        "/api/v1/admin/metrics": {"get": {"security": []}},
    },
    "security": [{"bearerAuth": []}],
}


def _input(**overrides) -> RuleInput:
    payload = dict(
        endpoint_method="GET",
        endpoint_path="/api/v1/users",
        endpoint_url="https://app.example.test/api/v1/users",
        classification="shadow",
        status_code=200,
        headers={"content-type": "application/json", "x-content-type-options": "nosniff", "content-security-policy": "default-src 'none'"},
        body_text='[{"id": 1}]',
        content_type="application/json",
        discovered_from=["javascript"],
        target_scheme="https",
    )
    payload.update(overrides)
    return RuleInput(**payload)


# ---------------------------------------------------------------- reconciler


def test_match_key_collapses_parameters():
    assert match_key("get", "/api/v1/users/1234") == "GET /api/v1/users/{param}"
    assert match_key("GET", "/api/v1/users/{userId}") == "GET /api/v1/users/{param}"
    assert collapse("/api/{a}/{b}") == "/api/{param}/{param}"


def test_build_baseline_reads_paths_and_protection():
    baseline = build_baseline(OPENAPI, "openapi")
    assert baseline.title == "Lab API"
    assert baseline.version == "1.0.0"
    assert baseline.endpoint_count == 4
    assert baseline.is_documented("GET", "/api/v1/users")
    assert baseline.is_documented("GET", "/api/v1/users/7")
    # Global security applies to all operations ...
    assert baseline.is_protected("GET", "/api/v1/users")
    # ... unless the operation explicitly opts out with an empty security list.
    assert not baseline.is_protected("GET", "/api/v1/admin/metrics")
    assert baseline.is_protected("DELETE", "/api/v1/users/{id}")


def test_reconcile_classifies_shadow_documented_and_zombies():
    baseline = build_baseline(OPENAPI, "openapi")
    discovered = [("GET", "/api/v1/users/42"), ("GET", "/api/v1/internal/debug")]
    result = reconcile(discovered, baseline)
    assert result.classifications["GET /api/v1/users/{param}"] == "documented"
    assert result.classifications["GET /api/v1/internal/debug"] == "shadow"
    assert result.shadow_keys == ["GET /api/v1/internal/debug"]
    assert result.documented_count == 1
    # Every documented operation that was not observed becomes a zombie candidate.
    zombie_pairs = set(result.zombies)
    assert ("DELETE", "/api/v1/users/{param}") in zombie_pairs
    assert ("GET", "/api/v1/admin/metrics") in zombie_pairs
    assert ("GET", "/api/v1/users/{param}") not in zombie_pairs
    assert result.zombie_count == len(result.zombies) == 3


def test_reconcile_without_baseline_is_unknown():
    result = reconcile([("GET", "/api/v1/users")], None)
    assert result.classifications == {"GET /api/v1/users": "unknown"}
    assert result.shadow_keys == []
    assert result.zombies == []


def test_legacy_version_hint():
    hints = legacy_version_hint(
        documented=["GET /api/v2/users/{param}"],
        shadow=["GET /api/v1/users/{param}", "GET /api/v9/other"],
    )
    assert hints == [("GET", "/api/v1/users/{param}", "/api/v2/users/{param}")]


def test_compare_scans():
    previous = {"GET|a|/x|": ("GET", "/x", 200), "GET|a|/y|": ("GET", "/y", 404)}
    current = {"GET|a|/x|": ("GET", "/x", 401), "GET|a|/z|": ("GET", "/z", 200)}
    diff = compare_scans(previous, current)
    assert [entry["path"] for entry in diff["new"]] == ["/z"]
    assert [entry["path"] for entry in diff["removed"]] == ["/y"]
    assert diff["changed"][0]["previous_status"] == 200
    assert diff["changed"][0]["status"] == 401


def test_baseline_ignores_non_dict_documents():
    assert build_baseline([], "x").endpoint_count == 0
    assert build_baseline({"paths": "nope"}, "x").endpoint_count == 0


# ---------------------------------------------------------------- risk


def test_risk_score_is_bounded_and_monotonic():
    assert risk_score("medium", "high", 0.0) == 49.6
    assert risk_score("critical", "confirmed", 1.0) == 96.0
    assert risk_score("critical", "confirmed", 5.0) == 96.0  # exposure is clamped
    assert risk_score("info", "low", 0.0) == 4.4
    for severity in SEVERITY_ORDER:
        for confidence in CONFIDENCE_ORDER:
            score = risk_score(severity, confidence, 1.0)
            assert 0.0 <= score <= 100.0
            assert severity_rank(severity) == SEVERITY_ORDER.index(severity)
            assert confidence_rank(confidence) == CONFIDENCE_ORDER.index(confidence)
    # No overlap between bands: a lower severity can never outrank a higher one.
    assert risk_score("low", "confirmed", 1.0) < risk_score("medium", "low", 0.0)


def test_risk_score_rejects_unknown_buckets():
    with pytest.raises(ValueError):
        risk_score("catastrophic", "high", 0.5)
    with pytest.raises(ValueError):
        risk_score("high", "certain", 0.5)


def test_exposure_factor():
    assert exposure_factor(unauthenticated=False) == 0.2
    assert exposure_factor(unauthenticated=True) == 0.7
    assert exposure_factor(unauthenticated=True, sensitive_path=True) == 0.9
    assert exposure_factor(unauthenticated=True, in_scope=False, sensitive_path=True) == 0.7


# ---------------------------------------------------------------- rules


def test_rule_registry_is_unique_and_documented():
    ids = [rule.id for rule in ENDPOINT_RULES]
    assert len(ids) == len(set(ids))
    assert ids[0] == "ST-001"
    for rule in ENDPOINT_RULES:
        assert rule.severity in SEVERITY_ORDER
        assert rule.description
    documented = rules_documentation()
    assert {entry["id"] for entry in documented} == set(ids)
    assert {entry["id"] for entry in SCAN_RULES}.isdisjoint(set(ids))


def test_every_rule_text_passes_the_wording_lint():
    for rule in ENDPOINT_RULES:
        hit = rule.evaluate(_input(classification="shadow", status_code=200)) if rule.id != "ST-001" else None
        if hit is None:
            continue
        assert lint_wording(hit.status, hit.rationale, hit.limitations) == [], rule.id


def test_wording_lint_rejects_overclaiming_and_unhedged_suspicion():
    assert lint_wording("confirmed", "The route is vulnerable to IDOR.", "none") == [
        "certainty phrase in confirmed finding: 'is vulnerable'"
    ]
    assert "suspected finding lacks hedged wording" in lint_wording(
        "suspected", "The endpoint exposes records.", "not verified"
    )
    assert "empty rationale" in lint_wording("confirmed", "  ", "x")
    assert "empty limitations" in lint_wording("confirmed", "ok", "")
    for phrase in CERTAINTY_PHRASES:
        assert lint_wording("confirmed", f"This {phrase}.", "x")


def test_shadow_endpoint_rule():
    hits = evaluate_endpoint(_input(classification="shadow", status_code=200))
    assert [hit.rule_id for hit in hits] == ["ST-001"]
    assert hits[0].status == "confirmed"
    assert "not present in the documented baseline" in hits[0].rationale
    assert "undocumented API surface" in hits[0].rationale


def test_st001_requires_api_likeness():
    non_api = _input(
        endpoint_path="/about-us",
        headers={"content-type": "text/html"},
        content_type="text/html",
        discovered_from=["html"],
        classification="shadow",
        status_code=200,
    )
    hits = evaluate_endpoint(non_api)
    assert not any(hit.rule_id == "ST-001" for hit in hits)


def test_extra_rules_do_not_fire_by_default():
    # Endpoints with patterns that would match extra rules (CORS, debug, missing headers)
    inp = _input(
        endpoint_path="/api/v1/internal/debug",
        headers={"access-control-allow-origin": "*", "content-type": "application/json"},
        classification="documented",
        documented=True,
    )
    default_hits = evaluate_endpoint(inp, extra_rules=False)
    # Only core rules (ST-001, ST-004) can fire
    for hit in default_hits:
        assert hit.rule_id in {"ST-001", "ST-004"}
    assert not any(hit.rule_id in {"ST-002", "ST-003", "ST-005", "ST-006", "ST-007", "ST-008", "ST-010", "ST-011", "ST-013"} for hit in default_hits)

    # When extra_rules=True, they fire
    extra_hits = evaluate_endpoint(inp, extra_rules=True)
    assert any(hit.rule_id in {"ST-003", "ST-006"} for hit in extra_hits)


def test_documented_endpoint_is_not_shadow():
    assert evaluate_endpoint(_input(classification="documented", status_code=200)) == []


def test_protected_bypass_rule_is_suspected():
    hits = evaluate_endpoint(
        _input(classification="documented", documented=True, baseline_protected=True, status_code=200),
        extra_rules=True,
    )
    ids = [hit.rule_id for hit in hits]
    assert "ST-002" in ids
    hit = next(hit for hit in hits if hit.rule_id == "ST-002")
    assert hit.status == "suspected"
    assert hit.severity == "high"


def test_debug_and_specification_rules():
    debug = evaluate_endpoint(
        _input(endpoint_path="/api/v1/internal/debug", classification="documented", documented=True),
        extra_rules=True,
    )
    assert "ST-003" in {hit.rule_id for hit in debug}

    spec = evaluate_endpoint(
        _input(
            endpoint_path="/openapi.json",
            endpoint_url="https://app.example.test/openapi.json",
            body_text='{"openapi": "3.0.0", "paths": {"/api/v1/users": {"get": {}}}}',
            classification="documented",
        )
    )
    assert "ST-004" in {hit.rule_id for hit in spec}


def test_graphql_introspection_rule():
    body = '{"data": {"__schema": {"queryType": {"name": "Query"}}}}'
    hits = evaluate_endpoint(
        _input(
            endpoint_path="/graphql",
            endpoint_url="https://app.example.test/graphql",
            endpoint_method="POST",
            body_text=body,
            classification="shadow",
        ),
        extra_rules=True,
    )
    assert "ST-005" in {hit.rule_id for hit in hits}


def test_cors_rules():
    wildcard = evaluate_endpoint(
        _input(headers={"access-control-allow-origin": "*"}),
        extra_rules=True,
    )
    assert "ST-006" in {hit.rule_id for hit in wildcard}


def test_risky_methods_and_verbose_errors():
    allow = evaluate_endpoint(
        _input(headers={"allow": "GET, PUT, DELETE, TRACE"}),
        extra_rules=True,
    )
    assert "ST-007" in {hit.rule_id for hit in allow}

    verbose = evaluate_endpoint(
        _input(
            status_code=500,
            headers={"content-type": "text/plain", "x-content-type-options": "nosniff"},
            body_text='Traceback (most recent call last): File "/srv/app/api.py", line 42, in handler',
        ),
        extra_rules=True,
    )
    assert "ST-008" in {hit.rule_id for hit in verbose}


def test_secret_rule_redacts_the_value():
    token = "AKIAIOSFODNN7EXAMPLE"
    hits = evaluate_endpoint(_input(body_text=f'{{"key": "{token}"}}'), extra_rules=True)
    secret = next(hit for hit in hits if hit.rule_id == "ST-010")
    assert token not in str(secret.evidence)
    assert "redacted" in str(secret.evidence).lower()


def test_sensitive_fields_rule():
    body = '{"email": "a@b.test", "password_hash": "deadbeef", "ssn": "123-45-6789"}'
    hits = evaluate_endpoint(_input(body_text=body), extra_rules=True)
    assert "ST-011" in {hit.rule_id for hit in hits}


def test_missing_headers_rule():
    hits = evaluate_endpoint(_input(headers={"content-type": "application/json"}), extra_rules=True)
    assert "ST-013" in {hit.rule_id for hit in hits}


def test_cleartext_and_banner_scan_rules():
    cleartext = cleartext_http("http://lab.example.test", "/api/v1/users")
    assert cleartext.rule_id == "ST-012" and cleartext.severity == "medium"
    assert cleartext.status == "confirmed"

    legacy = legacy_api("/api/v1/users", "/api/v2/users", "GET", "https://app.example.test")
    assert legacy.rule_id == "ST-015"
    zombie = zombie_endpoint("DELETE", "/api/v1/users/{param}", "https://app.example.test")
    assert zombie.rule_id == "ST-016" and zombie.severity == "info"
    catch_all = soft_404("<html>app shell</html>")
    assert catch_all.rule_id == "ST-017"
    assert "not a vulnerability" in catch_all.limitations


def test_scan_facts_default_shape():
    facts = ScanFacts(base_url="https://app.example.test")
    assert facts.source_maps == [] and facts.zombies == [] and facts.exposed_specs == []


def test_scan_rule_text_passes_lint():
    for hit in (
        cleartext_http("http://lab.example.test", "/api/v1/users"),
        legacy_api("/api/v1/users", "/api/v2/users", "GET", "https://app.example.test"),
        zombie_endpoint("GET", "/api/v1/gone", "https://app.example.test"),
        soft_404("<html>shell</html>"),
    ):
        assert lint_wording(hit.status, hit.rationale, hit.limitations) == []
