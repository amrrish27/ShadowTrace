"""Normalization tests: templates must be stable, deduplicated and scope-aware."""
from __future__ import annotations

import pytest

from app.engine.normalizer import (
    NormalizedEndpoint,
    collapse,
    dedupe_endpoints,
    looks_static,
    method_allowed_for_validation,
    normalize_endpoint,
    normalize_path,
    normalize_query,
    normalize_segment,
    split_path,
)
from app.engine.types import DiscoveredEndpoint

UUID = "2f1c8a1e-6f4f-4d1c-9d5c-3a7b8c9d0e1f"
OBJECT_ID = "507f1f77bcf86cd799439011"
SHA = "d41d8cd98f00b204e9800998ecf8427e"


@pytest.mark.parametrize(
    "segment,expected",
    [
        ("42", "{id}"),
        (UUID, "{uuid}"),
        (OBJECT_ID, "{hash}"),
        (SHA, "{hash}"),
        ("{userId}", "{param}"),
        (":userId", "{param}"),
        ("2024-05-01", "{date}"),
        ("session_8f2b1c34d5e6f708", "{token}"),
        ("users", "users"),
        ("api-v1", "api-v1"),
    ],
)
def test_normalize_segment(segment, expected):
    assert normalize_segment(segment) == expected


def test_normalize_path_collapses_values():
    assert normalize_path("/api/v1/users/1234/orders/" + UUID) == "/api/v1/users/{id}/orders/{uuid}"
    assert normalize_path("api/v1/users") == "/api/v1/users"
    assert normalize_path("") == "/"
    assert normalize_path("///") == "/"


def test_normalize_path_caps_segment_count():
    path = "/" + "/".join(f"s{index}" for index in range(60))
    assert normalize_path(path).count("/") == 40


def test_collapse_maps_typed_parameters():
    assert collapse("/api/{id}/{uuid}") == "/api/{param}/{param}"
    assert collapse("/api/users") == "/api/users"


def test_normalize_query_drops_tracking_and_sorts():
    assert normalize_query("b=2&a=1") == "a={value}&b={value}"
    assert normalize_query("utm_source=x&page=2") == "page={value}"
    assert normalize_query("") == ""
    assert normalize_query("flag") == "flag"


def test_normalize_endpoint_builds_fingerprint():
    endpoint = DiscoveredEndpoint(
        method="get", path="/api/v1/users/42", query="role=admin", source_type="html"
    )
    normalized = normalize_endpoint(endpoint, "https://api.example.test")
    assert normalized is not None
    assert normalized.method == "GET"
    assert normalized.path_template == "/api/v1/users/{param}"
    assert normalized.query_template == "role={value}"
    assert normalized.fingerprint == "GET|api.example.test|/api/v1/users/{param}|role={value}"


def test_normalize_endpoint_uses_endpoint_base_and_skips_static():
    endpoint = DiscoveredEndpoint(method="GET", path="/assets/app.js")
    assert normalize_endpoint(endpoint, "https://api.example.test") is None
    absolute = DiscoveredEndpoint(method="GET", path="/api/ping", base_url="https://other.example.test")
    normalized = normalize_endpoint(absolute, "https://api.example.test")
    assert normalized is not None
    assert normalized.host == "other.example.test"
    assert normalized.origin == "https://other.example.test"


def test_normalize_endpoint_requires_a_base():
    assert normalize_endpoint(DiscoveredEndpoint(method="GET", path="/api/ping"), "") is None


def test_dedupe_groups_by_fingerprint():
    low = DiscoveredEndpoint(method="GET", path="/api/v1/users/1", source_type="html", confidence=0.4)
    high = DiscoveredEndpoint(method="GET", path="/api/v1/users/2", source_type="javascript", confidence=0.9)
    other = DiscoveredEndpoint(method="GET", path="/api/v1/orders/3", source_type="html")
    pairs = []
    for endpoint in (low, high, other):
        normalized = normalize_endpoint(endpoint, "https://api.example.test")
        assert normalized is not None
        pairs.append((normalized, endpoint))
    grouped = dedupe_endpoints(pairs)
    assert len(grouped) == 2
    users = grouped["GET|api.example.test|/api/v1/users/{param}|"]
    assert users[0].path_template == "/api/v1/users/{param}"
    assert [raw.path for raw in users[1]] == ["/api/v1/users/1", "/api/v1/users/2"]


def test_static_assets_and_safe_methods():
    assert looks_static("/static/app.css")
    assert looks_static("/img/logo.PNG")
    assert not looks_static("/api/v1/users")
    assert method_allowed_for_validation("GET")
    assert method_allowed_for_validation("head")
    assert method_allowed_for_validation("OPTIONS")
    assert not method_allowed_for_validation("POST")
    assert not method_allowed_for_validation("DELETE")


def test_split_path():
    assert split_path("/api/v1/users/{id}") == ["api", "v1", "users", "{id}"]
    assert split_path("/") == []


def test_normalized_endpoint_is_immutable():
    endpoint = NormalizedEndpoint(
        method="GET", scheme="https", host="a.test", path_template="/x", query_template="", raw_path="/x", origin="https://a.test"
    )
    with pytest.raises(Exception):
        endpoint.host = "b.test"  # type: ignore[misc]
