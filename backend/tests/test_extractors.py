"""Extractor tests over the five discovery sources plus HAR import."""
from __future__ import annotations

import json

from app.engine.extractors.har_extract import parse_har
from app.engine.extractors.html_extract import extract_html, extract_method_path_pairs
from app.engine.extractors.js_extract import extract_javascript
from app.engine.extractors.robotssitemap import API_MARKERS, parse_robots, parse_sitemap
from app.engine.extractors.sourcemap import (
    extraction_from_map,
    find_source_map_reference,
    source_map_header,
)
from app.engine.extractors.specs import (
    WELL_KNOWN_SPEC_PATHS,
    documented_signatures,
    is_openapi,
    is_postman,
    parse_specification,
)

BASE = "https://app.example.test"


def _paths(result):
    return sorted({f"{endpoint.method} {endpoint.path}" for endpoint in result.endpoints})


# ---------------------------------------------------------------- HTML


def test_html_links_forms_and_scripts():
    html = """
    <html><head>
      <link rel="stylesheet" href="/static/app.css">
      <script src="/static/app.js"></script>
      <meta name="application-url" content="url=/api/v1/meta">
    </head><body>
      <a href="/api/v1/users">Users</a>
      <a href="/catalog">Catalog</a>
      <form action="/api/v1/login" method="POST"><input name="email"></form>
      <div data-endpoint="/api/v1/feature-flags"></div>
      <script>fetch('/api/v1/session');</script>
    </body></html>
    """
    result = extract_html(html, f"{BASE}/index.html")
    paths = _paths(result)
    assert "GET /api/v1/users" in paths
    assert "POST /api/v1/login" in paths
    assert "GET /api/v1/feature-flags" in paths
    assert "GET /api/v1/meta" in paths
    assert f"{BASE}/static/app.js" in result.scripts
    assert any(location.startswith("inline-script[") for location, _ in result.inline_scripts)
    assert any(spec.get("kind") == "form" and spec.get("action") == "/api/v1/login" for spec in result.specifications)


def test_html_comments_are_decoys_not_sources():
    html = """<html><body><!-- GET /api/v1/decoy-only-in-comment -->
        <a href="/catalog">catalog</a></body></html>"""
    result = extract_html(html, f"{BASE}/")
    assert "GET /api/v1/decoy-only-in-comment" not in _paths(result)
    # Non-API navigation targets are kept as crawl links, never as inventory endpoints.
    assert f"{BASE}/catalog" in result.links
    assert _paths(result) == []


def test_html_prose_is_not_an_endpoint_source():
    html = "<html><body><p>See GET /api/v1/decoy-in-prose for details.</p></body></html>"
    assert _paths(extract_html(html, f"{BASE}/")) == []


def test_html_base_tag_rebases_relative_links():
    html = '<html><head><base href="/app/"></head><body><a href="api/v1/status">s</a></body></html>'
    result = extract_html(html, f"{BASE}/index.html")
    assert "GET /app/api/v1/status" in _paths(result)


def test_method_path_pairs_are_low_confidence_hints():
    text = "Docs:\nGET /api/v1/users\nPOST /api/v1/users/{id}\nnot-a-method /nope"
    endpoints = extract_method_path_pairs(text, f"{BASE}/docs")
    assert [f"{e.method} {e.path}" for e in endpoints] == ["GET /api/v1/users", "POST /api/v1/users/{id}"]
    assert all(endpoint.confidence < 0.5 for endpoint in endpoints)


# ---------------------------------------------------------------- JavaScript


def test_javascript_client_calls_and_literals():
    code = """
    const API_BASE = '/api/v1';
    fetch('/api/v1/session');
    axios.post('/api/v1/users', payload);
    axios.get(`${API_BASE}/reports/summary`);
    const xhr = new XMLHttpRequest(); xhr.open('DELETE', '/api/v1/users/9');
    $.get('/api/v1/orders');
    new WebSocket('wss://app.example.test/ws');
    const url = 'https://app.example.test/api/v1/remote';
    fetch(API_BASE + '/invoices');
    """
    result = extract_javascript(code, f"{BASE}/static/app.js", BASE)
    paths = _paths(result)
    for expected in (
        "GET /api/v1/session",
        "POST /api/v1/users",
        "GET /api/v1/reports/summary",
        "DELETE /api/v1/users/9",
        "GET /api/v1/orders",
        "GET /api/v1/remote",
        "GET /api/v1/invoices",
    ):
        assert expected in paths, expected


def test_javascript_template_parameter_paths_are_kept():
    code = "const item = '/api/v1/users/${userId}/invoices';"
    result = extract_javascript(code, f"{BASE}/app.js", BASE)
    # Template parameters are normalized like path parameters.
    assert "GET /api/v1/users/{param}/invoices" in _paths(result)


def test_javascript_ignores_non_path_strings():
    code = "const label = 'hello world'; const css = 'flex';"
    assert extract_javascript(code, f"{BASE}/app.js", BASE).endpoints == []


# ---------------------------------------------------------------- Specs


OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Lab", "version": "1"},
    "paths": {
        "/api/v1/users": {"get": {"summary": "List users"}},
        "/api/v1/users/{id}": {"get": {}, "delete": {"security": []}},
        "not-a-path": {"get": {}},
    },
}


def test_openapi_document_yields_operations_and_baseline():
    result = parse_specification(json.dumps(OPENAPI), f"{BASE}/openapi.json", BASE)
    assert "GET /api/v1/users" in _paths(result)
    assert "DELETE /api/v1/users/{id}" in _paths(result)
    assert "GET /not-a-path" not in _paths(result)
    assert is_openapi(OPENAPI)
    signatures = documented_signatures(OPENAPI)
    assert ("GET", "/api/v1/users") in signatures
    assert ("DELETE", "/api/v1/users/{id}") in signatures
    # Only absolute path keys become endpoints.
    assert all("/not-a-path" not in f"{method} {path}" for method, path in documented_signatures({**OPENAPI, "paths": {"/api/v1/users": {"get": {}}}}))


def test_openapi_remote_refs_are_refused_not_fetched():
    document = {
        "openapi": "3.0.0",
        "paths": {"/api/v1/ping": {"get": {}}},
        "components": {"schemas": {"$ref": "http://169.254.169.254/latest/meta-data/"}},
    }
    result = parse_specification(json.dumps(document), f"{BASE}/openapi.json", BASE)
    assert any(note.startswith("refused_remote_refs") for note in result.notes)


def test_swagger_ui_config_points_at_specification():
    config = {"urls": [{"name": "v1", "url": "/api/openapi.json"}]}
    result = parse_specification(json.dumps(config), f"{BASE}/swagger-ui-init.js", BASE)
    assert "GET /api/openapi.json" in _paths(result)


def test_postman_collection_is_supported():
    collection = {
        "info": {"name": "lab", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": [
            {"name": "users", "request": {"method": "GET", "url": {"path": ["api", "v1", "users"]}}},
            {"name": "folder", "item": [{"request": {"method": "POST", "url": {"raw": "/api/v1/users"}}}]},
        ],
    }
    result = parse_specification(json.dumps(collection), f"{BASE}/collection.json", BASE)
    assert "GET /api/v1/users" in _paths(result)
    assert "POST /api/v1/users" in _paths(result)
    assert is_postman(collection)


def test_unrecognised_and_unsafe_documents_are_noted():
    unrecognised = parse_specification("just: a mapping\n", f"{BASE}/spec.json", BASE)
    assert "specification_unrecognized" in unrecognised.notes
    unsafe = parse_specification(
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        f"{BASE}/spec.xml",
        BASE,
    )
    assert unsafe.endpoints == []
    assert unsafe.notes


def test_well_known_spec_paths_are_bounded():
    assert len(WELL_KNOWN_SPEC_PATHS) >= 20
    assert all(path.startswith("/") for path in WELL_KNOWN_SPEC_PATHS)
    assert len(set(WELL_KNOWN_SPEC_PATHS)) == len(WELL_KNOWN_SPEC_PATHS)


# ---------------------------------------------------------------- robots.txt / sitemap


def test_robots_disallow_and_sitemap_hints():
    robots = """
    User-agent: *
    Disallow: /api/internal/
    Disallow: /api/v1/debug
    Disallow: /private
    Sitemap: https://app.example.test/sitemap.xml
    """
    result = parse_robots(robots, f"{BASE}/robots.txt", BASE)
    assert "GET /api/v1/debug" in _paths(result)
    # Directory prefixes and shallow paths are not endpoints.
    assert "GET /api/internal/" not in _paths(result)
    assert "GET /private" not in _paths(result)
    assert any(note.startswith("sitemap_url:") for note in result.notes)


def test_sitemap_namespaced_urlset_keeps_only_api_like_urls():
    body = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://app.example.test/api/v1/users</loc></url>
      <url><loc>https://app.example.test/catalog</loc></url>
      <url><loc>http://169.254.169.254/latest/meta-data/</loc></url>
    </urlset>"""
    result, sitemaps = parse_sitemap(body, f"{BASE}/sitemap.xml", BASE)
    paths = _paths(result)
    assert "GET /api/v1/users" in paths
    assert "GET /catalog" not in paths
    assert all("169.254" not in path for path in paths)
    assert sitemaps == []
    assert any(note.startswith("sitemap_entries:") for note in result.notes)


def test_sitemap_index_follows_child_sitemaps():
    body = """<?xml version="1.0" encoding="UTF-8"?>
    <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap><loc>https://app.example.test/sitemap-api.xml</loc></sitemap>
    </sitemapindex>"""
    result, sitemaps = parse_sitemap(body, f"{BASE}/sitemap.xml", BASE)
    assert sitemaps == ["https://app.example.test/sitemap-api.xml"]


def test_sitemap_with_entities_is_rejected():
    body = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "abc">]><urlset><url><loc>&e;</loc></url></urlset>'
    result, sitemaps = parse_sitemap(body, f"{BASE}/sitemap.xml", BASE)
    assert result.endpoints == []
    assert sitemaps == []
    assert "sitemap_rejected" in result.notes


def test_api_markers_cover_the_usual_namespaces():
    assert any("/api/" == marker for marker in API_MARKERS)
    assert "/graphql" in API_MARKERS


# ---------------------------------------------------------------- Source maps


def test_source_map_reference_detection():
    assert find_source_map_reference("var a=1;\n//# sourceMappingURL=app.js.map") == "app.js.map"
    assert find_source_map_reference("", "application/json") is None
    assert source_map_header({"sourcemap": "app.js.map"}) == "app.js.map"


def test_source_map_contents_are_scanned_but_traversal_strings_ignored():
    mapping = {
        "version": 3,
        "file": "app.js",
        "sources": ["../secrets/config.js", "src/api.js"],
        "sourcesContent": ["const hidden = fetch('/api/v1/legacy-reports');", ""],
    }
    result = extraction_from_map(json.dumps(mapping), f"{BASE}/app.js.map", BASE)
    assert "GET /api/v1/legacy-reports" in _paths(result)
    assert "source_map_traversal_strings_ignored" in result.notes
    assert any(note.startswith("source_map_target:") for note in result.notes)


def test_source_map_without_content_is_noted():
    result = extraction_from_map(json.dumps({"version": 3, "sources": ["a.js"]}), f"{BASE}/a.js.map", BASE)
    assert result.endpoints == []
    assert "source_map_parsed_without_content" in result.notes


# ---------------------------------------------------------------- HAR


def _har(entries):
    return json.dumps({"log": {"version": "1.2", "entries": entries}})


def test_har_import_filters_scope_and_redacts():
    entries = [
        {
            "request": {
                "method": "GET",
                "url": "https://app.example.test/api/v1/users",
                "headers": [{"name": "Authorization", "value": "Bearer abcdef123456"}],
            }
        },
        {"request": {"method": "POST", "url": "https://evil.example.net/api/v1/users"}},
        {"request": {"method": "GET", "url": "ftp://app.example.test/x"}},
        {"nope": True},
    ]
    result = parse_har(_har(entries), source_name="capture.har", base_url=BASE, policy_hosts=("app.example.test",))
    assert result.entries_total == 4
    assert result.entries_in_scope == 1
    assert result.entries_out_of_scope == 1
    assert result.entries_dropped == 2
    assert _paths(result.result) == ["GET /api/v1/users"]
    dumped = json.dumps(result.redacted_entries)
    assert "abcdef123456" not in dumped


def test_har_invalid_document_is_noted():
    result = parse_har("{not json", source_name="bad.har", base_url=BASE, policy_hosts=("app.example.test",))
    assert result.result.endpoints == []
    assert "har_invalid" in result.result.notes
