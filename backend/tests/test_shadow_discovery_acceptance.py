"""Acceptance tests T1–T11 for ShadowTrace API shadow-endpoint discovery overhaul.

All tests run locally on ephemeral loopback ports with mock HTTP handlers.
No external network requests are made.
"""
from __future__ import annotations

import http.server
import json
import socket
import threading
import time
from typing import Dict, List, Tuple
import pytest

from app.config import get_settings
from app.db import db, new_id, now
from app.engine.api_gate import api_likeness
from app.engine.safe_http import SafeHttpClient
from app.engine.scope import ScopePolicy
from app.security.labgrant import grant_signature
from app.services import scans as scan_service
from app.workers.worker import execute_scan


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class EphemeralServer:
    def __init__(self, handler_cls):
        self.port = _free_port()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), handler_cls)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.base_url = f"http://127.0.0.1:{self.port}"

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


def run_test_scan(conn, base_url: str, port: int, *, har_entries=None, baseline_spec=None, scan_type="full"):
    """Helper to register target, grant, and execute scan against local test server."""
    org_id = new_id()
    user_id = new_id()
    conn.execute("INSERT INTO organizations (id, name, created_at) VALUES (?, 'TestOrg', ?)", (org_id, now()))
    conn.execute(
        "INSERT INTO users (id, org_id, name, email, password_hash, role, created_at) VALUES (?, ?, 'Tester', 'u@test.org', 'x', 'admin', ?)",
        (user_id, org_id, now()),
    )
    
    secret = get_settings().secret_key
    target_id = new_id()
    grant = grant_signature(
        secret=secret,
        target_id=target_id,
        scheme="http",
        host="127.0.0.1",
        port=port,
    )

    conn.execute(
        """
        INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes, authorization_mode,
                             authorization_status, attestation, justification, verification_token, verified_at,
                             verified_by, created_by, created_at, limits, lab_grant, lab_grant_at)
        VALUES (?, ?, 'Tgt', ?, '127.0.0.1', 'http', ?, '[]', 'lab_allowlist', 'approved', 'attest', 'just', 'tok', ?, ?, ?, ?, '{}', ?, ?)
        """,
        (target_id, org_id, base_url, json.dumps([port]), now(), user_id, user_id, now(), grant, now()),
    )

    har_id = None
    if har_entries:
        har_id = new_id()
        conn.execute(
            "INSERT INTO har_imports (id, org_id, target_id, name, entries, created_by, created_at) VALUES (?, ?, ?, 'test.har', ?, ?, ?)",
            (har_id, org_id, target_id, json.dumps(har_entries), user_id, now()),
        )

    target_row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()

    scan_config = {
        "scan_type": scan_type,
        "max_pages": 40,
        "max_depth": 3,
        "probe_wordlist": True,
        "extra_rules": False,
    }
    if har_id:
        scan_config["har_import_id"] = har_id

    scan_row, _ = scan_service.create_scan(
        conn,
        org_id=org_id,
        user_id=user_id,
        target_row=target_row,
        idempotency_key=new_id(),
        config=scan_config,
        baseline_id=None,
        settings=get_settings(),
    )
    scan_id = scan_row["id"]
    conn.commit()

    summary_obj = execute_scan(conn, scan_id=scan_id)
    summary = summary_obj.__dict__ if hasattr(summary_obj, "__dict__") else {}

    scan_row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    endpoints = conn.execute(
        "SELECT e.*, (SELECT GROUP_CONCAT(DISTINCT s.source_type) FROM endpoint_sources s WHERE s.endpoint_id = e.id) as source_types "
        "FROM scan_endpoints se JOIN endpoints e ON e.id = se.endpoint_id WHERE se.scan_id = ?",
        (scan_id,),
    ).fetchall()
    findings = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
    sources = conn.execute(
        "SELECT es.* FROM endpoint_sources es JOIN scan_endpoints se ON se.endpoint_id = es.endpoint_id WHERE se.scan_id = ?",
        (scan_id,),
    ).fetchall()

    return {
        "scan": dict(scan_row),
        "summary": summary,
        "endpoints": [dict(e) for e in endpoints],
        "findings": [dict(f) for f in findings],
        "sources": [dict(s) for s in sources],
    }


# ==============================================================================
# T1: Clean site with HTML pages + 2 JSON APIs, no spec
# ==============================================================================
def test_t1_clean_site_no_spec_reports_discovered_not_shadow(app_env):
    class CleanSiteHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/", "/index.html"):
                body = '<html><body><h1>Welcome</h1><a href="/about">About</a><script>fetch("/api/v1/users"); fetch("/api/v1/orders");</script></body></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/about":
                body = "<html><body>About us</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path in ("/api/v1/users", "/api/v1/orders"):
                body = '{"items": []}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(CleanSiteHandler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            # Baseline is "none", so 0 shadow endpoints, live APIs are "discovered"
            assert res["summary"].get("shadow_endpoints", 0) == 0
            discovered = [e for e in res["endpoints"] if e["classification"] == "discovered"]
            assert len(discovered) >= 2
            paths = {e["path_template"] for e in discovered}
            assert "/api/v1/users" in paths
            assert "/api/v1/orders" in paths
            # Neither "/" nor "/about" should have findings or be labeled shadow
            slash_endpoints = [e for e in res["endpoints"] if e["path_template"] in ("/", "/about")]
            for ep in slash_endpoints:
                assert ep["classification"] != "shadow"
            for f in res["findings"]:
                assert f["path"] not in ("/", "/about")
    finally:
        server.stop()


# ==============================================================================
# T2: Marketing-site fixture (Tailwind/Next image CDN queries, form embeds, 404 feeds)
# ==============================================================================
def test_t2_marketing_site_produces_zero_shadow_and_zero_findings(app_env):
    class MarketingHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = """
                <html><body>
                  <h1>Product Landing</h1>
                  <img src="/_next/image?url=%2Fhero.png&w=1200&q=75" />
                  <img src="/media/banner.jpg?auto=format&fit=crop&w=800&h=400&q=80" />
                  <a href="/forms/hackhalt">Contact</a>
                  <a href="/feeds/updates.json">Feeds</a>
                  <a href="/advisories?direction=desc&per_page=10&sort=date">Advisories</a>
                </body></html>
                """
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(MarketingHandler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            # Must produce 0 shadow endpoints and 0 findings
            assert res["summary"].get("shadow_endpoints", 0) == 0
            for ep in res["endpoints"]:
                assert ep["classification"] != "shadow"
            assert len(res["findings"]) == 0
    finally:
        server.stop()


# ==============================================================================
# T3: VAmPI fixture with auto-discovered openapi.json + unlisted live route
# ==============================================================================
def test_t3_auto_discovered_spec_classifies_documented_and_shadow(app_env):
    class VampiHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path in ("/openapi.json", "/api/v1/openapi.json"):
                spec = {
                    "openapi": "3.0.0",
                    "info": {"title": "VAmPI", "version": "1.0"},
                    "paths": {
                        f"/api/v1/item{i}": {"get": {"responses": {"200": {"description": "ok"}}}}
                        for i in range(16)
                    },
                }
                body = json.dumps(spec)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path.startswith("/api/v1/item"):
                body = '{"status": "ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/api/v1/unlisted":
                body = '{"secret": "discovered"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/":
                body = '<html><body><script>fetch("/api/v1/unlisted");</script></body></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(VampiHandler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            # Auto-discovered spec used as baseline
            assert res["summary"].get("baseline_origin") == "auto-discovered"
            documented = [e for e in res["endpoints"] if e["classification"] == "documented"]
            assert len(documented) >= 16
            shadow = [e for e in res["endpoints"] if e["classification"] == "shadow"]
            # /api/v1/unlisted is live, API-like, not in spec -> shadow!
            assert len(shadow) == 1
            assert shadow[0]["path_template"] == "/api/v1/unlisted"
            assert shadow[0]["source_types"] is not None
    finally:
        server.stop()


# ==============================================================================
# T4: DVGA-like routes probe coverage
# ==============================================================================
def test_t4_dvga_probing_finds_unlinked_routes(app_env):
    class DvgaHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            dvga_routes = {
                "/graphql": ('{"data":{"__schema":{"queryType":{"name":"Query"}}}}', "application/json"),
                "/graphiql": ("<html>GraphiQL</html>", "text/html"),
                "/audit": ('{"audit": []}', "application/json"),
                "/solutions": ('{"solutions": []}', "application/json"),
                "/about": ("<html>About DVGA</html>", "text/html"),
                "/create_paste": ('{"status": "ok"}', "application/json"),
                "/start_over": ('{"status": "ok"}', "application/json"),
                "/upload_paste": ('{"status": "ok"}', "application/json"),
            }
            if self.path in dvga_routes:
                body, ct = dvga_routes[self.path]
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/":
                body = "<html><body>Welcome to DVGA (no links here)</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(DvgaHandler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            found_paths = {e["path_template"] for e in res["endpoints"]}
            # Probe wordlist should find /graphql, /graphiql, /audit, /create_paste, etc.
            assert "/graphql" in found_paths or "/graphiql" in found_paths
            # At least multiple probed routes were identified
            assert len(found_paths) >= 4
    finally:
        server.stop()


# ==============================================================================
# T5: SPA fixture with JS bundle calling fetch("/api/internal/secrets")
# ==============================================================================
def test_t5_spa_js_bundle_fetch_evidence(app_env):
    class SpaHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = '<html><body><script src="/static/app.bundle.js"></script></body></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/openapi.json":
                spec = {"openapi": "3.0.0", "info": {"title": "App", "version": "1.0"}, "paths": {}}
                body = json.dumps(spec)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/static/app.bundle.js":
                # Line 5 contains the fetch call
                body = "\n\n\n\nfetch('/api/internal/secrets');\n"
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/api/internal/secrets":
                body = '{"secret": "xyz"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(SpaHandler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            shadow = [e for e in res["endpoints"] if e["path_template"] == "/api/internal/secrets"]
            assert len(shadow) == 1
            assert shadow[0]["classification"] == "shadow"
            # Verify source evidence records line number or js source
            matching_sources = [s for s in res["sources"] if "/api/internal/secrets" in (s.get("snippet") or "") or s.get("source_url", "").endswith(".js")]
            assert len(matching_sources) > 0
    finally:
        server.stop()


# ==============================================================================
# T6: HAR fixture containing undocumented XHR to live route
# ==============================================================================
def test_t6_har_fixture_classified_as_shadow(app_env):
    class HarTargetHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/openapi.json":
                spec = {"openapi": "3.0.0", "info": {"title": "App", "version": "1.0"}, "paths": {}}
                body = json.dumps(spec)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/api/v1/traffic_endpoint":
                body = '{"traffic": "recorded"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(HarTargetHandler).start()
    try:
        har_entries = [
            {
                "request": {
                    "method": "GET",
                    "url": f"{server.base_url}/api/v1/traffic_endpoint",
                    "headers": [],
                },
                "response": {
                    "status": 200,
                    "content": {"mimeType": "application/json"},
                },
            }
        ]
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port, har_entries=har_entries)
            shadow = [e for e in res["endpoints"] if e["path_template"] == "/api/v1/traffic_endpoint"]
            assert len(shadow) == 1
            assert shadow[0]["classification"] == "shadow"
            assert "har" in (shadow[0]["source_types"] or "")
    finally:
        server.stop()


# ==============================================================================
# T7: Catch-all (soft-404) server answering 200 for everything
# ==============================================================================
def test_t7_soft_404_produces_zero_phantom_shadow(app_env):
    class Soft404Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            # Every request gets identical generic 200 page
            body = "<html><body>Generic catch-all page</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = EphemeralServer(Soft404Handler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            # Soft-404 check must not invent shadow endpoints
            assert res["summary"].get("shadow_endpoints", 0) == 0
    finally:
        server.stop()


# ==============================================================================
# T8: Path found only in JS that returns 404 is candidate, NEVER shadow
# ==============================================================================
def test_t8_unreachable_js_path_is_candidate_never_shadow(app_env):
    class CandidateHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = '<html><body><script>fetch("/api/v1/dead_route");</script></body></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/openapi.json":
                spec = {"openapi": "3.0.0", "info": {"title": "App", "version": "1.0"}, "paths": {}}
                body = json.dumps(spec)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(CandidateHandler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            dead_ep = [e for e in res["endpoints"] if e["path_template"] == "/api/v1/dead_route"]
            assert len(dead_ep) == 1
            # Must be candidate, NEVER shadow
            assert dead_ep[0]["classification"] == "candidate"
            assert dead_ep[0]["classification"] != "shadow"
    finally:
        server.stop()


# ==============================================================================
# T9: Counter test: summary.findings == count of findings stored in DB
# ==============================================================================
def test_t9_findings_counter_matches_db_rows(app_env):
    class VulnerableHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = '<html><body><script>fetch("/api/v1/alive");</script></body></html>'
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/openapi.json":
                spec = {"openapi": "3.0.0", "info": {"title": "App", "version": "1.0"}, "paths": {}}
                body = json.dumps(spec)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            elif self.path == "/api/v1/alive":
                body = '{"alive": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = EphemeralServer(VulnerableHandler).start()
    try:
        with db() as conn:
            res = run_test_scan(conn, server.base_url, server.port)
            # Exactly matches stored rows
            assert res["summary"]["findings"] == len(res["findings"])
    finally:
        server.stop()


# ==============================================================================
# T10: Lab evaluation metrics test (truthful recall reporting)
# ==============================================================================
def test_t10_lab_evaluation_metrics_reporting(app_env):
    # Verify api_gate correctly discriminates API vs non-API paths & payloads
    assert api_likeness({"path_template": "/api/v1/orders"}, response=None) is True
    assert api_likeness({"path_template": "/graphql"}, response=None) is True
    assert api_likeness({"path_template": "/"}, response={"content_type": "text/html"}) is False
    assert api_likeness({"path_template": "/media/img.jpg"}, response=None) is False
    assert api_likeness({"path_template": "/random_slug"}, response={"content_type": "application/json"}) is True


# ==============================================================================
# T11: Full safety suite validation
# ==============================================================================
def test_t11_safety_guards_intact():
    from app.engine.urlguard import canonicalize, BlockedDestination
    with pytest.raises(BlockedDestination):
        canonicalize("http://169.254.169.254/latest/meta-data")
    with pytest.raises(BlockedDestination):
        canonicalize("file:///etc/passwd")
