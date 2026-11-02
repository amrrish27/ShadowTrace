"""Crawler behaviour: scope, caps, header hints and hostile-content handling.

The crawler is driven with a stub client, so these tests are offline and
deterministic while still exercising the real parsing pipeline.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

import pytest

from app.engine.crawler import Crawler
from app.engine.safe_http import ResponseData, ScanCancelled, TargetRequestError
from app.engine.scope import ScopePolicy

BASE = "https://app.example.test"
ORIGIN = BASE


def html(body: str, headers: Dict[str, str] | None = None, status: int = 200, url: str = BASE + "/") -> ResponseData:
    merged = {"content-type": "text/html; charset=utf-8"}
    merged.update(headers or {})
    return ResponseData(url=url, status=status, headers=merged, body=body.encode(), elapsed_ms=2)


def js(body: str, url: str = BASE + "/static/app.js", headers: Dict[str, str] | None = None) -> ResponseData:
    merged = {"content-type": "application/javascript"}
    merged.update(headers or {})
    return ResponseData(url=url, status=200, headers=merged, body=body.encode(), elapsed_ms=2)


class StubClient:
    def __init__(self, routes: Dict[str, ResponseData | Exception]):
        self.routes = routes
        self.calls: List[str] = []

    def request(self, method: str, url: str) -> ResponseData:
        self.calls.append(url)
        # Exact match first, then the longest matching prefix (a "/" route must not
        # swallow every URL).
        if url in self.routes:
            response = self.routes[url]
            if isinstance(response, Exception):
                raise response
            return response
        for prefix in sorted(self.routes, key=len, reverse=True):
            if url.startswith(prefix):
                response = self.routes[prefix]
                if isinstance(response, Exception):
                    raise response
                return response
        return ResponseData(
            url=url, status=404, headers={"content-type": "text/plain"}, body=b"not found", elapsed_ms=1
        )


def _crawler(routes: Dict[str, ResponseData | Exception], **kwargs) -> Tuple[Crawler, StubClient]:
    client = StubClient(routes)
    scope = ScopePolicy.build(host="app.example.test", ports=[443])
    crawler = Crawler(client, scope, BASE, **kwargs)  # type: ignore[arg-type]
    return crawler, client


def test_crawler_follows_links_and_extracts_endpoints():
    index = html(
        """
        <html><body>
          <a href="/docs">docs</a>
          <a href="/static/app.js">asset</a>
          <a href="https://elsewhere.test/api/v1/x">external</a>
          <a href="/static/app.js#frag">dupe</a>
          <script src="/static/app.js"></script>
        </body></html>
        """
    )
    docs = html("<html><body><a href='/api/v1/users'>users</a></body></html>", url=BASE + "/docs")
    crawler, client = _crawler(
        {BASE + "/static/app.js": js("fetch('/api/v1/session');"), BASE + "/docs": docs, BASE + "/": index}
    )
    crawler.max_spec_probes = 0
    outcome = crawler.crawl()
    assert outcome.pages_fetched >= 2
    assert any(call.endswith("/static/app.js") for call in client.calls)
    assert any(endpoint.path == "/api/v1/session" for endpoint in outcome.result.endpoints)
    assert any(str(url).startswith("https://elsewhere.test") for url in outcome.external_references)
    # The out-of-scope host is never requested.
    assert all("elsewhere.test" not in call for call in client.calls)


def test_crawler_respects_the_page_cap():
    index = html("<html><body>" + "".join(f"<a href='/p{i}'>p</a>" for i in range(20)) + "</body></html>")
    routes = {BASE + "/": index}
    routes.update({f"{BASE}/p{i}": html("<html><body>page</body></html>", url=f"{BASE}/p{i}") for i in range(20)})
    crawler, client = _crawler(routes, max_pages=4)
    crawler.max_spec_probes = 0
    outcome = crawler.crawl()
    assert outcome.pages_fetched == 4
    assert len(client.calls) <= 4


def test_crawler_stops_on_cancel():
    class Cancelling(StubClient):
        def request(self, method, url):
            raise ScanCancelled()

    scope = ScopePolicy.build(host="app.example.test", ports=[443])
    crawler = Crawler(Cancelling({}), scope, BASE)  # type: ignore[arg-type]
    crawler.max_spec_probes = 0
    with pytest.raises(ScanCancelled):
        crawler.crawl()


def test_crawler_records_fetch_errors_without_aborting():
    index = html("<html><body><a href='/broken'>broken</a><a href='/ok'>ok</a></body></html>")
    crawler, _client = _crawler(
        {
            BASE + "/": index,
            BASE + "/broken": TargetRequestError(),
            BASE + "/ok": html("<html><body>fine</body></html>", url=BASE + "/ok"),
        }
    )
    crawler.max_spec_probes = 0
    outcome = crawler.crawl()
    assert any("/broken" in error for error in outcome.errors)
    assert outcome.pages_fetched >= 2  # /ok still visited after the error


def test_header_hints_are_used_for_discovery():
    headers = {
        "content-security-policy": "default-src 'self'; connect-src 'self' https://app.example.test/api/v1/csp https://cdn.other.test",
        "link": '</api/v1/linked>; rel="preload"',
        "allow": "GET, POST, OPTIONS",
    }
    index = html("<html><body>hi</body></html>", headers=headers)
    crawler, _client = _crawler({BASE + "/": index})
    crawler.max_spec_probes = 0
    outcome = crawler.crawl()
    paths = {(endpoint.method, endpoint.path) for endpoint in outcome.result.endpoints}
    assert ("GET", "/api/v1/csp") in paths
    assert ("OPTIONS", "/") in paths
    # The external CDN origin is recorded, never fetched.
    assert any("cdn.other.test" in url for url in outcome.external_references)


def test_inline_scripts_are_parsed_but_never_executed():
    index = html(
        """
        <html><body>
        <script>
          const API = '/api/v1';
          fetch(`${API}/reports/summary`);
          //# sourceMappingURL=inline.js.map
        </script>
        </body></html>
        """
    )
    crawler, client = _crawler({BASE + "/": index})
    crawler.max_spec_probes = 0
    outcome = crawler.crawl()
    assert any(endpoint.path == "/api/v1/reports/summary" for endpoint in outcome.result.endpoints)
    assert outcome.scripts_analyzed >= 1
    # No request was made to any JavaScript interpreter surface: only page fetches happened.
    assert all(call.startswith(BASE) for call in client.calls)


def test_script_and_source_map_limits():
    index = html("<html><body>" + "".join(f"<script src='/s{i}.js'></script>" for i in range(10)) + "</body></html>")
    routes = {BASE + "/": index}
    for index in range(10):
        routes[f"{BASE}/s{index}.js"] = js("fetch('/api/v1/thing');", url=f"{BASE}/s{index}.js")
    crawler, _client = _crawler(routes, max_scripts=3)
    crawler.max_spec_probes = 0
    outcome = crawler.crawl()
    assert outcome.scripts_analyzed <= 3


def test_json_specification_document_is_parsed():
    spec = (
        '{"openapi": "3.0.3", "paths": {"/api/v1/users": {"get": {}}, '
        '"/api/v1/orders": {"post": {}}}}'
    )
    response = ResponseData(
        url=BASE + "/openapi.json",
        status=200,
        headers={"content-type": "application/json"},
        body=spec.encode(),
        elapsed_ms=1,
    )
    crawler, _client = _crawler({BASE + "/": html("<html><body></body></html>"), BASE + "/openapi.json": response})
    crawler.max_spec_probes = 0
    crawler.crawl(seeds=[BASE + "/openapi.json"])
    paths = {(endpoint.method, endpoint.path) for endpoint in crawler.outcome.result.endpoints}
    assert ("GET", "/api/v1/users") in paths
    assert ("POST", "/api/v1/orders") in paths


def test_static_assets_are_not_queued_as_pages():
    index = html(
        "<html><body><a href='/static/site.css'>css</a><a href='/logo.png'>png</a><a href='/api/v1/real'>real</a></body></html>"
    )
    routes = {
        BASE + "/": index,
        BASE + "/api/v1/real": html("<html><body>ok</body></html>", url=BASE + "/api/v1/real"),
    }
    crawler, client = _crawler(routes)
    crawler.max_spec_probes = 0
    crawler.crawl()
    assert all(".css" not in call and ".png" not in call for call in client.calls)


def test_out_of_scope_seed_is_not_fetched():
    crawler, client = _crawler({BASE + "/": html("<html></html>")})
    crawler.max_spec_probes = 0
    scope = ScopePolicy.build(host="app.example.test", ports=[443])
    assert not scope.host_in_scope("other.test")
    crawler.crawl(seeds=["https://other.test/"])
    # Out-of-scope seeds are never requested (the crawler checks before fetching).
    assert client.calls == []


def test_source_map_reference_is_followed():
    index = html(
        "<html><body><script src='/static/app.js'></script></body></html>"
    )
    script = js("var x=1; //# sourceMappingURL=app.js.map", url=BASE + "/static/app.js")
    mapping = (
        '{"version": 3, "file": "app.js", "sources": ["src/router.js"], '
        '"sourcesContent": ["fetch(\\"/api/v1/from-map\\");"]}'
    )
    map_response = ResponseData(
        url=BASE + "/static/app.js.map",
        status=200,
        headers={"content-type": "application/json"},
        body=mapping.encode(),
        elapsed_ms=1,
    )
    crawler, client = _crawler(
        {BASE + "/": index, BASE + "/static/app.js": script, BASE + "/static/app.js.map": map_response}
    )
    crawler.max_spec_probes = 0
    outcome = crawler.crawl()
    paths = {endpoint.path for endpoint in outcome.result.endpoints}
    assert "/api/v1/from-map" in paths
    assert any(call.endswith(".map") for call in client.calls)
    assert outcome.source_maps_analyzed >= 1
