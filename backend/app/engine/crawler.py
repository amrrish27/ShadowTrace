"""Bounded, polite crawler for the discovery phase.

Rules: stay inside the authorized scope, honour depth/page/script/source-map
caps, never follow out-of-scope hosts (they are recorded as references), never
execute JavaScript, and re-check cancellation before every fetch.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from ..security.redaction import make_snippet, secret_kinds
from .extractors.html_extract import extract_html, extract_method_path_pairs
from .extractors.js_extract import extract_javascript
from .extractors.robotssitemap import looks_like_sitemap, parse_robots, parse_sitemap
from .extractors.sourcemap import extraction_from_map, find_source_map_reference, source_map_header
from .extractors.specs import WELL_KNOWN_SPEC_PATHS, is_openapi, parse_specification
from .parsers import parse_yaml_or_json
from .urlguard import canonicalize
from .normalizer import looks_static
from .safe_http import ResponseData, SafeHttpClient, ScanCancelled, ScanError
from .scope import ScopePolicy
from .types import DiscoveredEndpoint, ExtractionResult
from .validator import Soft404Probe
from .api_gate import api_likeness

MAX_HTML_PAGES = 12
# Bounded sample retention for the analyser: enough to analyse the application's own
# responses, small enough to keep memory flat on a large crawl.
MAX_PAGE_SAMPLES = 80
MAX_PAGE_SAMPLE_BYTES = 65536
MAX_SCRIPTS = 20
MAX_SOURCE_MAPS = 6
MAX_SPEC_PROBES = 200
SCRIPT_EXTENSIONS = (".js", ".mjs", ".cjs")
_CSP_CONNECT_RE = re.compile(r"connect-src([^;]{0,500})", re.I)
_LINK_HEADER_RE = re.compile(r"<([^>]{1,500})>\s*;\s*rel=", re.I)


@dataclass
class CrawlOutcome:
    result: ExtractionResult = field(default_factory=ExtractionResult)
    pages_fetched: int = 0
    scripts_analyzed: int = 0
    source_maps_analyzed: int = 0
    specs_probed: int = 0
    external_references: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    source_map_urls: List[str] = field(default_factory=list)
    spec_urls: List[str] = field(default_factory=list)
    robots_url: str = ""
    secret_hits: List[Tuple[str, List[str]]] = field(default_factory=list)
    seed_headers: Dict[str, str] = field(default_factory=dict)
    seed_url: str = ""
    # Responses the application itself pointed us at (url, status, headers, body excerpt).
    # The analyser reads these in addition to the neutralised validation replay: a page the
    # target linked to is evidence the target chose to serve, and rules such as reflection
    # detection can only see what was actually returned.
    page_samples: List[Tuple[str, int, Dict[str, str], str]] = field(default_factory=list)


def _is_sampleable(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return "html" in lowered or "json" in lowered or "xml" in lowered or "text/plain" in lowered


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_script_url(url: str, content_type: str = "") -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(SCRIPT_EXTENSIONS) or "javascript" in content_type or "ecmascript" in content_type


def _error_detail(exc: "ScanError") -> str:
    """`category` alone is too coarse: add the policy reason and an actionable hint."""
    detail = getattr(exc, "detail", "")
    return f"{exc.category} ({detail})" if detail else exc.category


class Crawler:
    def __init__(
        self,
        client: SafeHttpClient,
        scope: ScopePolicy,
        base_url: str,
        *,
        max_pages: int = MAX_HTML_PAGES,
        max_scripts: int = MAX_SCRIPTS,
        max_source_maps: int = MAX_SOURCE_MAPS,
        max_spec_probes: int = MAX_SPEC_PROBES,
        event: Optional[Callable[..., None]] = None,
        progress: Optional[Callable[[], None]] = None,
    ) -> None:
        self.client = client
        self.scope = scope
        self.base_url = base_url.rstrip("/") + "/"
        self.origin = f"{urlsplit(self.base_url).scheme}://{urlsplit(self.base_url).netloc}"
        self.max_pages = max_pages
        self.max_scripts = max_scripts
        self.max_source_maps = max_source_maps
        self.max_spec_probes = max_spec_probes
        self.event = event or (lambda *args, **kwargs: None)
        self.progress = progress or (lambda: None)
        self.outcome = CrawlOutcome()
        self.visited: Set[str] = set()
        self.queued: Set[str] = set()
        self.script_urls: List[str] = []

    # -- helpers ---------------------------------------------------------
    def _note_external(self, url: str) -> None:
        host = _host_of(url)
        if not host or not self.scope.host_in_scope(host):
            if url not in self.outcome.external_references and len(self.outcome.external_references) < 200:
                self.outcome.external_references.append(url)

    def _scan_headers(self, response: ResponseData, source_url: str) -> None:
        csp = response.headers.get("content-security-policy", "")
        if csp:
            match = _CSP_CONNECT_RE.search(csp)
            if match:
                for token in match.group(1).split():
                    candidate = token.strip().strip("'\"")
                    if candidate.startswith(("http://", "https://", "//")):
                        url = "https:" + candidate if candidate.startswith("//") else candidate
                        self._note_external(url)
                        if self.scope.host_in_scope(_host_of(url)):
                            parts = urlsplit(url)
                            self.outcome.result.endpoints.append(
                                DiscoveredEndpoint(
                                    method="GET",
                                    path=parts.path or "/",
                                    query=parts.query,
                                    source_type="crawler",
                                    source_url=source_url,
                                    location="Content-Security-Policy connect-src",
                                    snippet=make_snippet(f"connect-src {candidate}"),
                                    extractor="csp_connect_src",
                                    confidence=0.4,
                                    base_url=f"{parts.scheme}://{parts.netloc}",
                                )
                            )
        link_header = response.headers.get("link", "")
        for match in _LINK_HEADER_RE.finditer(link_header[:2000]):
            target = urljoin(source_url, match.group(1))
            self._note_external(target)
        allow = response.headers.get("allow", "")
        if allow:
            parts = urlsplit(source_url)
            for method in allow.split(","):
                method = method.strip().upper()
                if method in {"GET", "HEAD", "OPTIONS"}:
                    self.outcome.result.endpoints.append(
                        DiscoveredEndpoint(
                            method=method,
                            path=parts.path or "/",
                            query=parts.query,
                            source_type="crawler",
                            source_url=source_url,
                            location="Allow header",
                            snippet=make_snippet(f"Allow: {allow}"),
                            extractor="allow_header",
                            confidence=0.5,
                            base_url=f"{parts.scheme}://{parts.netloc}",
                        )
                    )

    def _process_script(self, code: str, script_url: str, location_prefix: str = "") -> None:
        if self.outcome.scripts_analyzed >= self.max_scripts:
            return
        self.outcome.scripts_analyzed += 1
        base = f"{urlsplit(script_url).scheme}://{urlsplit(script_url).netloc}"
        kinds = secret_kinds(code[:1_000_000])
        if kinds:
            self.outcome.secret_hits.append((script_url, sorted(set(kinds))[:5]))
        extracted = extract_javascript(code, script_url, base, location_prefix=location_prefix)
        self.outcome.result.endpoints.extend(extracted.endpoints)
        self.outcome.result.notes.extend(extracted.notes)
        for child in extracted.scripts:
            if child not in self.script_urls and len(self.script_urls) < self.max_scripts * 2:
                if self.scope.host_in_scope(_host_of(child)):
                    self.script_urls.append(child)
                else:
                    self._note_external(child)

    def _source_map_from_response(self, response: ResponseData, source_url: str) -> None:
        if self.outcome.source_maps_analyzed >= self.max_source_maps:
            return
        reference = source_map_header(response.headers) or find_source_map_reference(
            response.text[-8192:], response.content_type
        )
        if not reference or reference.startswith("data:"):
            return
        map_url = urljoin(source_url, reference)
        if not self.scope.host_in_scope(_host_of(map_url)):
            self._note_external(map_url)
            return
        try:
            map_response = self.client.request("GET", map_url)
        except ScanError:
            return
        if map_response.status != 200 or not map_response.text.strip().startswith("{"):
            return
        self.outcome.source_maps_analyzed += 1
        self.outcome.source_map_urls.append(map_url)
        base = f"{urlsplit(map_url).scheme}://{urlsplit(map_url).netloc}"
        extracted = extraction_from_map(map_response.text, map_url, base)
        self.outcome.result.endpoints.extend(extracted.endpoints)
        self.outcome.result.notes.extend(extracted.notes)

    # -- phases ----------------------------------------------------------
    def probe_well_known(self) -> None:
        soft_404: Optional[Soft404Probe] = None
        consecutive_connection_failures = 0
        for path in WELL_KNOWN_SPEC_PATHS[: self.max_spec_probes]:
            if self.outcome.specs_probed >= self.max_spec_probes:
                break
            if consecutive_connection_failures >= 3 and self.outcome.pages_fetched == 0:
                break
            url = urljoin(self.origin + "/", path.lstrip("/"))
            try:
                if not self.scope.check(canonicalize(url))[0]:
                    continue
            # Rationale: an unparseable spec path is skipped, never fatal
            except Exception:  # nosec B112
                continue
            self.outcome.specs_probed += 1
            try:
                response = self.client.request("GET", url)
                consecutive_connection_failures = 0
            except ScanCancelled:
                raise
            except ScanError:
                consecutive_connection_failures += 1
                self.progress()
                continue
            self.progress()
            if response.status != 200:
                continue

            # Check soft-404: if the target answers 200 with a catch-all body, ignore probe hits
            if soft_404 is None:
                soft_404 = Soft404Probe(self.client, self.base_url)
                try:
                    soft_404.detect()
                except Exception:
                    pass
            if soft_404 and soft_404.detected and soft_404.matches(response):
                continue

            content_type = response.content_type
            body = response.text[:2_000_000]
            if path == "/robots.txt" and "text/" in content_type:
                self.outcome.robots_url = url
                extracted = parse_robots(body, url, self.origin)
                self.outcome.result.extend(extracted)
                for note in extracted.notes:
                    if note.startswith("sitemap_url:"):
                        sitemap_url = note.split(":", 1)[1]
                        self._fetch_sitemap(sitemap_url)
                continue
            elif path == "/sitemap.xml" and looks_like_sitemap(content_type, body):
                extracted, children = parse_sitemap(body, url, self.origin)
                self.outcome.result.extend(extracted)
                for child in children[:3]:
                    self._fetch_sitemap(child)
                continue

            # API-likeness gate: a probe hit counts only if the response passes the API-likeness gate
            if not api_likeness(path, response):
                continue

            # GraphQL introspection check
            if path in ("/graphql", "/api/graphql"):
                try:
                    intro_url = urljoin(self.origin + "/", path.lstrip("/") + "?query={__schema{queryType{name}}}")
                    intro_res = self.client.request("GET", intro_url)
                    if intro_res.status == 200 and "__schema" in intro_res.text:
                        self.outcome.spec_urls.append(url)
                        self.outcome.result.endpoints.append(
                            DiscoveredEndpoint(
                                method="GET",
                                path=path,
                                source_type="graphql",
                                source_url=intro_url,
                                location="graphql introspection",
                                snippet="GET ?query={__schema{queryType{name}}}",
                                extractor="graphql_schema",
                                confidence=1.0,
                                base_url=self.origin,
                            )
                        )
                except Exception:
                    pass

            if "json" in content_type or "yaml" in content_type or path.endswith((".json", ".yaml")):
                extracted = parse_specification(body, url, self.origin)
                if extracted.endpoints:
                    self.outcome.spec_urls.append(url)
                    self.outcome.result.extend(extracted)
                    self.outcome.result.endpoints.append(
                        DiscoveredEndpoint(
                            method="GET",
                            path=path,
                            source_type="openapi",
                            source_url=url,
                            location="well-known probe",
                            snippet=make_snippet(f"GET {path} -> {content_type}"),
                            extractor="well_known_probe",
                            confidence=0.9,
                            base_url=self.origin,
                        )
                    )
                else:
                    # Empty spec still found on target — track it so scanner can use it as a baseline
                    is_openapi_spec = False
                    try:
                        parsed = parse_yaml_or_json(body)
                        is_openapi_spec = is_openapi(parsed)
                    except Exception:
                        pass
                    self.outcome.result.endpoints.append(
                        DiscoveredEndpoint(
                            method="GET",
                            path=path,
                            source_type="openapi" if is_openapi_spec else "crawler",
                            source_url=url,
                            location="well-known probe",
                            snippet=make_snippet(f"GET {path} -> {content_type}"),
                            extractor="well_known_probe",
                            confidence=0.9 if is_openapi_spec else 0.8,
                            base_url=self.origin,
                        )
                    )
                    if is_openapi_spec:
                        self.outcome.spec_urls.append(url)
            elif "html" in content_type:
                extracted = extract_html(body, url)
                lower = body[:100_000].lower()
                if "swagger" in lower or "redoc" in lower or "openapi" in lower:
                    self.outcome.spec_urls.append(url)
                    self.outcome.result.endpoints.extend(extracted.endpoints)
                    self.outcome.result.endpoints.append(
                        DiscoveredEndpoint(
                            method="GET",
                            path=path,
                            source_type="swagger_ui" if "swagger" in lower else "redoc",
                            source_url=url,
                            location="well-known probe",
                            snippet=make_snippet(f"GET {path} -> documentation UI"),
                            extractor="well_known_probe",
                            confidence=0.9,
                            base_url=self.origin,
                        )
                    )
                else:
                    self.outcome.result.endpoints.extend(extracted.endpoints)
                    self.outcome.result.endpoints.append(
                        DiscoveredEndpoint(
                            method="GET",
                            path=path,
                            source_type="crawler",
                            source_url=url,
                            location="well-known probe",
                            snippet=make_snippet(f"GET {path} -> HTML"),
                            extractor="well_known_probe",
                            confidence=0.8,
                            base_url=self.origin,
                        )
                    )
            else:
                self.outcome.result.endpoints.append(
                    DiscoveredEndpoint(
                        method="GET",
                        path=path,
                        source_type="crawler",
                        source_url=url,
                        location="well-known probe",
                        snippet=make_snippet(f"GET {path} -> {content_type}"),
                        extractor="well_known_probe",
                        confidence=0.8,
                        base_url=self.origin,
                    )
                )

    def _fetch_sitemap(self, url: str) -> None:
        if not self.scope.host_in_scope(_host_of(url)):
            self._note_external(url)
            return
        try:
            response = self.client.request("GET", url)
        except ScanError:
            return
        if response.status != 200:
            return
        extracted, children = parse_sitemap(response.text, url, self.origin)
        for note in extracted.notes[:5]:
            self.outcome.result.notes.append(f"{url}: {note}")
        self.outcome.result.extend(extracted)
        for child in children[:3]:
            if child != url:
                self._fetch_sitemap(child)

    def crawl(self, *, seeds: Optional[List[str]] = None) -> CrawlOutcome:
        queue: List[Tuple[str, int]] = [(seed, 0) for seed in (seeds or [self.base_url])]
        self.queued.update(seed for seed, _ in queue)
        while queue and self.outcome.pages_fetched < self.max_pages:
            url, depth = queue.pop(0)
            if url in self.visited:
                continue
            if not self.scope.host_in_scope(_host_of(url)):
                # Defence in depth: the HTTP client also refuses this, but an
                # out-of-scope seed must never even be attempted.
                self._note_external(url)
                continue
            self.visited.add(url)
            try:
                response = self.client.request("GET", url)
            except ScanCancelled:
                raise
            except ScanError as exc:
                self.outcome.errors.append(f"{url}: {_error_detail(exc)}")
                self.progress()
                continue
            self.outcome.pages_fetched += 1
            self.progress()
            if (
                len(self.outcome.page_samples) < MAX_PAGE_SAMPLES
                and _is_sampleable(response.content_type)
            ):
                self.outcome.page_samples.append(
                    (url, response.status, dict(response.headers), response.text[:MAX_PAGE_SAMPLE_BYTES])
                )
            if not self.outcome.seed_headers:
                self.outcome.seed_headers = dict(response.headers)
                self.outcome.seed_url = url
            self._scan_headers(response, url)
            content_type = response.content_type
            body = response.text
            if "html" in content_type or (not content_type and "<html" in body[:2000].lower()):
                extracted = extract_html(body, url)
                self.outcome.result.endpoints.extend(extracted.endpoints)
                for ext in getattr(extracted, "external_references", []):
                    self._note_external(ext)
                for endpoint in extract_method_path_pairs(body[:2_000_000], url)[:200]:
                    self.outcome.result.endpoints.append(endpoint)
                for location, code in extracted.inline_scripts:
                    self._process_script(code, url, location_prefix=location)
                for script in extracted.scripts:
                    if script not in self.script_urls and len(self.script_urls) < self.max_scripts:
                        if self.scope.host_in_scope(_host_of(script)):
                            self.script_urls.append(script)
                        else:
                            self._note_external(script)
                if depth < 2:
                    for link in extracted.links:
                        if not self.scope.host_in_scope(_host_of(link)):
                            self._note_external(link)
                            continue
                        clean = link.split("#", 1)[0]
                        path = urlsplit(clean).path
                        if looks_static(path) or clean in self.queued:
                            continue
                        if not self.scope.path_in_scope(path):
                            continue
                        if len(self.queued) < 200:
                            self.queued.add(clean)
                            queue.append((clean, depth + 1))
                self._source_map_from_response(response, url)
            elif _is_script_url(url, content_type):
                self._process_script(body, url)
                self._source_map_from_response(response, url)
            elif "json" in content_type or "yaml" in content_type:
                extracted = parse_specification(body, url, self.origin)
                for note in extracted.notes[:5]:
                    self.outcome.result.notes.append(f"{url}: {note}")
                if extracted.endpoints:
                    self.outcome.result.extend(extracted)
                    self.outcome.spec_urls.append(url)
                else:
                    try:
                        parsed = parse_yaml_or_json(body)
                        if is_openapi(parsed):
                            self.outcome.spec_urls.append(url)
                    except Exception:
                        pass
            elif "xml" in content_type:
                extracted, _children = parse_sitemap(body, url, self.origin)
                for note in extracted.notes[:5]:
                    self.outcome.result.notes.append(f"{url}: {note}")
                self.outcome.result.extend(extracted)

        index = 0
        while index < len(self.script_urls):
            if self.outcome.scripts_analyzed >= self.max_scripts:
                break
            script_url = self.script_urls[index]
            index += 1
            try:
                response = self.client.request("GET", script_url)
            except ScanCancelled:
                raise
            except ScanError as exc:
                self.outcome.errors.append(f"{script_url}: {_error_detail(exc)}")
                continue
            if response.status != 200:
                continue
            self._process_script(response.text, script_url)
            self._source_map_from_response(response, script_url)

        if self.max_spec_probes > 0:
            # If no pages could be fetched and all seed requests resulted in network/transport errors,
            # the target is unreachable. Do not waste minutes probing spec paths on an unreachable host.
            if self.outcome.pages_fetched > 0 or not self.outcome.errors:
                self.probe_well_known()

        self.outcome.external_references = self.outcome.external_references[:200]
        return self.outcome
