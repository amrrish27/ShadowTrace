"""HTML discovery source.

Extracts links, scripts, frames, meta references, ``data-*`` URL attributes and
forms.  Forms are *recorded*, never submitted.  HTML comments are ignored so that
decoy strings in comments are not treated as endpoints.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Dict, List
from urllib.parse import urljoin, urlsplit

from ..types import DiscoveredEndpoint, ExtractionResult
from ...security.redaction import make_snippet
from ..api_gate import is_image_cdn_url, is_static_asset

URL_ATTRS = {"href", "src", "action", "data-url", "data-href", "data-api", "data-endpoint", "data-src", "poster"}
MAX_HTML_BYTES = 3 * 1024 * 1024
MAX_INLINE_SCRIPT = 400 * 1024
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
API_MARKERS = ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/internal/", "/graphql", "/swagger", "/openapi", "/admin/")


def _api_like(path: str) -> bool:
    lowered = (path or "/").lower()
    return any(marker in lowered for marker in API_MARKERS)


def _is_candidate(value: str) -> bool:
    if not value or len(value) > 2048:
        return False
    lowered = value.strip().lower()
    if lowered.startswith(("javascript:", "data:", "mailto:", "tel:", "blob:", "#")):
        return False
    return True


class _Collector(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.result = ExtractionResult()
        self.forms: List[Dict[str, str]] = []
        self._in_script = False
        self._script_buf: List[str] = []
        self._script_index = 0
        self._style_depth = 0

    # comments are deliberately ignored: decoy endpoint strings live there.
    def handle_comment(self, data: str) -> None:  # noqa: D401
        return

    def handle_starttag(self, tag: str, attrs: List[tuple]) -> None:  # type: ignore[override]
        attr: Dict[str, str] = {}
        for key, value in attrs:
            if value is None:
                continue
            attr[key.lower()] = value
        tag = tag.lower()
        if tag == "base" and attr.get("href"):
            candidate = urljoin(self.base_url, attr["href"])
            if _is_candidate(candidate):
                self.base_url = candidate
        if tag == "form":
            action = attr.get("action", "")
            method = (attr.get("method") or "GET").upper()
            if method not in METHODS:
                method = "GET"
            self.forms.append({"action": action, "method": method})
            if action and _is_candidate(action):
                self._record(method, urljoin(self.base_url, action), "form", attr)
        if tag == "script":
            self._in_script = True
            self._script_buf = []
            src = attr.get("src", "")
            if src and _is_candidate(src):
                absolute = urljoin(self.base_url, src)
                self.result.scripts.append(absolute)
        if tag in {"a", "area"} and attr.get("href"):
            if _is_candidate(attr["href"]):
                absolute = urljoin(self.base_url, attr["href"])
                self.result.links.append(absolute)
                path = urlsplit(absolute).path
                is_doc_page = any(token in self.base_url.lower() for token in ("/docs", "/api-docs", "/documentation", "/swagger", "/redoc"))
                if is_doc_page or _api_like(path):
                    if not is_static_asset(path) and not is_image_cdn_url(path, urlsplit(absolute).query):
                        self._record("GET", absolute, tag, attr)
        if tag in {"link", "iframe", "frame"} and attr.get("src"):
            if _is_candidate(attr["src"]):
                absolute = urljoin(self.base_url, attr["src"])
                self.result.links.append(absolute)
                if _api_like(urlsplit(absolute).path):
                    self._record("GET", absolute, tag, attr)
        if tag == "link" and attr.get("href"):
            rel = (attr.get("rel") or "").lower()
            if _is_candidate(attr["href"]):
                self.result.links.append(attr["href"])
                target = urljoin(self.base_url, attr["href"])
                if _api_like(urlsplit(target).path) and rel in {"openapi", "service-doc", "api"}:
                    self._record("GET", target, f"link:{rel}"[:40], attr)
        if tag == "meta":
            content = attr.get("content", "")
            target = ""
            if "url=" in content.lower():
                target = re.split(r"url\s*=\s*", content, flags=re.I)[-1].strip("'\" ")
            elif _is_candidate(content) and _api_like(content):
                target = content
            if target and _is_candidate(target):
                self._record("GET", urljoin(self.base_url, target), "meta", attr)
        for key in ("data-api", "data-endpoint"):
            val = attr.get(key)
            if val and _is_candidate(val) and _api_like(val):
                self._record("GET", urljoin(self.base_url, val), f"attr:{key}"[:40], attr)

    def handle_endtag(self, tag: str) -> None:  # type: ignore[override]
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            code = "".join(self._script_buf)
            self._script_buf = []
            if code.strip():
                self._script_index += 1
                location = f"inline-script[{self._script_index}]"
                if len(code) <= MAX_INLINE_SCRIPT:
                    self.result.inline_scripts.append((location, code))
                else:
                    self.result.inline_scripts.append((location, code[:MAX_INLINE_SCRIPT]))

    def handle_data(self, data: str) -> None:  # type: ignore[override]
        if self._in_script:
            self._script_buf.append(data)

    def _record(self, method: str, url: str, extractor: str, attr: Dict[str, str]) -> None:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            return
        path = parts.path or "/"
        if is_static_asset(path) or is_image_cdn_url(path, parts.query):
            return
        base_host = urlsplit(self.base_url).netloc.split(":")[0].lower()
        url_host = parts.netloc.split(":")[0].lower()
        if url_host and base_host and url_host != base_host:
            if url not in self.result.external_references:
                self.result.external_references.append(url)
            return
        snippet_source = attr.get("href") or attr.get("src") or attr.get("action") or url
        self.result.endpoints.append(
            DiscoveredEndpoint(
                method=method,
                path=path,
                query=parts.query,
                source_type="html",
                source_url=self.base_url,
                location=f"{self.base_url}#{extractor}"[:500],
                snippet=make_snippet(snippet_source),
                extractor=extractor,
                confidence=0.6,
                base_url=f"{parts.scheme}://{parts.netloc}",
            )
        )


def extract_html(html: str, page_url: str) -> ExtractionResult:
    if len(html) > MAX_HTML_BYTES:
        html = html[:MAX_HTML_BYTES]
    collector = _Collector(page_url)
    try:
        collector.feed(html)
        collector.close()
    # Rationale: HTMLParser is tolerant; keep whatever was collected
    except Exception:  # nosec B110
        pass
    collector.result.notes.append(f"forms:{len(collector.forms)}")
    for form in collector.forms:
        collector.result.specifications.append({"kind": "form", **form})
    return collector.result


def extract_method_path_pairs(text: str, page_url: str) -> List[DiscoveredEndpoint]:
    """Conservative METHOD /path extraction for prose documentation pages."""
    endpoints: List[DiscoveredEndpoint] = []
    pattern = re.compile(
        r"(?im)^[\s>*`|\-]*(?:<[^>]+>\s*)*\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b[\s`|]*"
        r"(/(?:[A-Za-z0-9._~%\-]+|\{[A-Za-z0-9_]+\}|:[A-Za-z0-9_]+)(?:/(?:[A-Za-z0-9._~%\-]+|\{[A-Za-z0-9_]+\}|:[A-Za-z0-9_]+))*)"
    )
    for match in pattern.finditer(text[:2_000_000]):
        method = match.group(1).upper()
        path = match.group(2)
        if len(path) < 2 or len(path) > 300:
            continue
        line_start = text.rfind("\n", 0, match.start()) + 1
        line_no = text.count("\n", 0, match.start()) + 1
        snippet = text[line_start : line_start + 160]
        endpoints.append(
            DiscoveredEndpoint(
                method=method,
                path=path.split("?")[0],
                query="",
                source_type="docs",
                source_url=page_url,
                location=f"line {line_no}",
                snippet=make_snippet(snippet),
                extractor="docs_method_path",
                confidence=0.35,
            )
        )
    return endpoints
