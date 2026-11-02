"""robots.txt and sitemap discovery sources.

These are *discovery hints only* and are never treated as an authorization
mechanism.  XML goes through the hardened parser (no DTD, no entities, bounded
depth and size).
"""
from __future__ import annotations

from typing import Any, List, Tuple
from urllib.parse import urlsplit

from ...security.redaction import make_snippet
from ..parsers import UnsafeDocument, safe_xml_fromstring
from ..types import DiscoveredEndpoint, ExtractionResult

MAX_SITEMAP_URLS = 500
API_MARKERS = ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/internal/", "/graphql", "/admin/")


def _api_like(path: str) -> bool:
    lowered = (path or "/").lower()
    return any(marker in lowered for marker in API_MARKERS)
MAX_SITEMAP_INDEX_FILES = 20


def parse_robots(text: str, robots_url: str, base_url: str) -> ExtractionResult:
    result = ExtractionResult()
    sitemaps: List[str] = []
    disallowed: List[str] = []
    for line in text.splitlines()[:5000]:
        stripped = line.split("#", 1)[0].strip()
        if not stripped or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key_lower = key.strip().lower()
        value = value.strip()
        if key_lower == "sitemap" and value.startswith(("http://", "https://", "/")):
            sitemaps.append(value)
        elif key_lower == "disallow" and value.startswith("/") and len(value) < 300 and "*" not in value:
            # Directory prefixes ("/api/internal/") are namespaces, not endpoints.
            if not value.endswith("/") and value.count("/") >= 2:
                disallowed.append(value)
    for path in disallowed[:200]:
        result.endpoints.append(
            DiscoveredEndpoint(
                method="GET",
                path=path.split("?")[0],
                query=path.split("?", 1)[1] if "?" in path else "",
                source_type="robots",
                source_url=robots_url,
                location="robots.txt Disallow",
                snippet=make_snippet(f"Disallow: {path}"),
                extractor="robots_disallow",
                confidence=0.35,
                base_url=base_url,
            )
        )
    result.notes.extend(f"sitemap:{url}" for url in sitemaps[:10])
    result.specifications.append({"kind": "robots", "sitemaps": sitemaps[:10]})
    for sitemap in sitemaps[:MAX_SITEMAP_INDEX_FILES]:
        result.notes.append(f"sitemap_url:{sitemap}")
    return result


def _local_name(tag: Any) -> str:
    text = str(tag)
    return text.rsplit("}", 1)[-1].lower()


def _loc_text(node: Any) -> str:
    for child in list(node):
        if _local_name(getattr(child, "tag", "")) == "loc" and getattr(child, "text", None):
            return str(child.text).strip()
    return ""


def _collect_locs(root: Any, url: str, base_url: str, result: ExtractionResult, depth: int = 0) -> List[str]:
    sitemaps: List[str] = []
    if depth > 2:
        return sitemaps
    for child in list(root):
        child_tag = _local_name(getattr(child, "tag", ""))
        loc_text = _loc_text(child)[:2048]
        if child_tag == "url" and loc_text.startswith(("http://", "https://")) and _api_like(urlsplit(loc_text).path):
            parts = urlsplit(loc_text)
            result.endpoints.append(
                DiscoveredEndpoint(
                    method="GET",
                    path=parts.path or "/",
                    query=parts.query,
                    source_type="sitemap",
                    source_url=url,
                    location="sitemap <loc>",
                    snippet=make_snippet(loc_text),
                    extractor="sitemap_loc",
                    confidence=0.4,
                    base_url=base_url,
                )
            )
        elif child_tag == "sitemap" and loc_text:
            sitemaps.append(loc_text)
        if len(result.endpoints) >= MAX_SITEMAP_URLS:
            break
    return sitemaps


def parse_sitemap(text: str, sitemap_url: str, base_url: str) -> Tuple[ExtractionResult, List[str]]:
    result = ExtractionResult()
    try:
        root = safe_xml_fromstring(text)
    except UnsafeDocument:
        result.notes.append("sitemap_rejected")
        return result, []
    sitemaps = _collect_locs(root, sitemap_url, base_url, result)
    result.notes.append(f"sitemap_entries:{len(result.endpoints)}")
    return result, sitemaps[:MAX_SITEMAP_INDEX_FILES]


def looks_like_sitemap(content_type: str, body: str) -> bool:
    return "xml" in (content_type or "") or body.lstrip().startswith("<?xml") or "<urlset" in body[:2000]
