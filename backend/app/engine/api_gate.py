"""API-likeness gate for ShadowTrace.

Answers the single question: is this an API endpoint?
Filters out HTML pages, homepages, static assets, and image CDN URLs.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional, Sequence, Union

# Matches /api, /v1, /v2, /graphql, /graphiql, /rest, /rpc, /internal, /admin, /_word, /actuator
API_PATH_RE = re.compile(
    r"""(?i)(?:^|/)(?:api(?:/v\d+)?|v\d+|graphql|graphiql|rest|rpc|internal|admin|_[a-zA-Z0-9]+|actuator)(?:/|$)"""
)

# Known static file extensions
STATIC_EXTENSIONS = (
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".mp4",
    ".webm",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
)

# Image CDN query parameter patterns (e.g. ?auto=compress&fit=crop&w=600&h=400&q=75)
IMAGE_CDN_PARAMS = {"auto", "fit", "w", "h", "q", "crop", "format", "quality", "width", "height", "dpr"}

# API Content-Types
API_CONTENT_TYPES = (
    "application/json",
    "application/ld+json",
    "application/vnd.api+json",
    "+json",
    "application/xml",
    "text/xml",
    "+xml",
    "application/graphql",
    "application/x-protobuf",
    "application/protobuf",
)

API_EXTRACTORS = {
    "fetch",
    "http_client_call",
    "xhr_open",
    "jquery_ajax",
    "websocket",
    "openapi",
    "swagger_ui",
    "redoc",
    "postman",
    "graphql",
    "graphql_endpoint",
    "har",
}

API_SOURCE_TYPES = {
    "openapi",
    "swagger_ui",
    "redoc",
    "postman",
    "graphql",
    "har",
}


def is_image_cdn_url(path: str, query: str = "") -> bool:
    """Check if the path or query matches image CDN patterns."""
    if not query:
        # Check if query is in path
        if "?" in path:
            path, query = path.split("?", 1)
    if query:
        param_names = {part.split("=")[0].strip().lower() for part in query.split("&") if part}
        if param_names and param_names.issubset(IMAGE_CDN_PARAMS):
            return True
        if len(param_names & IMAGE_CDN_PARAMS) >= 2:
            return True
    return False


def is_static_asset(path: str) -> bool:
    """Check if the path ends in a known static asset extension."""
    clean_path = path.split("?")[0].split("#")[0].lower()
    return clean_path.endswith(STATIC_EXTENSIONS)


def api_likeness(
    endpoint: Any,
    response: Optional[Any] = None,
    *,
    sources: Optional[Iterable[Any]] = None,
) -> bool:
    """Evaluate whether an endpoint candidate is an API endpoint.

    Returns True if ANY of:
      1. Response content-type is JSON, XML, GraphQL or protobuf.
      2. Path matches /api, /v\\d+, /graphql, /rest, /rpc, /internal, /admin, /_<word>, /actuator.
      3. The endpoint was found as a fetch/axios/XHR/WebSocket target in JS,
         a HAR entry, or an OpenAPI/Postman/GraphQL entry.

    NOT an API by itself:
      - "/" (homepage)
      - plain text/html pages (unless matching API path or API source)
      - static assets (.js, .css, .png, .jpg, .svg, .woff, .ico, .map, etc.)
      - image/CDN URLs (e.g. ?auto=&fit=&w=&h=&q=)
    """
    path = ""
    query = ""
    extractor = ""
    source_type = ""
    discovered_from: Sequence[str] = ()

    if isinstance(endpoint, str):
        path = endpoint
    elif isinstance(endpoint, dict):
        path = endpoint.get("path_template") or endpoint.get("path") or endpoint.get("endpoint_path") or ""
        query = endpoint.get("query_template") or endpoint.get("query") or ""
        extractor = endpoint.get("extractor") or ""
        source_type = endpoint.get("source_type") or ""
        discovered_from = endpoint.get("discovered_from") or ()
    else:
        path = getattr(endpoint, "path_template", None) or getattr(endpoint, "path", None) or getattr(endpoint, "endpoint_path", "") or ""
        query = getattr(endpoint, "query_template", None) or getattr(endpoint, "query", "") or ""
        extractor = getattr(endpoint, "extractor", "") or ""
        source_type = getattr(endpoint, "source_type", "") or ""
        discovered_from = getattr(endpoint, "discovered_from", None) or ()

    clean_path = path.split("?")[0].split("#")[0].strip()

    # Rule out "/" (root homepage)
    if not clean_path or clean_path == "/":
        return False

    # Rule out static assets
    if is_static_asset(clean_path):
        return False

    # Rule out image CDN URLs
    if is_image_cdn_url(clean_path, query):
        return False

    # Check 1: Response content type
    content_type = ""
    if response is not None:
        if isinstance(response, str):
            content_type = response.lower()
        elif isinstance(response, dict):
            content_type = (
                response.get("content_type")
                or (response.get("headers") or {}).get("content-type", "")
            ).lower()
        else:
            content_type = (
                getattr(response, "content_type", None)
                or (getattr(response, "headers", {}) or {}).get("content-type", "")
            ).lower()

    if content_type:
        # If response is an explicit API content type
        if any(api_ct in content_type for api_ct in API_CONTENT_TYPES):
            return True

    # Check 2: Path matches standard API route patterns
    if API_PATH_RE.search(clean_path):
        # Exception: if response is explicitly text/html and not GraphQL/spec UI,
        # but path is /api/... or /graphql, it still counts as an API (e.g. GraphQL UI, API error page).
        return True

    # Check 3: Discovered from an API client call in JS, HAR, or Spec
    if extractor in API_EXTRACTORS or source_type in API_SOURCE_TYPES:
        return True

    if any(st in API_SOURCE_TYPES or st in API_EXTRACTORS for st in discovered_from):
        return True

    if sources:
        for src in sources:
            src_type = getattr(src, "source_type", "") or ""
            src_extractor = getattr(src, "extractor", "") or ""
            if src_type in API_SOURCE_TYPES or src_extractor in API_EXTRACTORS:
                return True

    # If it returns plain text/html and none of the API criteria matched, it is NOT an API
    if "text/html" in content_type:
        return False

    return False
