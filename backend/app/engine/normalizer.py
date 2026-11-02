"""Path canonicalization and normalization into stable path templates.

``/api/users/1234`` and ``/api/users/99`` collapse to ``/api/users/{id}`` so the
inventory stays stable across scans and findings keep a stable fingerprint.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .types import DiscoveredEndpoint
from .api_gate import is_image_cdn_url

DYNAMIC_TEMPLATE_RE = re.compile(r"\{[a-z]+\}")


def collapse(template: str) -> str:
    """Collapse typed parameters (``{id}``, ``{uuid}`` ...) to ``{param}``."""
    return DYNAMIC_TEMPLATE_RE.sub("{param}", template)

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HASH_RE = re.compile(r"\b[0-9a-fA-F]{16,64}\b")
OBJECTID_RE = re.compile(r"\b[0-9a-fA-F]{24}\b")
BRACED_RE = re.compile(r"\{[^/{}]{1,60}\}")
COLON_RE = re.compile(r"(?<=/):[A-Za-z_][A-Za-z0-9_]{0,40}")
NUMBER_RE = re.compile(r"^[0-9]{1,20}$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T[0-9:.]+Z?)?$")
LONG_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{16,80}$")

STATIC_EXTENSIONS = (
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
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
    ".js",
    ".mjs",
)

TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "msclkid",
    "ref",
    "_",
}


@dataclass(frozen=True)
class NormalizedEndpoint:
    method: str
    scheme: str
    host: str
    path_template: str
    query_template: str
    raw_path: str
    origin: str

    @property
    def fingerprint(self) -> str:
        return f"{self.method}|{self.host}|{self.path_template}|{self.query_template}"


def normalize_segment(segment: str) -> str:
    if not segment:
        return segment
    if BRACED_RE.fullmatch(segment) or segment.startswith(":"):
        return "{param}"
    if UUID_RE.fullmatch(segment):
        return "{uuid}"
    if OBJECTID_RE.fullmatch(segment) or HASH_RE.fullmatch(segment):
        return "{hash}"
    if NUMBER_RE.fullmatch(segment):
        return "{id}"
    if ISO_DATE_RE.fullmatch(segment):
        return "{date}"
    if LONG_TOKEN_RE.fullmatch(segment) and any(c.isdigit() for c in segment) and len(segment) >= 20:
        return "{token}"
    return segment


def normalize_path(path: str) -> str:
    raw = (path or "/").split("?", 1)[0].split("#", 1)[0]
    if not raw.startswith("/"):
        raw = "/" + raw
    segments = [segment for segment in raw.split("/") if segment != ""]
    normalized = [normalize_segment(segment) for segment in segments[:40]]
    if not normalized:
        return "/"
    return "/" + "/".join(normalized)


def normalize_query(query: str) -> str:
    if not query:
        return ""
    pairs = []
    for chunk in query.split("&")[:40]:
        if not chunk or "=" not in chunk:
            if chunk:
                pairs.append((chunk.split("=")[0][:40], ""))
            continue
        key, _, _value = chunk.partition("=")
        key = key.strip()[:40]
        if not key or key.lower() in TRACKING_PARAMS:
            continue
        pairs.append((key, "{value}"))
    if not pairs:
        return ""
    pairs.sort()
    return "&".join(f"{key}={value}" if value else key for key, value in pairs)


def looks_static(path: str) -> bool:
    lowered = path.lower().split("?")[0]
    return lowered.endswith(STATIC_EXTENSIONS)


def normalize_endpoint(endpoint: DiscoveredEndpoint, default_base: str) -> Optional[NormalizedEndpoint]:
    base = endpoint.base_url or default_base
    if not base:
        return None
    try:
        parts = urlsplit(base)
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname.lower()
    port = parts.port
    origin = f"{parts.scheme}://{host}" + (f":{port}" if port and port not in (80, 443) else "")
    path = endpoint.path or "/"
    if looks_static(path):
        return None
    if is_image_cdn_url(path, endpoint.query):
        return None
    template = collapse(normalize_path(path))
    if template.count("/") > 20:
        return None
    SPEC_HAR_SOURCES = {"openapi", "swagger_ui", "redoc", "postman", "graphql", "har"}
    if endpoint.source_type not in SPEC_HAR_SOURCES:
        if template in {"/{param}", "/{param}/{param}"} or re.match(r"^/\{param\}/[A-Za-z0-9_-]+$", template):
            return None
    method = endpoint.method.upper()
    if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"}:
        method = "GET"
    return NormalizedEndpoint(
        method=method,
        scheme=parts.scheme,
        host=host,
        path_template=template,
        query_template=normalize_query(endpoint.query),
        raw_path=path,
        origin=origin,
    )


def dedupe_endpoints(
    endpoints: Iterable[Tuple[NormalizedEndpoint, DiscoveredEndpoint]]
) -> dict[str, Tuple[NormalizedEndpoint, list[DiscoveredEndpoint]]]:
    grouped: dict[str, Tuple[NormalizedEndpoint, list[DiscoveredEndpoint]]] = {}
    for normalized, raw in endpoints:
        key = normalized.fingerprint
        if key in grouped:
            grouped[key][1].append(raw)
        else:
            grouped[key] = (normalized, [raw])
    return grouped


def method_allowed_for_validation(method: str) -> bool:
    return method.upper() in {"GET", "HEAD", "OPTIONS"}


def split_path(path_template: str) -> Sequence[str]:
    return [segment for segment in path_template.split("/") if segment]
