"""API specification discovery: OpenAPI/Swagger, Postman, Swagger UI and Redoc.

``$ref`` resolution is local-only.  Remote (http/https) and ``file:`` references
are refused and recorded; nothing is fetched from inside a specification.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ...security.redaction import make_snippet
from ..parsers import UnsafeDocument, parse_yaml_or_json
from ..types import DiscoveredEndpoint, ExtractionResult

MAX_REFS = 200
WELL_KNOWN_SPEC_PATHS: Tuple[str, ...] = (
    # OpenAPI, Swagger and Documentation UIs
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui.html",
    "/api-docs.json",
    "/redoc",
    "/v3/api-docs",
    "/api-docs",
    "/docs",
    "/v2/api-docs",
    "/openapi.yaml",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/docs/openapi.json",
    "/api/openapi.json",
    "/.well-known/openapi.json",
    "/.well-known/schema-discovery",
    "/api/swagger.json",
    "/api/spec",
    "/spec",
    "/swagger-ui/index.html",
    "/api/docs",
    "/api/v1/docs",
    "/api/v2/docs",
    "/api/swagger",
    "/swagger-resources",
    "/robots.txt",
    "/sitemap.xml",
    # GraphQL and GraphiQL
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/graphql/console",
    "/v1/graphql",
    "/v2/graphql",
    "/subscriptions",
    # Spring Boot Actuator, Health, Metrics, and Diagnostics
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/mappings",
    "/actuator/beans",
    "/health",
    "/healthz",
    "/livez",
    "/readyz",
    "/status",
    "/ping",
    "/version",
    "/info",
    "/metrics",
    "/_health",
    "/_status",
    "/_debug",
    "/debug",
    "/_stats",
    "/api/health",
    "/api/status",
    "/api/version",
    # Admin, Internal and Management
    "/admin",
    "/api/admin",
    "/api/admin/backup",
    "/internal",
    "/api/internal",
    "/api/internal/tokens",
    "/api/internal/export",
    "/api/internal/audit-log",
    "/api/internal/shipments",
    "/_admin",
    "/management",
    "/management/health",
    "/console",
    "/.git/HEAD",
    # API Version roots
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/v3",
    "/rest",
    "/rpc",
    "/api/v1/users",
    "/api/v1/health",
    "/api/v2/users",
    "/api/v1/orders",
    "/api/v2/orders",
    "/api/v1/invoices",
    "/api/v1/customers",
    "/api/v1/reports",
    "/api/v1/partners",
    "/api/v1/secret-report",
    "/api/v1/legacy",
    "/api/legacy",
    "/api/legacy/checkout",
    # DVGA and Common Application Routes
    "/audit",
    "/create_paste",
    "/import_paste",
    "/upload_paste",
    "/solutions",
    "/start_over",
    "/about",
    "/my_pastes",
    "/public_pastes",
    "/difficulty",
    "/difficulty/1",
    "/difficulty/easy",
    "/paste",
    "/pastes",
    "/import",
    "/upload",
    "/export",
    "/search",
    "/auth",
    "/auth/login",
    "/auth/register",
    "/login",
    "/logout",
    "/register",
    "/token",
    "/tokens",
    "/profile",
    "/account",
    "/users",
    "/orders",
    "/invoices",
    "/items",
    "/products",
    "/checkout",
    "/cart",
    "/feedback",
    "/config",
    "/settings",
    "/setup",
    "/help",
    # Lab and Diagnostic Scenarios
    "/lab/api/cookies/session",
    "/lab/api/cors/profile",
    "/lab/api/errors/checkout",
    "/lab/api/xss/echo",
    "/lab/api/sqli/product",
    "/lab/api/diagnostics/env",
    "/lab/transport/checkout",
)

_BAD_REF_PREFIXES = ("http://", "https://", "file:", "ftp:", "//", "\\\\")


def _iter_refs(node: Any, found: List[str], depth: int = 0) -> None:
    if depth > 20 or len(found) > MAX_REFS:
        return
    if isinstance(node, dict):
        for key, value in list(node.items())[:200]:
            if key == "$ref" and isinstance(value, str):
                found.append(value[:500])
            else:
                _iter_refs(value, found, depth + 1)
    elif isinstance(node, list):
        for item in node[:200]:
            _iter_refs(item, found, depth + 1)


def parse_openapi(document: Any, source_url: str, base_url: str) -> ExtractionResult:
    result = ExtractionResult()
    if not isinstance(document, dict):
        return result
    version = str(document.get("openapi") or document.get("swagger") or "")
    if not version:
        return result
    refs: List[str] = []
    _iter_refs(document, refs)
    refused = [ref for ref in refs if ref.lower().startswith(_BAD_REF_PREFIXES)]
    if refused:
        result.notes.append(f"refused_remote_refs:{len(refused)}")
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return result
    for path, operations in list(paths.items())[:500]:
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        if not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            upper = str(method).upper()
            if upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}:
                continue
            description = ""
            if isinstance(operation, dict):
                description = str(operation.get("summary") or operation.get("description") or "")[:160]
            result.endpoints.append(
                DiscoveredEndpoint(
                    method=upper,
                    path=path,
                    source_type="openapi",
                    source_url=source_url,
                    location=f"paths.{path}.{upper.lower()}",
                    snippet=make_snippet(f"{upper} {path} {description}".strip()),
                    extractor="openapi_paths",
                    confidence=1.0,
                    base_url=base_url,
                )
            )
    result.specifications.append({"kind": "openapi", "version": version, "paths": len(paths)})
    return result


def _postman_url(raw: Any) -> str:
    """Return a request URL from a Postman url string/object.

    Collections may store either ``"raw": "https://host/api/v1/users"`` or the
    structured form with ``host``/``path`` arrays; both are supported and neither
    is treated as anything but data.
    """
    if isinstance(raw, str):
        return raw[:500]
    if not isinstance(raw, dict):
        return ""
    direct = raw.get("raw")
    if isinstance(direct, str) and direct:
        return direct[:500]
    host = raw.get("host")
    if isinstance(host, list):
        host = ".".join(str(part) for part in host[:10])
    path = raw.get("path")
    if isinstance(path, list):
        path = "/".join(str(part) for part in path[:40])
    path = str(path or "")
    if not path and not host:
        return ""
    if host:
        joined = f"{host}/{path}" if path else str(host)
        return joined if "://" in joined else f"https://{joined}"
    return "/" + path.lstrip("/")


def parse_postman(document: Any, source_url: str, base_url: str) -> ExtractionResult:
    result = ExtractionResult()
    if not isinstance(document, dict) or "info" not in document or "item" not in document:
        return result
    base_variables: Dict[str, str] = {}
    for variable in (document.get("variable") or [])[:50]:
        if isinstance(variable, dict) and "key" in variable and "value" in variable:
            base_variables[str(variable["key"])] = str(variable["value"])
    raw_urls: List[Tuple[str, str]] = []

    def walk(items: Any, depth: int = 0) -> None:
        if depth > 8 or not isinstance(items, list):
            return
        for item in items[:200]:
            if not isinstance(item, dict):
                continue
            if "item" in item:
                walk(item.get("item"), depth + 1)
            request = item.get("request")
            if isinstance(request, dict):
                method = str(request.get("method") or "GET").upper()
                raw = _postman_url(request.get("url"))
                if isinstance(raw, str) and raw:
                    raw_urls.append((method, raw[:500]))

    walk(document.get("item"))
    for method, raw in raw_urls[:500]:
        for key, value in base_variables.items():
            raw = raw.replace("{{" + key + "}}", value)
        path = raw.split("://", 1)[-1] if "://" in raw else raw
        if "://" in raw:
            path = "/" + path.split("/", 1)[1] if "/" in path else "/"
        if not path.startswith("/"):
            path = "/" + path
        result.endpoints.append(
            DiscoveredEndpoint(
                method=method,
                path=path.split("?")[0],
                query=path.split("?", 1)[1] if "?" in path else "",
                source_type="postman",
                source_url=source_url,
                location="postman collection item",
                snippet=make_snippet(f"{method} {raw}"),
                extractor="postman_collection",
                confidence=0.9,
                base_url=base_url,
            )
        )
    result.specifications.append({"kind": "postman", "requests": len(raw_urls)})
    return result


def parse_swagger_ui_config(document: Any, source_url: str, base_url: str) -> ExtractionResult:
    result = ExtractionResult()
    urls: List[str] = []
    if isinstance(document, dict):
        for candidate in (document.get("urls"), document.get("url")):
            if isinstance(candidate, str):
                urls.append(candidate)
            elif isinstance(candidate, list):
                for entry in candidate[:50]:
                    if isinstance(entry, dict) and isinstance(entry.get("url"), str):
                        urls.append(entry["url"])
    for url in urls[:20]:
        path = url.split("://", 1)[-1] if "://" in url else url
        if "://" in url:
            path = "/" + path.split("/", 1)[1] if "/" in path else "/"
        result.endpoints.append(
            DiscoveredEndpoint(
                method="GET",
                path=path if path.startswith("/") else "/" + path,
                source_type="swagger_ui",
                source_url=source_url,
                location="swagger ui config",
                snippet=make_snippet(url),
                extractor="swagger_ui_config",
                confidence=0.7,
                base_url=base_url,
            )
        )
    if urls:
        result.specifications.append({"kind": "swagger_ui", "urls": urls[:10]})
    return result


def is_openapi(document: Any) -> bool:
    return isinstance(document, dict) and ("openapi" in document or "swagger" in document) and "paths" in document


def is_postman(document: Any) -> bool:
    return isinstance(document, dict) and "info" in document and "item" in document


def parse_specification(text: str, source_url: str, base_url: str) -> ExtractionResult:
    result = ExtractionResult()
    try:
        document = parse_yaml_or_json(text)
    except UnsafeDocument:
        result.notes.append("specification_rejected_unsafe")
        return result
    if document is None:
        result.notes.append("specification_unparseable")
        return result
    if is_openapi(document):
        result.extend(parse_openapi(document, source_url, base_url))
    elif is_postman(document):
        result.extend(parse_postman(document, source_url, base_url))
    elif isinstance(document, dict) and ("urls" in document or "url" in document):
        result.extend(parse_swagger_ui_config(document, source_url, base_url))
    elif isinstance(document, dict) and isinstance(document.get("paths"), dict):
        result.extend(parse_openapi({**document, "openapi": "unknown"}, source_url, base_url))
    if not result.endpoints and not result.specifications:
        result.notes.append("specification_unrecognized")
    return result


def documented_signatures(document: Any) -> List[Tuple[str, str]]:
    """(method, path) pairs from an OpenAPI document, used as the baseline."""
    pairs: List[Tuple[str, str]] = []
    if not isinstance(document, dict):
        return pairs
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return pairs
    for path, operations in list(paths.items())[:1000]:
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        for method in operations:
            upper = str(method).upper()
            if upper in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}:
                pairs.append((upper, path))
    return pairs
