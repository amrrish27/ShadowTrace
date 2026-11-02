"""JavaScript discovery source.

A real parse (tree-sitter) drives the primary extraction; a bounded, linear-time
regex fallback runs when parsing fails or produces nothing.  Target JavaScript is
parsed as data only — it is never executed, and no code from a target reaches an
interpreter.
"""
from __future__ import annotations

import re
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin

from ...security.redaction import make_snippet
from ..api_gate import is_image_cdn_url, is_static_asset
from ..types import DiscoveredEndpoint, ExtractionResult

MAX_JS_BYTES = 3 * 1024 * 1024
MAX_JS_PARSE_SECONDS = 5.0
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# Bounded, non-backtracking patterns (no nested quantifiers).
_PATH_RE = re.compile(
    r"""(?<![A-Za-z0-9_])["'`]((?:\$\{[A-Za-z_$][A-Za-z0-9_$.]{0,40}\})?/[A-Za-z0-9._~%\-{}$:/?=&+]{1,300})["'`]"""
)
_ABS_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9._~%\-:/?#\[\]@!$&'()*+,;=]{4,400})["'`]""")
_FETCH_RE = re.compile(r"""\bfetch\s*\(\s*["'`]([^"'`\s]{1,400})["'`]""")
_CLIENT_CALL_RE = re.compile(
    r"""\b(?:[A-Za-z0-9_$]*(?:client|api|http|service|request)|axios|ky|got|superagent)\s*(?:\.\s*(get|post|put|patch|delete|head|options)\s*)?\(\s*["'`]([^"'`\s]{1,400})["'`]""",
    re.I,
)
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']\s*,\s*["'`]([^"'`\s]{1,400})["'`]""",
    re.I,
)
_JQUERY_RE = re.compile(r"""\$\.(get|post|ajax)\s*\(\s*["'`]([^"'`\s]{1,400})["'`]""", re.I)
_IMPORT_RE = re.compile(r"""\b(?:import|require)\s*\(\s*["']([^"'\s]{1,400}\.js(?:\?[^"'\s]*)?)["']""")
_WS_RE = re.compile(r"""new\s+WebSocket\s*\(\s*["'`]([^"'`\s]{1,400})["'`]""")
_ES_RE = re.compile(r"""new\s+EventSource\s*\(\s*["'`]([^"'`\s]{1,400})["'`]""")
_CONST_RE = re.compile(r"""(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]{0,40})\s*=\s*["'`]([^"'`\n]{1,200})["'`]""")
_GRAPHQL_RE = re.compile(r"""(?:query|mutation)\s+([A-Za-z_][A-Za-z0-9_]{0,60})""")
_CONCAT_RE = re.compile(r"""([A-Za-z_$][A-Za-z0-9_$]{0,40})\s*\+\s*["'`]([^"'`\n]{1,300})["'`]""")
_CHUNK_RE = re.compile(r"""["']([A-Za-z0-9._\-/]{1,200}\.(?:js|mjs|chunk\.js))["']""")

_TEMPLATE_PARAM_RE = re.compile(r"\$\{[^}]{1,80}\}")


API_MARKERS = ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/internal/", "/graphql", "/admin/", "/oauth")


def _api_like(path: str) -> bool:
    lowered = (path or "").lower()
    return any(marker in lowered for marker in API_MARKERS)


def _line_of(code: str, index: int) -> int:
    return code.count("\n", 0, index) + 1


def _resolve_path(raw: str, consts: Dict[str, str]) -> Optional[str]:
    """Resolve simple template literals and concatenations into a path template."""
    value = raw.strip()
    if not value:
        return None
    for name, replacement in list(consts.items())[:200]:
        value = value.replace("${" + name + "}", replacement)
        if value == replacement:
            pass
    value = _TEMPLATE_PARAM_RE.sub("{param}", value)
    if value.startswith("http://") or value.startswith("https://"):
        return value
    if not value.startswith("/"):
        return None
    if value.startswith("//"):
        return None
    if len(value) < 2 or len(value) > 300:
        return None
    if any(ch.isspace() for ch in value):
        return None
    return value


def _literal_endpoints(
    code: str, source_url: str, base_url: str, consts: Dict[str, str], source_type: str
) -> List[DiscoveredEndpoint]:
    found: List[DiscoveredEndpoint] = []
    seen: set[Tuple[str, str]] = set()
    concat_literals = {match.group(2) for match in _CONCAT_RE.finditer(code)}
    const_literals = set(consts.values())

    def add(method: str, raw: str, index: int, extractor: str, confidence: float) -> None:
        resolved = _resolve_path(raw, consts)
        if not resolved:
            return
        if is_image_cdn_url(resolved) or is_static_asset(resolved):
            return
        if resolved.startswith("http://") or resolved.startswith("https://"):
            absolute = resolved
            # If host differs from target base_url, do not treat as an endpoint
            target_host = base_url.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
            abs_host = absolute.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
            if abs_host != target_host:
                return
            path = "/" + absolute.split("://", 1)[1].split("/", 1)[1] if "/" in absolute.split("://", 1)[1] else "/"
            query = absolute.split("?", 1)[1] if "?" in absolute else ""
        else:
            path, _, query = resolved.partition("?")
            absolute = urljoin(base_url, resolved)
        if path.startswith("http://") or path.startswith("https://"):
            pass
        else:
            segments = [s for s in path.strip("/").split("/") if s]
            if segments and segments[0] == "{param}" and len(segments) <= 2:
                return

        key = (method.upper(), resolved)
        if key in seen:
            return
        seen.add(key)
        line_no = _line_of(code, index)
        found.append(
            DiscoveredEndpoint(
                method=method.upper(),
                path=path or "/",
                query=query,
                source_type=source_type,
                source_url=source_url,
                location=f"line {line_no}",
                snippet=make_snippet(code[max(0, index - 60) : index + 120]),
                extractor=extractor,
                confidence=confidence,
                base_url=base_url,
            )
        )

    for match in _XHR_OPEN_RE.finditer(code):
        add(match.group(1), match.group(2), match.start(), "xhr_open", 0.9)
    for match in _CLIENT_CALL_RE.finditer(code):
        method = (match.group(1) or "GET").upper()
        add(method, match.group(2), match.start(), "http_client_call", 0.9)
    for match in _JQUERY_RE.finditer(code):
        method = {"get": "GET", "post": "POST", "ajax": "GET"}[match.group(1).lower()]
        add(method, match.group(2), match.start(), "jquery_ajax", 0.85)
    for match in _FETCH_RE.finditer(code):
        add("GET", match.group(1), match.start(), "fetch", 0.9)
    for match in _WS_RE.finditer(code):
        add("GET", match.group(1), match.start(), "websocket", 0.7)
    for match in _ES_RE.finditer(code):
        add("GET", match.group(1), match.start(), "eventsource", 0.7)
    for match in _CONCAT_RE.finditer(code):
        base_value = consts.get(match.group(1))
        if base_value:
            add("GET", base_value.rstrip("/") + "/" + match.group(2).lstrip("/"), match.start(), "constant_concat", 0.8)
    for match in _CONST_RE.finditer(code):
        val = match.group(2)
        if _api_like(val) and len(val.strip("/").split("/")) >= 2:
            add("GET", val, match.start(), "const_endpoint", 0.75)
    return found


def _parse_with_tree_sitter(code: str) -> Optional[object]:
    try:
        import tree_sitter_javascript as tsjs
        from tree_sitter import Language, Parser
    except Exception:  # pragma: no cover - dependency missing
        return None
    try:
        language = Language(tsjs.language())
        parser = Parser(language)
        return parser.parse(code.encode("utf-8", "replace"))
    except Exception:
        return None


def _tree_chunks(tree: object, code: str, deadline: float = 0.0) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Return (chunk script specifiers, inline import() literals) from the AST."""
    chunks: List[str] = []
    literals: List[Tuple[str, str]] = []
    if tree is None:
        return chunks, literals
    root = getattr(tree, "root_node", None)
    if root is None:
        return chunks, literals
    stack = [root]
    budget = 200_000
    while stack and budget > 0:
        if deadline > 0 and time.monotonic() > deadline:
            break
        budget -= 1
        node = stack.pop()
        node_type = getattr(node, "type", "")
        if node_type in {"string", "template_string"}:
            text = code[node.start_byte : node.end_byte]
            literals.append((node_type, text[:400]))
        if node_type == "call_expression":
            callee = code[node.start_byte : node.end_byte][:120]
            if callee.startswith("import(") or callee.startswith("require("):
                match = re.search(r"""\(\s*["']([^"']{1,300}\.(?:js|mjs))["']""", callee + ")")
                if match:
                    chunks.append(match.group(1))
        stack.extend(getattr(node, "named_children", [])[:50])
    return chunks, literals


def extract_javascript(
    code: str,
    source_url: str,
    base_url: str,
    *,
    location_prefix: str = "",
    source_type: str = "javascript",
) -> ExtractionResult:
    result = ExtractionResult()
    if not code:
        return result
    if len(code) > MAX_JS_BYTES:
        code = code[:MAX_JS_BYTES]
    consts: Dict[str, str] = {}
    start_time = time.monotonic()
    deadline = start_time + MAX_JS_PARSE_SECONDS
    for match in _CONST_RE.finditer(code):
        if len(consts) < 200:
            consts[match.group(1)] = match.group(2)
        if time.monotonic() > deadline:
            break

    tree = _parse_with_tree_sitter(code)
    parsed_ok = tree is not None
    if tree is not None:
        chunks, literals = _tree_chunks(tree, code, deadline=deadline)
        for value in chunks[:200]:
            absolute = urljoin(base_url, value)
            if absolute not in result.scripts:
                result.scripts.append(absolute)
        ast_paths = 0
        for _kind, literal in literals[:20_000]:
            inner = literal.strip().strip("'\"`")
            resolved = _resolve_path(inner, consts)
            if resolved and (resolved.startswith("/") or resolved.startswith("http")):
                ast_paths += 1
        result.notes.append(f"ast_literals:{len(literals)}")

    fallback = _literal_endpoints(code, source_url, base_url, consts, source_type)
    chunks_re = [m.group(1) for m in _CHUNK_RE.finditer(code)][:100]
    for value in chunks_re:
        absolute = urljoin(base_url, value)
        if absolute not in result.scripts and absolute != source_url:
            result.scripts.append(absolute)

    for match in _IMPORT_RE.finditer(code):
        absolute = urljoin(base_url, match.group(1))
        if absolute not in result.scripts:
            result.scripts.append(absolute)

    graphql_ops = [m.group(1) for m in _GRAPHQL_RE.finditer(code)][:20]
    if graphql_ops:
        result.notes.extend(f"graphql_operation:{op}" for op in graphql_ops)
        if "/graphql" in code:
            result.endpoints.append(
                DiscoveredEndpoint(
                    method="POST",
                    path="/graphql",
                    source_type="graphql",
                    source_url=source_url,
                    location="graphql operation",
                    snippet=make_snippet(", ".join(graphql_ops)),
                    extractor="graphql_endpoint",
                    confidence=0.7,
                    base_url=base_url,
                )
            )

    for endpoint in fallback:
        if location_prefix:
            endpoint = DiscoveredEndpoint(
                **{**endpoint.__dict__, "location": f"{location_prefix} {endpoint.location}".strip()}
            )
        result.endpoints.append(endpoint)

    if not parsed_ok:
        result.notes.append("parser_fallback_regex")
    return result


def iter_denied_methods(endpoints: Iterable[DiscoveredEndpoint]) -> Sequence[str]:
    return sorted({e.method for e in endpoints if e.method not in HTTP_METHODS})
