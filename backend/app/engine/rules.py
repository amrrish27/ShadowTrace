"""Detection rule registry.

Every rule has a stable ID, an explicit severity, confidence, status and a
rationale that never overclaims.  ``suspected`` findings must use hedged wording;
:func:`lint_wording` enforces this and is part of the test suite.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence

from ..security.redaction import make_snippet, redact_text, secret_kinds
from .evidence import evidence_block
from .risk import exposure_factor, risk_score
from .types import RuleHit, RuleInput
from .api_gate import api_likeness

log = logging.getLogger("shadowtrace.rules")

SENSITIVE_PATH_TOKENS = {
    "admin",
    "internal",
    "debug",
    "actuator",
    "env",
    "dump",
    "backup",
    "token",
    "secret",
    "config",
    "metrics",
    "private",
    "staging",
    "dev",
    "test",
    "export",
    "manage",
    "console",
    "graphiql",
}

CERTAINTY_PHRASES = (
    "is vulnerable",
    "are vulnerable",
    "proven vulnerable",
    "definitely vulnerable",
    "guaranteed exploitable",
    "exploit confirmed",
)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    confidence: str
    status: str
    evaluate: Callable[[RuleInput], Optional[RuleHit]]
    description: str


def _sensitive_path(path: str) -> bool:
    segments = [segment.lower() for segment in path.split("/") if segment]
    return any(segment in SENSITIVE_PATH_TOKENS for segment in segments)


def _is_json(headers: Dict[str, str], content_type: str) -> bool:
    return "json" in (content_type or "") or "json" in headers.get("content-type", "")


def _hit(
    rule_id: str,
    title: str,
    severity: str,
    confidence: str,
    status: str,
    rationale: str,
    limitations: str,
    remediation: str,
    inp: RuleInput,
    *,
    exposure: Optional[float] = None,
    evidence=None,
    patterns: Sequence[str] = (),
) -> RuleHit:
    exposure_value = (
        exposure
        if exposure is not None
        else exposure_factor(unauthenticated=status == "open", sensitive_path=_sensitive_path(inp.endpoint_path))
    )
    return RuleHit(
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        status=status,
        exposure=exposure_value,
        rationale=rationale,
        limitations=limitations,
        remediation=remediation,
        evidence=evidence
        or evidence_block(
            method=inp.endpoint_method,
            url=inp.endpoint_url,
            status=inp.status_code,
            headers=inp.headers,
            body=inp.body_text,
            patterns=patterns,
        ),
    )


def rule_shadow_endpoint(inp: RuleInput) -> Optional[RuleHit]:
    if inp.classification != "shadow" or inp.soft_404_match:
        return None
    if inp.status_code is None or not (200 <= inp.status_code < 300):
        return None
    if not api_likeness(inp):
        return None
    sensitive = _sensitive_path(inp.endpoint_path)
    cred_phrase = " without credentials" if inp.baseline_protected else ""
    return _hit(
        "ST-001",
        "Undocumented API endpoint discovered",
        "high" if sensitive else "medium",
        "high",
        "confirmed",
        (
            f"The endpoint {inp.endpoint_method} {inp.endpoint_path} is not present in the documented "
            f"baseline and answered HTTP {inp.status_code}{cred_phrase}. This demonstrates "
            "an undocumented API surface."
        ),
        "Reachability only. No authentication, authorization, rate-limit or business-logic behaviour "
        "was tested beyond the single read-only request.",
        "Inventory the endpoint, add it to the specification or remove it, require authentication and "
        "review its data exposure.",
        inp,
        patterns=("",),
    )


def rule_protected_bypass(inp: RuleInput) -> Optional[RuleHit]:
    if not inp.documented or not inp.baseline_protected:
        return None
    if inp.status_code != 200 or inp.soft_404_match:
        return None
    if inp.headers.get("www-authenticate"):
        return None
    return _hit(
        "ST-002",
        "Endpoint declared protected answers without credentials",
        "high",
        "medium",
        "suspected",
        (
            f"The baseline declares a security requirement for {inp.endpoint_method} {inp.endpoint_path}, "
            "yet an unauthenticated read-only request returned HTTP 200. This may indicate that the "
            "protection is not enforced on this route; a credentialed test would be required to confirm."
        ),
        "The baseline declaration is an assumption about intent. No credential or bypass attempt was "
        "made, and no state-changing request was sent.",
        "Verify the route's authentication middleware, enforce authorization server-side, and add an "
        "automated test that asserts a 401/403 for anonymous requests.",
        inp,
    )


def rule_debug_endpoint(inp: RuleInput) -> Optional[RuleHit]:
    if inp.status_code is None or not (200 <= inp.status_code < 300) or inp.soft_404_match:
        return None
    if not _sensitive_path(inp.endpoint_path):
        return None
    if inp.classification == "shadow":
        return None  # covered by ST-001 with a higher severity
    return _hit(
        "ST-003",
        "Debug or management endpoint is exposed",
        "high",
        "high",
        "confirmed",
        (
            f"{inp.endpoint_method} {inp.endpoint_path} appears to be a debug, management or diagnostic "
            f"route and answered HTTP {inp.status_code} without credentials."
        ),
        "Exposure confirmed by status code; impact depends on the data the endpoint returns and was "
        "not exercised further.",
        "Disable debug and management endpoints outside development, restrict them to an admin network "
        "and require strong authentication.",
        inp,
    )


def _looks_like_openapi(text: str) -> bool:
    head = text[:200_000]
    if '"openapi"' in head or '"swagger"' in head:
        return '"paths"' in head
    if "openapi:" in head[:4000] or "swagger:" in head[:4000]:
        return "paths:" in head
    return False


def rule_specification_exposed(inp: RuleInput) -> Optional[RuleHit]:
    if inp.status_code != 200 or inp.soft_404_match:
        return None
    exposed = _looks_like_openapi(inp.body_text)
    ui = "swagger-ui" in inp.body_text[:50_000].lower() or "redoc" in inp.body_text[:50_000].lower()
    if not exposed and not ui:
        return None
    return _hit(
        "ST-004",
        "API specification or documentation UI is publicly exposed",
        "medium",
        "confirmed",
        "confirmed",
        (
            f"{inp.endpoint_method} {inp.endpoint_path} returns an API specification or documentation "
            "UI without authentication. Public specifications are a discovery source themselves."
        ),
        "Presence is confirmed from the response body. The document's sensitivity depends on the "
        "organization; no attempt was made to use any declared credential.",
        "Restrict specification and documentation endpoints to authenticated users, or publish a "
        "deliberately curated public specification.",
        inp,
        patterns=('"paths"', "swagger", "openapi"),
    )


def rule_graphql_introspection(inp: RuleInput) -> Optional[RuleHit]:
    if inp.status_code is None or not (200 <= inp.status_code < 300):
        return None
    body = inp.body_text[:200_000]
    if '"__schema"' not in body and '"queryType"' not in body:
        return None
    return _hit(
        "ST-005",
        "GraphQL introspection is enabled",
        "medium",
        "confirmed",
        "confirmed",
        (
            f"The GraphQL endpoint {inp.endpoint_path} returns schema introspection data "
            "(queryType/__schema), exposing the full API surface."
        ),
        "Detected from a read-only response. Introspection exposure is confirmed; whether any "
        "operation enforces authorization was not tested.",
        "Disable introspection in production or restrict it to authenticated administrators.",
        inp,
        patterns=("queryType", "__schema"),
    )


def rule_permissive_cors(inp: RuleInput) -> Optional[RuleHit]:
    allow_origin = inp.headers.get("access-control-allow-origin", "")
    allow_credentials = inp.headers.get("access-control-allow-credentials", "").lower() == "true"
    if not allow_origin:
        return None
    wildcard = allow_origin.strip() == "*"
    reflected = not wildcard and inp.endpoint_url.startswith(allow_origin.strip())
    if wildcard and allow_credentials:
        severity, confidence, status = "high", "confirmed", "confirmed"
        detail = "wildcard origin combined with credentials"
    elif reflected and allow_credentials:
        severity, confidence, status = "high", "medium", "suspected"
        detail = "reflected origin combined with credentials"
    elif wildcard:
        severity, confidence, status = "medium", "confirmed", "confirmed"
        detail = "wildcard origin"
    else:
        return None
    return _hit(
        "ST-006",
        "Overly permissive CORS policy",
        severity,
        confidence,
        status,
        f"The response advertises a permissive CORS policy ({detail}: Access-Control-Allow-Origin "
        f"{make_snippet(allow_origin, 80)}). This determines browser-enforced access only; it does not "
        "by itself prove that server-side authorization is missing.",
        "CORS is enforced by browsers, not servers. Non-browser clients ignore it; impact depends on "
        "whether the endpoint also accepts cookies without other protections.",
        "Restrict Access-Control-Allow-Origin to exact trusted origins, remove credential support from "
        "public endpoints and add a Vary: Origin header.",
        inp,
    )


def rule_risky_methods(inp: RuleInput) -> Optional[RuleHit]:
    allow = inp.headers.get("allow", "") or inp.headers.get("access-control-allow-methods", "")
    if not allow:
        return None
    risky = sorted({m.strip().upper() for m in allow.split(",") if m.strip().upper() in {"PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}})
    if not risky:
        return None
    return _hit(
        "ST-007",
        "Risky HTTP methods are advertised",
        "low",
        "medium",
        "suspected",
        (
            f"The endpoint advertises {', '.join(risky)} through Allow/CORS headers. Advertised methods "
            "are not the same as permitted operations; this could indicate unnecessary write surface."
        ),
        "Only the advertisement was observed. No state-changing request was sent, by design.",
        "Confirm which methods the route truly needs and remove the rest from the routing layer, the "
        "Allow header and CORS preflight responses.",
        inp,
    )


_STACK_PATTERNS = (
    "traceback (most recent call last)",
    "at java.",
    "sqlexception",
    "syntax error at or near",
    "node_modules/",
    "internal server error:",
    "stack trace",
    "django.core.exceptions",
)
_PATH_PATTERNS = re.compile(r"(?:[A-Za-z]:\\\\|[A-Za-z]:\\|/var/www/|/srv/app/|/home/[a-z]+/)")


def rule_verbose_error(inp: RuleInput) -> Optional[RuleHit]:
    body = inp.body_text[:200_000]
    status_error = inp.status_code is not None and inp.status_code >= 400
    lowered = body.lower()
    matched = next((pattern for pattern in _STACK_PATTERNS if pattern in lowered), "")
    path_hit = bool(_PATH_PATTERNS.search(body))
    if not (matched or (path_hit and status_error)):
        return None
    return _hit(
        "ST-008",
        "Verbose error response discloses internals",
        "medium",
        "confirmed",
        "confirmed",
        (
            f"The response for {inp.endpoint_method} {inp.endpoint_path} contains internal details "
            f"(HTTP {inp.status_code}{', stack-trace text' if matched else ', filesystem paths'})."
        ),
        "The excerpt is redacted and truncated. No further probing of error handling was performed.",
        "Return generic error responses to clients, log details server-side with a correlation ID and "
        "disable debug mode in production.",
        inp,
        patterns=(matched,) if matched else ("/var/www/",),
    )


def rule_technology_banner(inp: RuleInput) -> Optional[RuleHit]:
    server = inp.headers.get("server", "")
    powered = inp.headers.get("x-powered-by", "")
    if not server and not powered:
        return None
    has_version = any(ch.isdigit() for ch in server + powered)
    return _hit(
        "ST-009",
        "Technology and version banners are disclosed",
        "low" if has_version else "info",
        "confirmed",
        "confirmed",
        f"The response discloses technology banners (Server/X-Powered-By). "
        f"{'A version number is included.' if has_version else 'No version number was identified.'}",
        "Banner data can be spoofed and is weak evidence on its own; it was not correlated with a CVE.",
        "Remove or generalize Server and X-Powered-By headers at the proxy.",
        inp,
    )


def rule_secret_in_content(inp: RuleInput) -> Optional[RuleHit]:
    kinds = secret_kinds(inp.body_text[:500_000])
    if not kinds:
        return None
    return _hit(
        "ST-010",
        "Credential-shaped string found in target content",
        "high",
        "medium",
        "suspected",
        (
            f"A string matching a credential pattern ({', '.join(sorted(set(kinds))[:5])}) appears in "
            f"the response for {inp.endpoint_path}. The value was not validated against any provider and "
            "is redacted everywhere in ShadowTrace."
        ),
        "Pattern matching only: the string may be a documented example value or a dummy. It was never "
        "used, replayed or tested.",
        "Rotate the credential if it is real, remove it from client-accessible bundles, and add a secret "
        "scanner to the build pipeline.",
        inp,
        patterns=(),
        evidence={**evidence_block(method=inp.endpoint_method, url=inp.endpoint_url, status=inp.status_code, headers=inp.headers, body=inp.body_text), "matched_patterns": sorted(set(kinds))},
    )


SENSITIVE_FIELDS = {"password", "passwd", "ssn", "credit_card", "card_number", "cvv", "api_key", "secret", "private_key", "salary"}


def rule_sensitive_fields(inp: RuleInput) -> Optional[RuleHit]:
    if inp.status_code != 200 or not _is_json(inp.headers, inp.content_type):
        return None
    body = inp.body_text[:200_000]
    found: List[str] = []
    try:
        document = json.loads(body)
    except Exception:
        document = None
    if isinstance(document, (dict, list)):
        stack = [document]
        budget = 2000
        while stack and budget > 0:
            node = stack.pop()
            budget -= 1
            if isinstance(node, dict):
                for key, value in list(node.items())[:100]:
                    if str(key).lower() in SENSITIVE_FIELDS and value not in (None, "", 0):
                        found.append(str(key).lower())
                    stack.append(value)
            elif isinstance(node, list):
                stack.extend(node[:50])
    if not found:
        return None
    unique = sorted(set(found))[:10]
    return _hit(
        "ST-011",
        "Sensitive-looking fields in an unauthenticated response",
        "high",
        "low",
        "suspected",
        (
            "The unauthenticated JSON response contains field names commonly used for sensitive data "
            f"({', '.join(unique)}). Field names are reported; values are redacted and were not stored."
        ),
        "Field-name detection only. Values were redacted, not interpreted; the data may be synthetic or "
        "non-personal.",
        "Confirm the data classification, minimize the fields returned, and require authentication and "
        "object-level authorization before returning personal or secret data.",
        inp,
        evidence={**evidence_block(method=inp.endpoint_method, url=inp.endpoint_url, status=inp.status_code, headers=inp.headers, body=""), "field_names": unique},
    )


def rule_cleartext_http(inp: RuleInput) -> Optional[RuleHit]:
    if inp.target_scheme != "http" or inp.status_code is None or not (200 <= inp.status_code < 300):
        return None
    return _hit(
        "ST-012",
        "API endpoint served over cleartext HTTP",
        "medium",
        "confirmed",
        "confirmed",
        (
            f"{inp.endpoint_method} {inp.endpoint_path} answered over cleartext HTTP. Traffic to this "
            "endpoint is not protected in transit by TLS."
        ),
        "Only the scheme of the probed URL is observed; an HTTPS listener may also exist.",
        "Serve the API exclusively over HTTPS and redirect HTTP to HTTPS at the proxy.",
        inp,
    )


def rule_missing_headers(inp: RuleInput) -> Optional[RuleHit]:
    if inp.status_code is None or inp.status_code >= 400 or not _is_json(inp.headers, inp.content_type):
        return None
    missing = [header for header in ("x-content-type-options", "content-security-policy") if not inp.headers.get(header)]
    if len(missing) < 2:
        return None
    return _hit(
        "ST-013",
        "API responses lack basic security headers",
        "low",
        "confirmed",
        "confirmed",
        (
            "An unauthenticated JSON API response is missing X-Content-Type-Options and "
            "Content-Security-Policy."
        ),
        "Header checks are a hygiene signal; their absence is not exploitable on its own.",
        "Add X-Content-Type-Options: nosniff, a restrictive Content-Security-Policy and other baseline "
        "headers at the application or proxy layer.",
        inp,
    )


def _set_cookie(headers: Dict[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "set-cookie":
            return value or ""
    return ""


def rule_cookie_flags(inp: RuleInput) -> Optional[RuleHit]:
    cookie = _set_cookie(inp.headers)
    if not cookie or inp.target_scheme != "http":
        return None
    lowered = cookie.lower()
    missing = [flag for flag in ("httponly", "secure", "samesite") if flag not in lowered]
    if not missing:
        return None
    return _hit(
        "ST-018",
        "Session cookie is issued without security attributes",
        "medium",
        "confirmed",
        "confirmed",
        "A Set-Cookie header on a cleartext origin omits " + ", ".join(missing) + ".",
        "The cookie value is not interpreted; only the attributes are evaluated.",
        "Issue cookies with HttpOnly, Secure and SameSite, and serve the application over HTTPS.",
        inp,
        patterns=("set-cookie",),
    )


_REFLECTED_MARKUP = ("<script", "<svg", "onerror=", "onload=", "javascript:")


def rule_reflected_markup(inp: RuleInput) -> Optional[RuleHit]:
    if inp.status_code is None or inp.status_code >= 400 or not inp.body_text:
        return None
    if "text/html" not in (inp.content_type or inp.headers.get("content-type", "")):
        return None
    lowered = inp.body_text.lower()
    hit = next((marker for marker in _REFLECTED_MARKUP if marker in lowered), "")
    if not hit:
        return None
    return _hit(
        "ST-019",
        "Request input is reflected into an HTML response unencoded",
        "high",
        "medium",
        "suspected",
        f"Markup passed in the request (for example '{hit}') appears verbatim in a text/html body.",
        "Reflection is necessary but not sufficient for script execution; no browser was driven to "
        "confirm execution, so this stays suspected.",
        "HTML-encode all reflected values and add a restrictive Content-Security-Policy.",
        inp,
        patterns=(hit,),
    )


_SQL_ERRORS = (
    "sqlite_error",
    "syntax error at or near",
    "psycopg2",
    "mysql",
    "ora-0",
    "unclosed quotation mark",
    "microsoft odbc",
)


def rule_sql_error(inp: RuleInput) -> Optional[RuleHit]:
    if not inp.body_text:
        return None
    lowered = inp.body_text.lower()
    hit = next((marker for marker in _SQL_ERRORS if marker in lowered), "")
    if not hit or inp.status_code is None or inp.status_code < 400:
        return None
    return _hit(
        "ST-020",
        "Database error text is returned to the client",
        "high",
        "medium",
        "suspected",
        f"The error body contains a database engine marker ('{hit}') after a quote-bearing request.",
        "A database error indicates unsafe query construction; whether data can be read or written "
        "was not tested, so this is reported as suspected.",
        "Use parameterised queries and return a generic error page without engine detail.",
        inp,
        patterns=(hit,),
    )


_TRAVERSAL_MARKERS = (
    "root:x:0:0:",
    "[fonts]",
    "[extensions]",
    "; for 16-bit app support",
)


def rule_path_traversal(inp: RuleInput) -> Optional[RuleHit]:
    if not inp.body_text or (inp.status_code or 0) >= 400:
        return None
    hit = next((marker for marker in _TRAVERSAL_MARKERS if marker in inp.body_text), "")
    if not hit:
        return None
    return _hit(
        "ST-021",
        "Path traversal sequence returns file content",
        "high",
        "medium",
        "suspected",
        "A traversal sequence in a file parameter returned well-known system file content.",
        "The response is consistent with traversal but the source of the content (host file versus "
        "fixture) cannot be proven from outside, so this stays suspected.",
        "Resolve and confine requested paths to an allow-listed directory; never build paths from input.",
        inp,
        patterns=("..", hit),
    )


def rule_open_redirect(inp: RuleInput) -> Optional[RuleHit]:
    if inp.status_code is None or inp.status_code not in (301, 302, 303, 307, 308):
        return None
    location = inp.headers.get("location") or inp.headers.get("Location") or ""
    if not location or location.startswith("/") or "://" not in location:
        return None
    return _hit(
        "ST-022",
        "Redirect target is taken from request input",
        "medium",
        "medium",
        "suspected",
        "A redirect status was observed with an absolute Location value, which may indicate that "
        "request input controls the destination.",
        "Whether the destination is truly attacker-controlled depends on how the value is read.",
        "Redirect only to a fixed allow-list of paths; reject absolute URLs in redirect parameters.",
        inp,
        patterns=("location",),
    )


_SEQUENTIAL_ID = re.compile(r"/(?:\d{2,})(?:/|$)")


def rule_sequential_identifier(inp: RuleInput) -> Optional[RuleHit]:
    """IDOR signal: a numeric object id served without any authentication.

    Deliberately narrow. It only fires for an *unauthenticated 2xx* response whose path
    carries a multi-digit identifier — the pattern that lets one caller read another
    caller's record. A numeric id behind a 401 is not reported.
    """
    if inp.status_code is None or inp.status_code >= 300:
        return None
    observed = inp.sample_path or inp.endpoint_path or ""
    if not _SEQUENTIAL_ID.search(observed):
        return None
    if inp.path_has_auth_hint:
        return None
    return _hit(
        "ST-023",
        "Object is addressed by a sequential identifier without authentication",
        "high",
        "low",
        "suspected",
        "A 2xx response was observed for an object addressed by a numeric identifier with no "
        "credential presented, which may indicate a missing object-level authorization check.",
        "Sequential identifiers are common in benign APIs; this is a review prompt, not a confirmed "
        "object-level authorization failure.",
        "Use unguessable identifiers and enforce object-level authorization on every read.",
        inp,
        patterns=(observed.rstrip("/").split("/")[-1].strip(),),
    )


ENDPOINT_RULES: Sequence[Rule] = (
    Rule("ST-001", "Undocumented API endpoint discovered", "inventory", "medium", "high", "confirmed", rule_shadow_endpoint, "Shadow endpoint answered a read-only probe."),
    Rule("ST-002", "Declared-protected endpoint answers anonymously", "authorization", "high", "medium", "suspected", rule_protected_bypass, "Baseline security requirement versus observed status."),
    Rule("ST-003", "Debug or management endpoint exposed", "exposure", "high", "high", "confirmed", rule_debug_endpoint, "Debug/management route reachable."),
    Rule("ST-004", "API specification publicly exposed", "exposure", "medium", "confirmed", "confirmed", rule_specification_exposed, "OpenAPI or documentation UI publicly served."),
    Rule("ST-005", "GraphQL introspection enabled", "exposure", "medium", "confirmed", "confirmed", rule_graphql_introspection, "Introspection response observed."),
    Rule("ST-006", "Overly permissive CORS policy", "configuration", "medium", "confirmed", "confirmed", rule_permissive_cors, "Wildcard/reflected origin observed."),
    Rule("ST-007", "Risky HTTP methods advertised", "configuration", "low", "medium", "suspected", rule_risky_methods, "Allow/CORS methods observed."),
    Rule("ST-008", "Verbose error response discloses internals", "information-disclosure", "medium", "confirmed", "confirmed", rule_verbose_error, "Stack traces or internal paths in errors."),
    Rule("ST-010", "Credential-shaped string found in target content", "secrets", "high", "medium", "suspected", rule_secret_in_content, "Secret-pattern match, redacted."),
    Rule("ST-011", "Sensitive-looking fields in an unauthenticated response", "information-disclosure", "high", "low", "suspected", rule_sensitive_fields, "Sensitive field names, values redacted."),
    Rule("ST-013", "API responses lack basic security headers", "configuration", "low", "confirmed", "confirmed", rule_missing_headers, "Missing nosniff/CSP."),
    Rule("ST-018", "Session cookie is issued without security attributes", "configuration", "medium", "confirmed", "confirmed", rule_cookie_flags, "Set-Cookie missing HttpOnly/Secure/SameSite on cleartext."),
    Rule("ST-019", "Request input is reflected into an HTML response unencoded", "injection", "high", "medium", "suspected", rule_reflected_markup, "Markup reflected into text/html."),
    Rule("ST-020", "Database error text is returned to the client", "injection", "high", "medium", "suspected", rule_sql_error, "Engine error text in a 4xx/5xx body."),
    Rule("ST-021", "Path traversal sequence returns file content", "injection", "high", "medium", "suspected", rule_path_traversal, "Traversal returned system-file content."),
    Rule("ST-022", "Redirect target is taken from request input", "input-validation", "medium", "medium", "suspected", rule_open_redirect, "Absolute Location in a redirect."),
    Rule("ST-023", "Object is addressed by a sequential identifier without authentication", "authorization", "high", "low", "suspected", rule_sequential_identifier, "Numeric id, 2xx, no credential."),
)

RULES_BY_ID: Dict[str, Rule] = {rule.id: rule for rule in ENDPOINT_RULES}


def rule_id_path(inp: RuleInput) -> str:
    """Short path label for rule-failure logs (never the full URL or body)."""
    return str(inp.endpoint_path or "")[:120]


CORE_ENDPOINT_RULES = {"ST-001", "ST-004"}


def evaluate_endpoint(inp: RuleInput, extra_rules: bool = False) -> List[RuleHit]:
    hits: List[RuleHit] = []
    for rule in ENDPOINT_RULES:
        if not extra_rules and rule.id not in CORE_ENDPOINT_RULES:
            continue
        try:
            hit = rule.evaluate(inp)
        # One failing rule must not abort the whole rule set — but it must not vanish
        # either: a rule that raises every time is a silent detection gap.
        except Exception:  # nosec B112
            log.exception("rule_failed rule_id=%s path=%s", rule.id, rule_id_path(inp))
            continue
        if hit is not None:
            if hit.rule_id not in RULES_BY_ID:
                continue
            hits.append(hit)
    return hits


def lint_wording(status: str, rationale: str, limitations: str = "") -> List[str]:
    """Wording lint: suspected findings must hedge; nobody may overclaim."""
    problems: List[str] = []
    lowered = f"{rationale} {limitations}".lower()
    for phrase in CERTAINTY_PHRASES:
        if phrase in lowered:
            problems.append(f"certainty phrase in {status} finding: {phrase!r}")
    if status == "suspected":
        hedges = ("suspected", "may", "might", "could", "appears", "possible", "indicate", "suggest")
        if not any(hedge in lowered for hedge in hedges):
            problems.append("suspected finding lacks hedged wording")
    if not rationale.strip():
        problems.append("empty rationale")
    if not limitations.strip():
        problems.append("empty limitations")
    return problems


def rules_documentation() -> List[Dict[str, str]]:
    return [
        {
            "id": rule.id,
            "title": rule.title,
            "category": rule.category,
            "severity": rule.severity,
            "confidence": rule.confidence,
            "status": rule.status,
            "description": rule.description,
        }
        for rule in ENDPOINT_RULES
    ]


def finalize_hit(hit: RuleHit) -> DependencyMeta:
    """Attach the computed risk score and validate wording before persistence."""
    problems = lint_wording(hit.status, hit.rationale, hit.limitations)
    if problems:
        raise ValueError("; ".join(problems))
    return DependencyMeta(score=risk_score(hit.severity, hit.confidence, hit.exposure))


@dataclass(frozen=True)
class DependencyMeta:
    score: float


def sanitize_snippet(text: str) -> str:
    return make_snippet(redact_text(text))
