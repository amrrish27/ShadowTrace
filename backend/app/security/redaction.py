"""Central redaction.  Every value that leaves the scanner (DB, logs, exports, UI)
passes through this module.  Pattern-based and deterministic; never validates or
uses a credential.
"""
from __future__ import annotations

import functools

import re
from typing import Any, Dict, Iterable, List, Mapping, Tuple

REDACTED = "[REDACTED]"
MAX_SNIPPET = 240

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "api-key",
    "apikey",
    "x-amz-security-token",
}

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "refresh_token",
    "id_token",
    "token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "sig",
    "signature",
    "auth",
    "session",
    "sessionid",
}

SENSITIVE_JSON_KEYS = SENSITIVE_QUERY_KEYS | {
    "authorization",
    "cookie",
    "credit_card",
    "cvv",
    "ssn",
    "private_key",
}

# (kind, compiled pattern).  Order matters: most specific first.
_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\b")),
    ("bearer", re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=\-]{8,}")),
    ("url_userinfo", re.compile(r"(?i)\b(https?://)[^/\s:@]{1,64}:[^/\s@]{1,64}@")),
    ("basic_auth_url", re.compile(r"(?i)\b(?:https?|ftp)://[^/\s@]+:[^/\s@]+@")),
    ("generic_secret_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|password|passwd|token|access[_-]?key)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"
    )),
]

_QUERY_RE = re.compile(r"([?&])([A-Za-z0-9_.\-\[\]]{1,40})=([^&#\s]{0,400})")


def _redact_match(kind: str, match: "re.Match[str]") -> str:
    """Replacement for one pattern family; URL userinfo keeps the username."""
    if kind == "url_userinfo":
        return f"{match.group(1)}{REDACTED}@"
    return f"[REDACTED:{kind}]"


def _mask_query(match: re.Match[str]) -> str:
    sep, key, _value = match.groups()
    if key.lower() in SENSITIVE_QUERY_KEYS:
        return f"{sep}{key}={REDACTED}"
    return match.group(0)


def redact_text(text: str) -> str:
    """Redact credential-shaped values and sensitive query parameters."""
    if not text:
        return ""
    out = text
    for kind, pattern in _PATTERNS:
        out = pattern.sub(functools.partial(_redact_match, kind), out)
    out = _QUERY_RE.sub(_mask_query, out)
    return out


def redact_headers(headers: Mapping[str, Any]) -> Dict[str, str]:
    redacted: Dict[str, str] = {}
    for raw_key, raw_value in list(headers.items())[:60]:
        key = str(raw_key)[:80]
        value = str(raw_value)[:1000]
        if key.lower().strip() in SENSITIVE_HEADERS:
            redacted[key] = REDACTED
        else:
            redacted[key] = redact_text(value)
    return redacted


def redact_value(value: Any, key_hint: str = "") -> Any:
    """Recursively redact a parsed JSON-like structure at sensitive keys."""
    if key_hint.lower() in SENSITIVE_JSON_KEYS:
        return REDACTED
    if isinstance(value, dict):
        return {str(k)[:100]: redact_value(v, str(k)) for k, v in list(value.items())[:200]}
    if isinstance(value, list):
        return [redact_value(v, key_hint) for v in value[:200]]
    if isinstance(value, str):
        return redact_text(value[:2000])
    return value


def redact_url(url: str) -> str:
    return redact_text(url)


def make_snippet(text: str, limit: int = MAX_SNIPPET) -> str:
    """One-line, bounded, redacted snippet for evidence and provenance."""
    if not text:
        return ""
    collapsed = " ".join(str(text).split())
    return redact_text(collapsed[:limit])


def contains_secret(text: str) -> bool:
    """True when a credential-shaped value is present (used by tests and evidence checks)."""
    return any(pattern.search(text or "") for _kind, pattern in _PATTERNS)


def secret_kinds(text: str) -> List[str]:
    return [kind for kind, pattern in _PATTERNS if pattern.search(text or "")]


def _header_pairs(raw: Any) -> Dict[str, str]:
    """Accept HAR header lists (name/value dicts) or an already flattened mapping."""
    if isinstance(raw, dict):
        return {str(k)[:80]: str(v)[:1000] for k, v in list(raw.items())[:60]}
    pairs: Dict[str, str] = {}
    if isinstance(raw, list):
        for item in raw[:60]:
            if isinstance(item, dict):
                pairs[str(item.get("name", ""))[:80]] = str(item.get("value", ""))[:1000]
            elif isinstance(item, str):
                name, _, value = item.partition(":")
                pairs[name.strip()[:80]] = value.strip()[:1000]
    return pairs


def redact_har_entry(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """Redact an imported HAR entry: headers, cookies, query strings and bodies."""
    request = dict(entry.get("request", {}) or {})
    response = dict(entry.get("response", {}) or {})
    out: Dict[str, Any] = {
        "startedDateTime": str(entry.get("startedDateTime", ""))[:40],
        "request": {
            "method": str(request.get("method", "GET"))[:10].upper(),
            "url": redact_url(str(request.get("url", ""))[:2048]),
            "headers": redact_headers(_header_pairs(request.get("headers", []))),
        },
        "response": {
            "status": int(response.get("status", 0) or 0),
            "headers": redact_headers(_header_pairs(response.get("headers", []))),
            "content": {
                "mimeType": str((response.get("content") or {}).get("mimeType", ""))[:100],
                "text": make_snippet(str((response.get("content") or {}).get("text", "")), 400),
            },
        },
    }
    return out


def audit_redact(details: Mapping[str, Any]) -> Dict[str, Any]:
    return {str(k)[:60]: redact_value(v, str(k)) for k, v in list(details.items())[:40]}


def redact_all(values: Iterable[str]) -> List[str]:
    return [redact_text(v) for v in values]
