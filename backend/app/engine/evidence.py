"""Evidence capture helpers: snippets, header digests and safe reproduction commands."""
from __future__ import annotations

import re
from typing import Dict, Iterable, Mapping, Optional, Sequence

from ..security.redaction import make_snippet, redact_text

SAFE_REPRO_METHODS = {"GET", "HEAD", "OPTIONS"}
_SAFE_URL_RE = re.compile(r"^https?://[^\s'\"<>]{3,2048}$")


def repro_command(method: str, url: str) -> str:
    """A non-destructive reproduction command (GET/HEAD/OPTIONS only, redacted)."""
    upper = method.upper()
    if upper not in SAFE_REPRO_METHODS:
        return (
            f"# {upper} is not replayed: ShadowTrace only issues read-only requests "
            "(GET, HEAD, OPTIONS)."
        )
    cleaned = redact_text(url)
    if not _SAFE_URL_RE.match(cleaned):
        return "# Reproduction URL suppressed: it did not pass URL validation."
    return f"curl -sS -D - -o /dev/null -X {upper} '{cleaned}'"


def header_digest(headers: Mapping[str, str], keys: Optional[Iterable[str]] = None) -> Dict[str, str]:
    interesting = (
        list(keys)
        if keys
        else [
            "server",
            "x-powered-by",
            "content-type",
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "allow",
            "x-content-type-options",
            "content-security-policy",
            "strict-transport-security",
            "www-authenticate",
        ]
    )
    digest: Dict[str, str] = {}
    for key in interesting:
        value = headers.get(key) or headers.get(key.lower())
        if value:
            digest[key] = make_snippet(value, 200)
    return digest


def body_excerpt(text: str, patterns: Sequence[str] = (), limit: int = 300) -> str:
    """A short, redacted excerpt, preferring the region that matched a rule."""
    if not text:
        return ""
    lowered = text.lower()
    for pattern in patterns:
        index = lowered.find(pattern.lower())
        if index >= 0:
            start = max(0, index - 80)
            return make_snippet(text[start : start + limit], limit)
    return make_snippet(text, limit)


def evidence_block(
    *,
    method: str,
    url: str,
    status: Optional[int],
    headers: Mapping[str, str],
    body: str,
    patterns: Sequence[str] = (),
    extra: Optional[Mapping[str, object]] = None,
) -> Dict[str, object]:
    block: Dict[str, object] = {
        "request": {"method": method.upper(), "url": redact_text(url)},
        "response": {
            "status": status,
            "headers": header_digest(headers),
            "body_excerpt": body_excerpt(body, patterns),
        },
        "reproduction": repro_command(method, url),
        "captured": "live response from the authorized target",
    }
    if extra:
        block.update({k: v for k, v in extra.items() if k not in block})
    return block
