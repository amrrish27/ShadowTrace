"""HAR 1.2 import.

HAR is the primary traffic source.  Entries are redacted at import time — before
anything is persisted — and entries outside the authorized scope are counted and
dropped.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from urllib.parse import urlsplit

from ...security.redaction import make_snippet, redact_har_entry
from ..parsers import UnsafeDocument, safe_json_load
from ..types import DiscoveredEndpoint, ExtractionResult

MAX_HAR_ENTRIES = 5000
MAX_HAR_BYTES = 8 * 1024 * 1024


@dataclass
class HarImport:
    result: ExtractionResult
    entries_total: int = 0
    entries_in_scope: int = 0
    entries_out_of_scope: int = 0
    entries_dropped: int = 0
    redacted_entries: List[Dict[str, Any]] = field(default_factory=list)


def _is_scope(host: str, allowed_hosts: Tuple[str, ...], policy_hosts: Tuple[str, ...]) -> bool:
    normalized = host.lower().strip(".")
    for candidate in policy_hosts:
        if normalized == candidate or normalized.endswith("." + candidate):
            return True
    return False


def parse_har(
    text: str,
    *,
    source_name: str,
    base_url: str,
    policy_hosts: Tuple[str, ...],
) -> HarImport:
    result = ExtractionResult()
    try:
        document = safe_json_load(text) if len(text) <= MAX_HAR_BYTES else None
    except UnsafeDocument:
        document = None
    if not isinstance(document, dict):
        result.notes.append("har_invalid")
        return HarImport(result=result)
    log = document.get("log")
    entries = (log or {}).get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        result.notes.append("har_missing_entries")
        return HarImport(result=result)
    total = len(entries)
    in_scope = 0
    out_scope = 0
    dropped = 0
    redacted: List[Dict[str, Any]] = []
    for entry_index, entry in enumerate(entries[:MAX_HAR_ENTRIES]):
        if not isinstance(entry, dict):
            dropped += 1
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            dropped += 1
            continue
        raw_url = str(request.get("url", ""))
        method = str(request.get("method", "GET")).upper()[:10]
        try:
            parts = urlsplit(raw_url)
        except ValueError:
            dropped += 1
            continue
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            dropped += 1
            continue
        if not _is_scope(parts.hostname, tuple(), policy_hosts):
            out_scope += 1
            continue
        in_scope += 1
        result.endpoints.append(
            DiscoveredEndpoint(
                method=method if method in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"} else "GET",
                path=parts.path or "/",
                query=parts.query,
                source_type="har",
                source_url=f"har:{source_name}",
                location=f"entry {entry_index}",
                snippet=make_snippet(raw_url),
                extractor="har_entry",
                confidence=0.95,
                base_url=f"{parts.scheme}://{parts.netloc}",
            )
        )
        if len(redacted) < 200:
            redacted.append(redact_har_entry(entry))
    result.notes.append(f"har_entries:{total}")
    return HarImport(
        result=result,
        entries_total=total,
        entries_in_scope=in_scope,
        entries_out_of_scope=out_scope,
        entries_dropped=dropped,
        redacted_entries=redacted,
    )
