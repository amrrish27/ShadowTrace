"""Source map discovery and extraction.

Source maps are found through ``sourceMappingURL`` comments and
``SourceMap``/``X-SourceMap`` headers.  Maps are parsed in memory only; a
``sources`` entry is *never* mapped to a filesystem path (there is no filesystem
access in this module at all) and remote references are not fetched.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional

from ..parsers import UnsafeDocument, safe_json_load
from ..types import DiscoveredEndpoint, ExtractionResult
from .js_extract import extract_javascript

MAX_MAP_BYTES = 5 * 1024 * 1024
MAX_MAP_PARSE_SECONDS = 10.0
_COMMENT_RE = re.compile(r"(?://[#@]\s*sourceMappingURL=|\/\*[#@]\s*sourceMappingURL=)([^\s*'\"]{1,500})")
_DATA_URI_PREFIX = "data:application/json;base64,"


def find_source_map_reference(body: str, content_type: str = "") -> Optional[str]:
    trailing = body[-4096:]
    match = _COMMENT_RE.search(trailing)
    if match:
        return match.group(1)
    # No comment reference: an inline source map is handled by the caller, not here.
    return None


def source_map_header(headers: Dict[str, str]) -> Optional[str]:
    for key in ("sourcemap", "x-sourcemap"):
        value = headers.get(key, "")
        if value:
            return value.strip()[:500]
    return None


def extraction_from_map(
    map_text: str,
    map_url: str,
    base_url: str,
    *,
    source_type: str = "source_map",
) -> ExtractionResult:
    result = ExtractionResult()
    if len(map_text) > MAX_MAP_BYTES:
        return result
    try:
        data = safe_json_load(map_text)
    except UnsafeDocument:
        return result
    if not isinstance(data, dict):
        return result
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if isinstance(sources, list) and any(isinstance(s, str) and ".." in s for s in sources[:2000]):
        result.notes.append("source_map_traversal_strings_ignored")
    file_name = str(data.get("file", "") or "")
    if file_name and not any(ch in file_name for ch in "\x00\\"):
        result.notes.append("source_map_target:" + file_name[:120])
    parse_start = time.monotonic()
    if isinstance(contents, list):
        for index, content in enumerate(contents[:200]):
            if time.monotonic() - parse_start > MAX_MAP_PARSE_SECONDS:
                result.notes.append("source_map_parse_timeout")
                break
            if not isinstance(content, str) or not content:
                continue
            label = (
                str(sources[index])[:120]
                if isinstance(sources, list) and index < len(sources)
                else f"source[{index}]"
            )
            extracted = extract_javascript(
                content,
                map_url,
                base_url,
                location_prefix=f"sourcemap:{label}",
                source_type=source_type,
            )
            result.endpoints.extend(extracted.endpoints)
            result.notes.extend(extracted.notes[:5])
    if not result.endpoints:
        result.notes.append("source_map_parsed_without_content")
    return result


def public_source_map_note(headers: Dict[str, str], map_url: str) -> List[DiscoveredEndpoint]:
    return []
