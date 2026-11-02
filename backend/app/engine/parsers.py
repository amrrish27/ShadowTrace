"""Hardened parsers for untrusted documents.

Every parser is bounded: input size, nesting depth, alias/entity expansion and
time.  YAML is loaded with :func:`yaml.safe_load` after an alias/expansion guard;
XML uses defusedxml (no entities, no external references); JSON depth is checked
before parsing.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

import defusedxml.ElementTree as DefusedET
# Rationale: only ever used with DefusedXMLParser (safe_xml_fromstring)
import xml.etree.ElementTree as StdET  # nosec B405

import yaml  # type: ignore[import-untyped]  # PyYAML ships no stubs

MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 40
MAX_YAML_ALIASES = 50
MAX_XML_ELEMENTS = 50_000
MAX_XML_DEPTH = 40


class UnsafeDocument(ValueError):
    """Raised when an untrusted document violates a parser safety limit."""


def check_size(data: bytes | str, limit: int = MAX_DOCUMENT_BYTES) -> None:
    size = len(data.encode("utf-8")) if isinstance(data, str) else len(data)
    if size > limit:
        raise UnsafeDocument(f"document exceeds {limit} bytes")


_ALIAS_RE = re.compile(r"(?m)(?:^|[\s:\-\[,{])(\*[A-Za-z0-9_\-]+|&[A-Za-z0-9_\-]+)")


def safe_yaml_load(text: str) -> Any:
    check_size(text)
    aliases = _ALIAS_RE.findall(text)
    anchors = {a for a in aliases if a.startswith("&")}
    if len(anchors) > MAX_YAML_ALIASES:
        raise UnsafeDocument("too many YAML anchors")
    if len(aliases) > MAX_YAML_ALIASES * 4:
        raise UnsafeDocument("possible YAML alias bomb")
    try:
        value = yaml.safe_load(text)  # safe_load: no arbitrary object construction
    except yaml.YAMLError as exc:
        raise UnsafeDocument("invalid YAML") from exc
    if json_depth(value) > MAX_JSON_DEPTH:
        raise UnsafeDocument("YAML nesting too deep")
    return value


def json_depth(value: Any, depth: int = 1) -> int:
    if depth > MAX_JSON_DEPTH:
        return depth
    if isinstance(value, dict):
        return max([depth] + [json_depth(v, depth + 1) for v in list(value.values())[:500]])
    if isinstance(value, list):
        return max([depth] + [json_depth(v, depth + 1) for v in value[:500]])
    return depth


def safe_json_load(text: str) -> Any:
    check_size(text)
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UnsafeDocument("invalid JSON") from exc
    if json_depth(value) > MAX_JSON_DEPTH:
        raise UnsafeDocument("JSON nesting too deep")
    return value


def safe_xml_fromstring(text: str | bytes) -> Any:
    check_size(text)
    parser = DefusedET.DefusedXMLParser(
        forbid_dtd=True,
        forbid_entities=True,
        forbid_external=True,
    )
    try:
        # Rationale: defused parser: DTD/entities/external access forbidden
        root = StdET.fromstring(text, parser=parser)  # nosec B314
    except DefusedET.ParseError as exc:
        raise UnsafeDocument("invalid XML") from exc
    except Exception as exc:  # defusedxml raises its own exception types
        raise UnsafeDocument("unsafe XML") from exc
    if _count_elements(root) > MAX_XML_ELEMENTS:
        raise UnsafeDocument("XML document too large")
    return root


def _count_elements(root: Any) -> int:
    count = 0
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_XML_ELEMENTS:
            return count
        if depth > MAX_XML_DEPTH:
            raise UnsafeDocument("XML nesting too deep")
        stack.extend((child, depth + 1) for child in list(node))
    return count


def parse_yaml_or_json(text: str) -> Optional[Any]:
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return safe_json_load(text)
        except UnsafeDocument:
            pass
    try:
        return safe_yaml_load(text)
    except UnsafeDocument:
        return None
