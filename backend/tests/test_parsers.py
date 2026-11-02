"""Parser hardening tests: untrusted documents must fail closed, never expand."""
from __future__ import annotations

import pytest

from app.engine.parsers import (
    MAX_DOCUMENT_BYTES,
    UnsafeDocument,
    check_size,
    json_depth,
    parse_yaml_or_json,
    safe_json_load,
    safe_xml_fromstring,
    safe_yaml_load,
)


def test_size_cap_counts_utf8_bytes():
    check_size(b"x" * 10)
    check_size("x" * 10)
    with pytest.raises(UnsafeDocument):
        check_size(b"x" * (MAX_DOCUMENT_BYTES + 1))
    # Multi-byte characters count by encoded size, not character count.
    with pytest.raises(UnsafeDocument):
        check_size("\u20ac" * (MAX_DOCUMENT_BYTES // 2))  # 3 bytes each


def test_json_parses_and_rejects_invalid():
    assert safe_json_load('{"a": [1, 2]}') == {"a": [1, 2]}
    with pytest.raises(UnsafeDocument):
        safe_json_load("{not json")


def test_json_depth_is_capped():
    deep: object = "leaf"
    for _ in range(60):
        deep = {"n": deep}
    with pytest.raises(UnsafeDocument):
        safe_json_load(__import__("json").dumps(deep))
    shallow = {"a": {"b": {"c": 1}}}
    assert json_depth(shallow) == 4


def test_json_depth_helper_stops_early():
    value: object = 1
    for _ in range(1000):
        value = [value]
    # The helper short-circuits once MAX_JSON_DEPTH is exceeded instead of recursing forever.
    assert json_depth(value) > 40


def test_yaml_rejects_alias_bomb():
    # Many anchors, each referenced repeatedly: the classic expansion shape.
    lines = [f"k{index}: &a{index} [x]" for index in range(60)]
    lines += [f"r{index}: [*a0, *a1, *a2, *a3, *a4, *a5]" for index in range(60)]
    with pytest.raises(UnsafeDocument):
        safe_yaml_load("\n".join(lines))


def test_yaml_rejects_deep_nesting():
    lines = []
    for index in range(60):
        lines.append("  " * index + f"k{index}:")
    lines.append("  " * 60 + "leaf: 1")
    with pytest.raises(UnsafeDocument):
        safe_yaml_load("\n".join(lines))


def test_yaml_rejects_python_object_tags():
    with pytest.raises(UnsafeDocument):
        safe_yaml_load("!!python/object/apply:os.system ['echo hi']")


def test_yaml_mapping_roundtrip():
    assert safe_yaml_load("openapi: 3.0.0\npaths: {}\n") == {"openapi": "3.0.0", "paths": {}}


def test_xml_rejects_doctype_and_entities():
    with pytest.raises(UnsafeDocument):
        safe_xml_fromstring(
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<foo>&xxe;</foo>"
        )
    with pytest.raises(UnsafeDocument):
        safe_xml_fromstring('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY a "aaaa">]><foo>&a;</foo>')


def test_xml_rejects_billion_laughs_shape():
    laughs = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>'
        "<lolz>&lol2;</lolz>"
    )
    with pytest.raises(UnsafeDocument):
        safe_xml_fromstring(laughs)


def test_xml_rejects_nesting_bomb():
    depth = 80
    body = "<a>" * depth + "x" + "</a>" * depth
    with pytest.raises(UnsafeDocument):
        safe_xml_fromstring(body)


def test_xml_accepts_namespaced_sitemap():
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        "<url><loc>https://example.test/api/v1/users</loc></url></urlset>"
    )
    root = safe_xml_fromstring(body)
    assert root.tag.endswith("urlset")


def test_parse_yaml_or_json_prefers_json_then_yaml():
    assert parse_yaml_or_json('{"openapi": "3.0.0"}') == {"openapi": "3.0.0"}
    assert parse_yaml_or_json("openapi: 3.0.0\n") == {"openapi": "3.0.0"}
    assert parse_yaml_or_json("") is None
    assert parse_yaml_or_json("{broken") is None
