"""Deterministic fixtures for the round-8 injection/authorization rules (ST-018…ST-023).

Each test states the finding it expects, and each rule also has at least one
*false-positive* case (input that resembles the pattern but must stay silent) and one
*false-negative guard* (a case that must fire that a naive substring check would miss).
The fixtures are hand-written literals: no network, no random data, no lab process.
"""
from __future__ import annotations

from typing import Dict

import pytest

from app.engine.rules import (
    ENDPOINT_RULES,
    RULES_BY_ID,
    evaluate_endpoint,
    lint_wording,
    rules_documentation,
)
from app.engine.types import RuleInput


def _input(**overrides) -> RuleInput:
    payload: Dict[str, object] = dict(
        endpoint_method="GET",
        endpoint_path="/lab/thing",
        endpoint_url="https://app.example.test/lab/thing",
        classification="shadow",
        status_code=200,
        headers={"content-type": "application/json"},
        body_text="",
        content_type="application/json",
        discovered_from=["crawl"],
        target_scheme="https",
        documented=False,
        baseline_protected=False,
        soft_404_match=False,
        path_has_auth_hint=False,
    )
    payload.update(overrides)
    return RuleInput(**payload)  # type: ignore[arg-type]


def hits(rule_id: str, inp: RuleInput) -> int:
    return len([hit for hit in evaluate_endpoint(inp, extra_rules=True) if hit.rule_id == rule_id])


def one(rule_id: str, inp: RuleInput):
    matches = [hit for hit in evaluate_endpoint(inp, extra_rules=True) if hit.rule_id == rule_id]
    assert len(matches) == 1, f"expected exactly one {rule_id} hit, got {len(matches)}"
    return matches[0]


def test_injection_rules_do_not_fire_by_default():
    inp = _input(
        headers={"set-cookie": "session=123", "content-type": "text/html"},
        body_text="<script>alert(1)</script>",
    )
    default_hits = evaluate_endpoint(inp, extra_rules=False)
    assert not any(h.rule_id in {"ST-018", "ST-019", "ST-020", "ST-021", "ST-022", "ST-023"} for h in default_hits)


# ---------------------------------------------------------------------------
# ST-018 — cookie flags
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "cookie",
    [
        "lab_session=abc; Path=/",
        "lab_session=abc; Path=/; Secure",
        "lab_session=abc; Path=/; HttpOnly",
        "lab_session=abc; Path=/; SameSite=Lax",
    ],
)
def test_st018_fires_when_a_flag_is_missing(cookie: str) -> None:
    inp = _input(
        headers={"set-cookie": cookie, "content-type": "text/html"},
        content_type="text/html",
        target_scheme="http",
    )
    hit = one("ST-018", inp)
    assert hit.severity == "medium"
    assert hit.status == "confirmed"


def test_st018_false_positive_fully_flagged_cookie() -> None:
    inp = _input(
        headers={"set-cookie": "sid=abc; Path=/; Secure; HttpOnly; SameSite=Strict"},
        target_scheme="http",
    )
    assert hits("ST-018", inp) == 0


def test_st018_false_positive_cookie_over_https_without_flags() -> None:
    """Over TLS a missing `Secure` alone is a hardening note, not a finding."""
    inp = _input(headers={"set-cookie": "sid=abc; Path=/; HttpOnly"}, target_scheme="https")
    assert hits("ST-018", inp) == 0


def test_st018_false_negative_flag_names_are_case_insensitive() -> None:
    inp = _input(
        headers={"set-cookie": "sid=abc; Path=/; secure"},
        target_scheme="http",
    )
    assert hits("ST-018", inp) == 1


# ---------------------------------------------------------------------------
# ST-019 — reflected markup
# ---------------------------------------------------------------------------
def test_st019_fires_on_reflected_script_tag() -> None:
    inp = _input(
        endpoint_path="/lab/xss/echo",
        content_type="text/html",
        headers={"content-type": "text/html"},
        body_text="<p>You searched for: <script>alert(1)</script></p>",
    )
    hit = one("ST-019", inp)
    assert hit.status == "suspected", "reflection alone is not proof of execution"
    excerpt = str((hit.evidence.get("response") or {}).get("body_excerpt") or "").lower()
    assert "script" in excerpt


@pytest.mark.parametrize("marker", ["<svg onload=alert(1)>", "javascript:alert(1)", "<img onerror=x>"])
def test_st019_fires_on_other_executable_reflections(marker: str) -> None:
    inp = _input(
        content_type="text/html",
        headers={"content-type": "text/html"},
        body_text=f"<div>result: {marker}</div>",
    )
    assert hits("ST-019", inp) == 1


def test_st019_false_positive_json_body() -> None:
    inp = _input(body_text='{"echo": "<script>alert(1)</script>"}', content_type="application/json")
    assert hits("ST-019", inp) == 0


def test_st019_false_positive_error_status() -> None:
    """A 500 page that echoes input back says nothing about rendering of real results."""
    inp = _input(
        status_code=500,
        content_type="text/html",
        headers={"content-type": "text/html"},
        body_text="<pre>error near <script></pre>",
    )
    assert hits("ST-019", inp) == 0


def test_st019_false_positive_encoded_output() -> None:
    inp = _input(
        content_type="text/html",
        headers={"content-type": "text/html"},
        body_text="<p>You searched for: &lt;script&gt;alert(1)&lt;/script&gt;</p>",
    )
    assert hits("ST-019", inp) == 0


# ---------------------------------------------------------------------------
# ST-020 — database error text
# ---------------------------------------------------------------------------
def test_st020_fires_on_sqlite_error() -> None:
    inp = _input(
        endpoint_path="/lab/sqli/product",
        status_code=500,
        body_text='{"error":"SQLITE_ERROR: near \\"1\'\\": syntax error"}',
    )
    hit = one("ST-020", inp)
    assert hit.severity == "high"
    assert hit.status == "suspected"


@pytest.mark.parametrize(
    "text",
    [
        "psycopg2.errors.SyntaxError: syntax error at or near None",
        "ORA-00933: SQL command not properly ended",
        "You have an error in your SQL syntax; check the manual for your MySQL server",
        "Unclosed quotation mark after the character string",
    ],
)
def test_st020_fires_on_each_engine(text: str) -> None:
    assert hits("ST-020", _input(status_code=500, body_text=text)) == 1


def test_st020_false_positive_successful_response() -> None:
    """A 200 body that merely mentions SQL is not a database error."""
    inp = _input(status_code=200, body_text='{"message":"SELECT statement executed in 4ms"}')
    assert hits("ST-020", inp) == 0


def test_st020_false_positive_client_error_without_engine_text() -> None:
    inp = _input(status_code=400, body_text='{"error":"invalid id"}')
    assert hits("ST-020", inp) == 0


# ---------------------------------------------------------------------------
# ST-021 — path traversal
# ---------------------------------------------------------------------------
def test_st021_fires_on_passwd_content() -> None:
    inp = _input(
        endpoint_path="/lab/files/download",
        body_text="root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n",
        content_type="text/plain",
        headers={"content-type": "text/plain"},
    )
    hit = one("ST-021", inp)
    assert hit.severity == "high"
    assert hit.status == "suspected"


@pytest.mark.parametrize("marker", ["[fonts]", "; for 16-bit app support"])
def test_st021_fires_on_windows_ini_content(marker: str) -> None:
    assert hits("ST-021", _input(body_text=f"{marker}\r\n")) == 1


def test_st021_false_positive_404() -> None:
    inp = _input(status_code=404, body_text="root:x:0:0:root:/root:/bin/sh")
    assert hits("ST-021", inp) == 0


def test_st021_false_positive_documentation_mention() -> None:
    inp = _input(body_text="Never allow '../' sequences in a file parameter.")
    assert hits("ST-021", inp) == 0


# ---------------------------------------------------------------------------
# ST-022 — open redirect
# ---------------------------------------------------------------------------
def test_st022_fires_on_absolute_location() -> None:
    inp = _input(
        status_code=302,
        headers={"location": "https://evil.example/landing"},
        content_type="text/html",
    )
    hit = one("ST-022", inp)
    assert hit.severity == "medium"


def test_st022_false_positive_relative_location() -> None:
    inp = _input(status_code=302, headers={"location": "/lab/landing"})
    assert hits("ST-022", inp) == 0


def test_st022_false_positive_non_redirect_status() -> None:
    inp = _input(status_code=200, headers={"location": "https://evil.example/"})
    assert hits("ST-022", inp) == 0


def test_st022_false_negative_header_lookup_is_case_insensitive() -> None:
    inp = _input(status_code=301, headers={"Location": "http://elsewhere.example/"})
    assert hits("ST-022", inp) == 1


# ---------------------------------------------------------------------------
# ST-023 — sequential identifier without authentication
# ---------------------------------------------------------------------------
def test_st023_fires_on_anonymous_numeric_object() -> None:
    inp = _input(endpoint_path="/lab/idor/account/1002", status_code=200)
    hit = one("ST-023", inp)
    assert hit.severity == "high"
    assert hit.confidence == "low", "a numeric id alone is a review prompt"


def test_st023_false_positive_when_auth_is_required() -> None:
    inp = _input(endpoint_path="/api/v1/users/1234", status_code=401)
    assert hits("ST-023", inp) == 0


def test_st023_false_positive_on_session_scoped_paths() -> None:
    inp = _input(endpoint_path="/api/v1/accounts/1234/session", path_has_auth_hint=True)
    assert hits("ST-023", inp) == 0


def test_st023_false_positive_short_identifier() -> None:
    """`/v1` and `/v2` are version segments, not object ids."""
    inp = _input(endpoint_path="/api/v1/reports", status_code=200)
    assert hits("ST-023", inp) == 0


# ---------------------------------------------------------------------------
# registry invariants for the six new rules
# ---------------------------------------------------------------------------
NEW_RULES = ("ST-018", "ST-019", "ST-020", "ST-021", "ST-022", "ST-023")


@pytest.mark.parametrize("rule_id", NEW_RULES)
def test_new_rules_are_registered_with_documentation(rule_id: str) -> None:
    rule = RULES_BY_ID[rule_id]
    assert rule.severity in {"info", "low", "medium", "high", "critical"}
    assert rule.confidence in {"low", "medium", "high", "confirmed"}
    assert rule.status in {"confirmed", "suspected"}
    assert rule.description
    assert rule_id in {row["id"] for row in rules_documentation()}


@pytest.mark.parametrize("rule_id", NEW_RULES)
def test_new_rules_use_hedged_wording(rule_id: str) -> None:
    """`suspected` findings must not assert certainty, and the linter must pass on them."""
    RULES_BY_ID[rule_id]  # registry must contain the rule under test
    sample = {
        "ST-018": _input(headers={"set-cookie": "a=b"}, target_scheme="http"),
        "ST-019": _input(
            content_type="text/html", headers={"content-type": "text/html"}, body_text="<script>"
        ),
        "ST-020": _input(status_code=500, body_text="SQLITE_ERROR"),
        "ST-021": _input(body_text="root:x:0:0:"),
        "ST-022": _input(status_code=302, headers={"location": "https://x.example/"}),
        "ST-023": _input(endpoint_path="/obj/4242"),
    }[rule_id]
    hit = one(rule_id, sample)
    assert lint_wording(hit.status, hit.rationale, hit.limitations) == []


def test_rule_ids_are_unique_and_documented() -> None:
    ids = [rule.id for rule in ENDPOINT_RULES]
    assert len(ids) == len(set(ids))
    assert "ST-023" in ids

