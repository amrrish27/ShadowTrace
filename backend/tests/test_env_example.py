"""`.env.example` and `app/config.py` must describe the same configuration.

A documented variable that the code ignores is worse than no documentation: the
operator believes a control is on while the default applies. This module keeps the
reference file and the code honest in both directions, and pins the published
defaults for the limits the README quotes.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG = ROOT / "backend" / "app" / "config.py"
ENV_EXAMPLE = ROOT / ".env.example"

# Every helper in config.py that reads an environment variable. `_env_raw` reads secrets
# verbatim (no strip); `_env_bool_preferring` takes the legacy name as its second argument.
_READ_HELPERS = ("_env", "_env_raw", "_env_bool", "_env_bool_preferring", "_env_int", "_env_list")
_READ_RE = re.compile(r"(?P<helper>" + "|".join(_READ_HELPERS) + r")\(\s*\"(?P<name>[A-Z_][A-Z0-9_]*)\"")
_DEPRECATED_RE = re.compile(r"_env_bool_preferring\(\s*\"ST_SCANNING_ENABLED\",\s*\"(SCANNING_ENABLED)\"")


def _env_example() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in ENV_EXAMPLE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        # Strip a trailing comment, but only when it is separated by whitespace, so a
        # value that legitimately contains '#' survives.
        value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        if key:
            values[key] = value
    return values


def _read_names() -> set[str]:
    return {m.group("name") for m in _READ_RE.finditer(CONFIG.read_text())}


def test_every_documented_variable_is_read_by_config():
    unused = sorted(set(_env_example()) - _read_names())
    assert not unused, f".env.example documents variables config.py never reads: {unused}"


def test_every_variable_read_by_config_is_documented():
    undocumented = sorted(_read_names() - set(_env_example()))
    assert not undocumented, f"config.py reads variables missing from .env.example: {undocumented}"


def test_the_kill_switch_is_documented_under_its_real_name():
    documented = _env_example()
    assert "ST_SCANNING_ENABLED" in documented
    assert "SCANNING_ENABLED" not in documented, "the deprecated name must not be the documented one"


def test_the_legacy_name_only_appears_as_a_documented_fallback():
    assert _DEPRECATED_RE.search(CONFIG.read_text()), (
        "ST_SCANNING_ENABLED must fall back to the deprecated SCANNING_ENABLED via "
        "_env_bool_preferring so existing deployments keep their kill switch"
    )


def _eval(node: ast.AST) -> object:
    """Evaluate a literal or simple arithmetic default such as ``2 * 1024 * 1024``."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        return _eval(node.left) * _eval(node.right)  # type: ignore[operator]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
        return _eval(node.left) - _eval(node.right)  # type: ignore[operator]
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_eval(node.operand)  # type: ignore[operator]
    raise ValueError(f"not a literal: {ast.dump(node)}")


def _literal_defaults(helper: str) -> dict[str, object]:
    """Evaluate the literal default of every `helper("ST_X", <literal>)` call."""
    source = CONFIG.read_text()
    found: dict[str, object] = {}
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id != helper or len(node.args) < 2:
            continue
        first, second = node.args[0], node.args[1]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            continue
        try:
            found[first.value] = _eval(second)
        except (ValueError, SyntaxError, TypeError):
            continue  # a computed default (e.g. `env == "production"`) is not a published value
    return found


@pytest.mark.parametrize("name", ["ST_MAX_UPLOAD_BYTES", "ST_MAX_RESPONSE_BYTES", "ST_SCAN_CONCURRENCY_PER_ORG"])
def test_the_limits_quoted_in_the_docs_match_the_code(name):
    documented = _env_example()
    assert name in documented, f"{name} must be documented"
    code_default = _literal_defaults("_env_int")[name]
    assert int(documented[name]) == code_default, f"{name}: .env.example says {documented[name]}, code uses {code_default}"


def test_every_numeric_default_is_identical_between_the_docs_and_the_code():
    documented = _env_example()
    mismatches = {
        name: (documented.get(name), default)
        for name, default in _literal_defaults("_env_int").items()
        if name in documented and documented[name] != "" and int(documented[name]) != default
    }
    assert not mismatches, f"documented default differs from the code default: {mismatches}"


def test_boolean_defaults_are_identical_between_the_docs_and_the_code():
    documented = _env_example()
    truthy = {"1", "true", "yes", "on"}
    falsy = {"0", "false", "no", "off"}
    for name, default in _literal_defaults("_env_bool").items():
        if name not in documented or not documented[name]:
            continue
        raw = documented[name].lower()
        assert raw in truthy | falsy, f"{name} must be a boolean, got {documented[name]!r}"
        assert (raw in truthy) is default, f"{name}: .env.example says {documented[name]}, code default is {default}"


def test_the_deprecated_kill_switch_default_is_true():
    documented = _env_example()
    assert documented["ST_SCANNING_ENABLED"].lower() in {"1", "true", "yes", "on"}
