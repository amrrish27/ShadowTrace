"""Scope policy and validator tests (soft-404, circuit breaker, method gate).

No network is used: the validator is driven by a stub client that returns
prepared ``ResponseData`` objects.
"""
from __future__ import annotations


from app.engine.safe_http import (
    BlockedRequest,
    BudgetExceeded,
    ResponseData,
    ResponseTimeout,
    ResponseTooLarge,
    TargetRequestError,
)
from app.engine.scope import ScopePolicy, filter_in_scope, is_in_scope
from app.engine.validator import (
    MAX_CONSECUTIVE_ERRORS,
    Soft404Probe,
    Validator,
)


def _response(status: int = 200, body: str = "{}", headers=None, url: str = "https://app.example.test/x") -> ResponseData:
    merged = {"content-type": "application/json"}
    merged.update(headers or {})
    return ResponseData(url=url, status=status, headers=merged, body=body.encode(), elapsed_ms=3)


class StubClient:
    """Returns queued responses/exceptions and records every request."""

    def __init__(self, items):
        self.items = list(items)
        self.calls = []

    def request(self, method, url):
        self.calls.append((method, url))
        item = self.items.pop(0) if self.items else _response()
        if isinstance(item, Exception):
            raise item
        return item


# ---------------------------------------------------------------- scope


def test_scope_host_port_and_prefix():
    policy = ScopePolicy.build(host="app.example.test", ports=[443, 8443], path_prefixes=["/api"])
    assert policy.host_in_scope("APP.example.test.")
    assert not policy.host_in_scope("evil.example.test")
    assert policy.port_in_scope(8443)
    assert not policy.port_in_scope(80)
    assert policy.path_in_scope("/api/v1/users")
    assert policy.path_in_scope("/api")
    assert not policy.path_in_scope("/apiary")
    assert not policy.path_in_scope("/admin")


def test_scope_wildcards_are_explicit_subdomains_only():
    policy = ScopePolicy.build(host="app.example.test", ports=[443], wildcard_parents=["app.example.test"])
    assert policy.host_in_scope("api.app.example.test")
    assert not policy.host_in_scope("app.example.test.evil.net")
    assert not policy.host_in_scope("evilapp.example.test")


def test_scope_check_reasons():
    policy = ScopePolicy.build(host="app.example.test", ports=[443], path_prefixes=["/api"])
    assert policy.check(__import__("app.engine.urlguard", fromlist=["canonicalize"]).canonicalize("https://api.example.test/x")) == (
        False,
        "host_out_of_scope",
    )
    assert policy.check(__import__("app.engine.urlguard", fromlist=["canonicalize"]).canonicalize("https://app.example.test:8443/api/x")) == (
        False,
        "port_out_of_scope",
    )
    assert policy.check(__import__("app.engine.urlguard", fromlist=["canonicalize"]).canonicalize("https://app.example.test/admin")) == (
        False,
        "path_out_of_scope",
    )
    assert policy.check(__import__("app.engine.urlguard", fromlist=["canonicalize"]).canonicalize("https://app.example.test/api/v1")) == (True, "")


def test_scope_helpers_tolerate_bad_urls():
    policy = ScopePolicy.build(host="app.example.test", ports=[443])
    assert is_in_scope(policy, "https://app.example.test/api/v1")
    assert not is_in_scope(policy, "not a url")
    assert filter_in_scope(
        policy, ["https://app.example.test/a", "https://other.test/b", "javascript:alert(1)"]
    ) == ["https://app.example.test/a"]


# ---------------------------------------------------------------- soft-404


def test_soft_404_detects_and_matches_catch_all_shell():
    shell = "<html><body><div id='app'>Loading…</div></body></html>"
    client = StubClient([_response(200, shell)])
    probe = Soft404Probe(client=client, base_url="https://app.example.test")
    probe.detect()
    assert probe.detected
    assert probe.sample_url.startswith("https://app.example.test/st-nonexistent-")
    assert probe.matches(_response(200, shell))
    # A materially different, larger document is not the shell.
    assert not probe.matches(_response(200, shell + "<script>/*" + "x" * 4000 + "*/</script>"))
    # 404s never match.
    assert not probe.matches(_response(404, shell))


def test_soft_404_is_not_detected_when_probe_fails():
    probe = Soft404Probe(client=StubClient([TargetRequestError()]), base_url="https://app.example.test")
    probe.detect()
    assert not probe.detected
    assert not probe.matches(_response(200, "<html>anything</html>"))


def test_soft_404_ignores_digits_when_comparing():
    shell = "<html><body>item 1 of 3</body></html>"
    probe = Soft404Probe(client=StubClient([_response(200, shell)]), base_url="https://app.example.test")
    probe.detect()
    assert probe.matches(_response(200, "<html><body>item 9 of 9</body></html>"))


# ---------------------------------------------------------------- validator


def test_validator_status_mapping():
    client = StubClient(
        [
            _response(200, '{"ok": true}'),
            _response(401),
            _response(403),
            _response(404),
            _response(410),
            _response(302),
            _response(204),
            _response(500),
        ]
    )
    validator = Validator(client)
    assert validator.validate("GET", "https://app.example.test/a").status == "live"
    assert validator.validate("GET", "https://app.example.test/b").status == "auth_required"
    assert validator.validate("GET", "https://app.example.test/c").status == "auth_required"
    assert validator.validate("GET", "https://app.example.test/d").status == "not_found"
    assert validator.validate("GET", "https://app.example.test/e").status == "not_found"
    assert validator.validate("GET", "https://app.example.test/f").status == "redirected"
    assert validator.validate("GET", "https://app.example.test/g").status == "live"
    outcome = validator.validate("GET", "https://app.example.test/h")
    assert outcome.status == "error"
    assert validator.stats.errors == 1


def test_validator_only_sends_safe_methods():
    client = StubClient([])
    validator = Validator(client)
    outcome = validator.validate("POST", "https://app.example.test/api/v1/users")
    assert outcome.status == "unvalidated"
    assert outcome.error == "method_not_allowed_for_safe_validation"
    assert client.calls == []
    assert validator.stats.skipped == 1


def test_validator_circuit_breaker_opens_after_repeated_errors():
    client = StubClient([TargetRequestError() for _ in range(MAX_CONSECUTIVE_ERRORS + 3)])
    validator = Validator(client)
    for _ in range(MAX_CONSECUTIVE_ERRORS):
        assert validator.validate("GET", "https://app.example.test/x").status == "error"
    outcome = validator.validate("GET", "https://app.example.test/x")
    assert outcome.status == "skipped_budget"
    assert outcome.error == "circuit_breaker_open"
    assert validator.stats.circuit_open
    # The breaker short-circuits: no further request is attempted.
    assert len(client.calls) == MAX_CONSECUTIVE_ERRORS


def test_validator_success_resets_the_breaker():
    client = StubClient([TargetRequestError(), TargetRequestError(), _response(200), TargetRequestError()])
    validator = Validator(client)
    validator.validate("GET", "https://app.example.test/a")
    validator.validate("GET", "https://app.example.test/b")
    assert validator.consecutive_errors == 2
    validator.validate("GET", "https://app.example.test/c")
    assert validator.consecutive_errors == 0


def test_validator_budget_and_policy_errors_are_distinct():
    client = StubClient([BudgetExceeded(), BlockedRequest("blocked_address"), ResponseTimeout(), ResponseTooLarge()])
    validator = Validator(client)
    budget = validator.validate("GET", "https://app.example.test/a")
    assert budget.status == "skipped_budget" and budget.error == "request_budget_exhausted"
    blocked = validator.validate("GET", "https://app.example.test/b")
    assert blocked.status == "blocked" and blocked.error == "policy_blocked"
    assert validator.stats.blocked == 1
    assert validator.validate("GET", "https://app.example.test/c").status == "error"
    assert validator.validate("GET", "https://app.example.test/d").status == "error"


def test_validator_applies_soft_404_verdict():
    shell = "<html><body>shell</body></html>"
    probe = Soft404Probe(client=StubClient([_response(200, shell)]), base_url="https://app.example.test")
    probe.detect()
    validator = Validator(StubClient([_response(200, shell)]), soft404=probe)
    outcome = validator.validate("GET", "https://app.example.test/api/v1/fake")
    assert outcome.status == "not_found"
    assert outcome.soft_404_match is True
    assert validator.stats.live == 0


def test_validator_backoff_uses_injected_sleep():
    sleeps = []
    client = StubClient([_response(429), _response(503)])
    validator = Validator(client, backoff_seconds=0.5, sleep=sleeps.append)
    validator.validate("GET", "https://app.example.test/a")
    validator.validate("GET", "https://app.example.test/b")
    assert sleeps == [1.0, 2.0]
