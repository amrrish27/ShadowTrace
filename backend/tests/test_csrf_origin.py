"""CSRF origin verification: the app's own origin must be accepted, nothing else.

Regression origin: `POST /api/v1/targets` from the UI returned 403 `csrf_failed`
("The request could not be verified.") when the app was opened at
`http://127.0.0.1:8000` — the origin the README quick start tells the operator to use.

Cause: `authenticate()` compared the request's `Origin` header only against
`ST_CORS_ORIGINS` and `ST_BASE_URL`, both of which default to `http://localhost:8000`.
`ST_ALLOWED_HOSTS` defaults to `localhost,127.0.0.1`, so the SPA is served at both
spellings, but only the `localhost` one passed the origin check. A same-origin POST from
the `127.0.0.1` page carries `Origin: http://127.0.0.1:8000` and was rejected.

The existing suite missed it because `conftest.app_env` sets
`ST_CORS_ORIGINS=http://testserver`, which happens to equal `TestClient`'s own origin, so
every test was posting an origin that was already in the configured list. These tests
configure the deployment for one documented dev origin and drive the app through the other,
by overriding the `Host` header (the `HostAllowlistMiddleware` still validates it).
"""
from __future__ import annotations

import pytest
from starlette.requests import Request

from app.config import reset_settings_cache
from app.security.auth import _origin_allowed, _parse_origin, request_origin

PASSWORD = "Correct-Horse-Battery-9!"

# A public host, self-approved by an administrator: creates without needing the lab
# allow-list, so the test exercises the CSRF gate and not the target policy.
TARGET = {
    "name": "Regression Target",
    "base_url": "https://api.regression.example",
    "authorization_mode": "admin",
    "attestation": "Operator owns this target; authorized regression coverage.",
    "ports": [443],
}

DEV_ORIGINS = ["http://127.0.0.1:8000", "http://localhost:8000"]


@pytest.fixture()
def deployment(app_env, monkeypatch):
    """The README's local configuration: base/CORS on localhost, both hosts served.

    Depends on `app_env` so the database is seeded and pointed at before the overrides.
    """
    original = {
        key: value for key, value in __import__("os").environ.items()
        if key in {"ST_BASE_URL", "ST_CORS_ORIGINS"}
    }

    def configure(
        *,
        base_url: str = "http://localhost:8000",
        cors: str = "http://localhost:8000",
        allowed_hosts: str = "testserver,localhost,127.0.0.1",
        trusted_proxies: str = "",
    ) -> None:
        monkeypatch.setenv("ST_ENV", "test")
        monkeypatch.setenv("ST_BASE_URL", base_url)
        monkeypatch.setenv("ST_CORS_ORIGINS", cors)
        monkeypatch.setenv("ST_ALLOWED_HOSTS", allowed_hosts)
        monkeypatch.setenv("ST_TRUSTED_PROXIES", trusted_proxies)
        reset_settings_cache()

    configure()
    yield configure
    monkeypatch.delenv("ST_TRUSTED_PROXIES", raising=False)
    for key, value in original.items():
        monkeypatch.setenv(key, value)
    reset_settings_cache()


def post(client, headers, *, origin=None, host="127.0.0.1:8000", payload=None, token=True):
    """POST as the SPA would from `http://<host>`: Host header, Origin, CSRF header."""
    merged = {**headers, "Host": host}
    if token:
        merged.setdefault("X-CSRF-Token", headers.get("X-CSRF-Token", ""))
    if origin is not None:
        merged["Origin"] = origin
    return client.post("/api/v1/targets", json={**TARGET, **(payload or {})}, headers=merged)


# ---------------------------------------------------------------- the reported failure


def test_target_creation_succeeds_from_the_apps_own_origin(admin_client, deployment):
    """The exact bug: deployment configured for localhost, request served from 127.0.0.1."""
    client, headers, _env = admin_client
    deployment(base_url="http://localhost:8000", cors="http://localhost:8000")
    response = post(client, headers, origin="http://127.0.0.1:8000", host="127.0.0.1:8000")
    assert response.status_code == 200, response.text
    assert response.json()["target"]["name"] == TARGET["name"]
    listed = client.get("/api/v1/targets", headers=headers).json()["targets"]
    assert any(target["name"] == TARGET["name"] for target in listed)


@pytest.mark.parametrize("origin", DEV_ORIGINS)
def test_both_documented_dev_origins_can_create_a_target(admin_client, deployment, origin):
    """`ST_ALLOWED_HOSTS` defaults to localhost *and* 127.0.0.1, so both serve the SPA."""
    client, headers, _env = admin_client
    deployment()
    host = origin.split("://", 1)[1]
    response = post(client, headers, origin=origin, host=host)
    assert response.status_code == 200, response.text


def test_an_analyst_can_also_create_a_target_from_the_own_origin(analyst_client, deployment):
    """The gate is shared: the same check governs every mutating route, every role."""
    client, headers, _env = analyst_client
    deployment()
    # an analyst cannot self-approve, so this one is created `pending` under `ownership`
    response = post(
        client, headers, origin="http://127.0.0.1:8000",
        payload={"authorization_mode": "ownership", "base_url": "https://api.analyst.example", "ports": [443]},
    )
    assert response.status_code == 200, response.text


# -------------------------------------------------- other admin actions (shared middleware)


MUTATIONS = [
    ("POST", "/api/v1/users/invite",
     {"email": "invited@org.example.test", "name": "Invited", "role": "viewer"}),
    ("POST", "/api/v1/targets/{target}/approve", None),
    ("POST", "/api/v1/scans", {"target_id": None, "attestation": "Authorized regression scan."}),
]


def _mutation(client, headers, method, template, payload, env, *, origin, host="127.0.0.1:8000"):
    body = dict(payload or {})
    if "target_id" in body:
        body["target_id"] = env["target"]["id"]
    path = template.format(target=env["target"]["id"])
    return client.request(method, path, json=body, headers={**headers, "Host": host, "Origin": origin})


@pytest.mark.parametrize("method, template, payload", MUTATIONS, ids=[m[1] for m in MUTATIONS])
@pytest.mark.parametrize("origin", DEV_ORIGINS)
def test_every_mutation_accepts_the_own_origin(admin_client, deployment, method, template, payload, origin):
    """No endpoint may reject its own first-party origin — the bug was shared middleware."""
    client, headers, env = admin_client
    deployment()
    response = _mutation(client, headers, method, template, payload, env,
                         origin=origin, host=origin.split("://", 1)[1])
    assert response.json().get("error", {}).get("code") != "csrf_failed", (response.status_code, response.text)


@pytest.mark.parametrize("method, template, payload", MUTATIONS, ids=[m[1] for m in MUTATIONS])
def test_every_mutation_still_rejects_a_foreign_origin(admin_client, deployment, method, template, payload):
    """Fixing the false positive must not open a false negative."""
    client, headers, env = admin_client
    deployment()
    response = _mutation(client, headers, method, template, payload, env, origin="https://evil.example.net")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


# ------------------------------------------------------------------- hostile origins


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example.net",
        "http://attacker.test",
        "http://127.0.0.1:9999",        # our host, wrong port
        "https://127.0.0.1:8000",       # our host, upgraded scheme
        "http://127.0.0.1:8000/x",      # a path is not an origin
        "http://127.0.0.1:8000?q=1",
        "null",                          # sandboxed iframe / file://
        "127.0.0.1:8000",               # no scheme
        "ftp://127.0.0.1:8000",
        "http://user:pass@127.0.0.1:8000",
    ],
)
def test_hostile_origins_are_rejected(admin_client, deployment, origin):
    client, headers, _env = admin_client
    deployment()
    response = post(client, headers, origin=origin)
    assert response.status_code == 403, (origin, response.status_code, response.text)
    assert response.json()["error"]["code"] == "csrf_failed"


def test_an_absent_origin_still_requires_the_token(admin_client, deployment):
    """A non-browser client (curl, the CLI) sends no Origin; the token is still mandatory."""
    client, headers, _env = admin_client
    deployment()
    assert post(client, headers, origin=None).status_code == 200
    missing_token = post(client, {k: v for k, v in headers.items() if k != "X-CSRF-Token"},
                         origin=None, token=False)
    assert missing_token.status_code == 403
    assert missing_token.json()["error"]["code"] == "csrf_failed"


def test_a_configured_origin_is_accepted_even_when_it_is_not_the_request_host(admin_client, deployment):
    """A split deployment (SPA on :5173, API on :8000) keeps working through ST_CORS_ORIGINS."""
    client, headers, _env = admin_client
    deployment(cors="http://localhost:5173,http://localhost:8000")
    response = post(client, headers, origin="http://localhost:5173", host="127.0.0.1:8000")
    assert response.status_code == 200, response.text


# -------------------------------------------------------- CSRF token and session cookies


def test_a_missing_csrf_header_is_rejected(client, admin_client, deployment):
    client, headers, _env = admin_client
    deployment()
    response = client.post(
        "/api/v1/targets", json=TARGET, headers={"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000"}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


def test_a_wrong_csrf_token_is_rejected(client, admin_client, deployment):
    client, headers, _env = admin_client
    deployment()
    response = client.post(
        "/api/v1/targets",
        json=TARGET,
        headers={"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000", "X-CSRF-Token": "not-the-token"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


def test_an_empty_csrf_token_is_rejected(client, admin_client, deployment):
    client, headers, _env = admin_client
    deployment()
    response = client.post(
        "/api/v1/targets",
        json=TARGET,
        headers={"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000", "X-CSRF-Token": ""},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


def test_safe_methods_do_not_need_a_csrf_token(client, admin_client, deployment):
    client, headers, _env = admin_client
    deployment()
    assert client.get("/api/v1/targets", headers={"Origin": "http://127.0.0.1:8000"}).status_code == 200


def test_an_unauthenticated_request_is_401_before_any_origin_check(client, deployment):
    """No session means no CSRF context at all: the answer is 401, not 403."""
    deployment()
    response = client.post(
        "/api/v1/targets",
        json=TARGET,
        headers={"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000", "X-CSRF-Token": "anything"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


def test_login_rejects_a_foreign_origin(client, app_env, deployment):
    """`/auth/login` is the one state-changing route with no session to check.

    There is no CSRF token before login, so a cross-site form post could otherwise sign a
    victim into an attacker-controlled account (login CSRF). The origin check is the whole
    gate on that route: a foreign origin is refused before any credential is examined, and
    the app's own origin and non-browser clients (no `Origin` header) are unaffected.
    """
    credentials = {"email": "admin@org.example.test", "password": PASSWORD}

    foreign = client.post(
        "/api/v1/auth/login",
        json=credentials,
        headers={"Origin": "https://evil.example"},
    )
    assert foreign.status_code == 403
    assert foreign.json()["error"]["code"] == "csrf_failed"
    assert not foreign.cookies.get("st_session"), "a refused login must not mint a session"

    # The same credentials from the app's own origin are accepted.
    client.cookies.clear()
    own = client.post(
        "/api/v1/auth/login",
        json=credentials,
        headers={"Origin": "http://localhost:8000"},
    )
    assert own.status_code == 200
    assert own.cookies.get("st_session")


def test_login_without_an_origin_header_still_works(client, app_env):
    """CLI/API clients do not send `Origin`; they must not be broken by the check."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@org.example.test", "password": PASSWORD},
    )
    assert response.status_code == 200


def test_the_session_cookie_is_httponly_and_the_csrf_cookie_is_readable(client, app_env):
    """The SPA must be able to read `st_csrf` (its fallback) but never `st_session`."""
    response = client.post("/api/v1/auth/login", json={"email": "admin@org.example.test", "password": PASSWORD})
    assert response.status_code == 200
    cookies = {header.split("=", 1)[0]: header for header in response.headers.get_list("set-cookie")}
    assert "HttpOnly" in cookies["st_session"]
    assert "HttpOnly" not in cookies["st_csrf"], "the SPA reads st_csrf as a fallback"
    lowered = {key: value.lower() for key, value in cookies.items()}
    assert "samesite=strict" in lowered["st_session"]
    assert "samesite=strict" in lowered["st_csrf"]
    assert client.cookies.get("st_csrf")


def test_the_csrf_token_from_me_matches_the_cookie(client, app_env):
    from .conftest import login

    csrf, _headers = login(client, "admin@org.example.test")
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["csrf_token"] == csrf
    assert client.cookies.get("st_csrf") == csrf


def test_logout_invalidates_the_old_token(client, app_env, deployment):
    from .conftest import login

    deployment()
    _csrf, headers = login(client, "admin@org.example.test")
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    stale = post(client, headers, origin="http://127.0.0.1:8000")
    assert stale.status_code == 401
    assert stale.json()["error"]["code"] == "unauthenticated"


# --------------------------------------------------------------- origin parsing (unit)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("http://127.0.0.1:8000", ("http", "127.0.0.1", 8000)),
        ("http://127.0.0.1:8000/", ("http", "127.0.0.1", 8000)),
        ("HTTP://LocalHost:8000", ("http", "localhost", 8000)),
        ("https://shadowtrace.example.com", ("https", "shadowtrace.example.com", 443)),
        ("https://shadowtrace.example.com:443", ("https", "shadowtrace.example.com", 443)),
        ("http://[::1]:8000", ("http", "::1", 8000)),
        ("null", None),
        ("", None),
        ("localhost:8000", None),
        ("http://host:not-a-port", None),
        ("http://host/path", None),
        ("http://host?q=1", None),
        ("http://user:pw@host", None),
        ("ftp://host", None),
    ],
)
def test_parse_origin(value, expected):
    assert _parse_origin(value) == expected


def _request(host: str = "127.0.0.1:8000", scheme: str = "http", peer: str = "127.0.0.1",
             headers: dict[str, str] | None = None) -> Request:
    raw = [(b"host", host.encode())]
    for key, value in (headers or {}).items():
        raw.append((key.lower().encode(), value.encode()))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/targets",
            "raw_path": b"/api/v1/targets",
            "query_string": b"",
            "headers": raw,
            "client": (peer, 51234),
            "server": (host.split(":")[0], 8000),
            "scheme": scheme,
        }
    )


def test_origin_matching_is_case_and_default_port_insensitive():
    request = _request(host="example.com", scheme="https")
    assert _origin_allowed("https://EXAMPLE.com", request) is True
    assert _origin_allowed("https://example.com:443", request) is True
    assert _origin_allowed("https://example.com:444", request) is False


def test_request_origin_uses_the_host_header():
    assert request_origin(_request(host="127.0.0.1:8000")) == ("http", "127.0.0.1", 8000)


def test_forwarded_proto_is_ignored_from_an_untrusted_peer(deployment):
    deployment(trusted_proxies="")
    request = _request(host="127.0.0.1:8000", headers={"X-Forwarded-Proto": "https"})
    assert request_origin(request) == ("http", "127.0.0.1", 8000)


def test_forwarded_proto_is_honoured_from_a_trusted_proxy(deployment):
    deployment(trusted_proxies="127.0.0.1")
    request = _request(host="app.example.test", headers={"X-Forwarded-Proto": "https"})
    assert request_origin(request) == ("https", "app.example.test", 443)


def test_forwarded_host_header_cannot_shift_the_origin(deployment):
    """X-Forwarded-Host is never consulted: the Host header is already allow-listed."""
    deployment(trusted_proxies="127.0.0.1")
    request = _request(host="app.example.test", headers={"X-Forwarded-Host": "evil.example.net"})
    assert request_origin(request) == ("http", "app.example.test", 80)
