"""Configuration must fail closed: insecure production settings refuse to start."""
from __future__ import annotations

import pytest

from app.config import ConfigurationError, Settings, load_settings


def _base(**overrides) -> dict:
    values = dict(
        env="production",
        secret_key="x" * 48,
        database_path="/tmp/st-test.db",
        base_url="https://shadowtrace.example.com",
        allowed_hosts=("shadowtrace.example.com",),
        cors_origins=("https://shadowtrace.example.com",),
        cookie_secure=True,
        session_idle_seconds=1800,
        session_absolute_seconds=43200,
        trusted_proxies=(),
        private_allowlist=(),
        max_requests_per_scan_hard_cap=2000,
        max_pages_per_scan_hard_cap=200,
        max_scan_seconds_hard_cap=900,
        max_upload_bytes=8 * 1024 * 1024,
        max_response_bytes=5 * 1024 * 1024,
        scan_concurrency_per_org=3,
        scans_per_day_per_org=50,
        retention_days=90,
        worker_poll_seconds=0.5,
        worker_lease_seconds=30,
        demo_mode=False,
        scanning_enabled=True,
        log_level="INFO",
        bootstrap_admin_email="",
        bootstrap_admin_password="",
        bootstrap_org_name="ShadowTrace Demo",
    )
    values.update(overrides)
    return values


def _load(monkeypatch, **overrides) -> Settings:
    import app.config as config

    for key in list(__import__("os").environ):
        if key.startswith("ST_") or key == "SCANNING_ENABLED":  # both kill-switch spellings
            monkeypatch.delenv(key, raising=False)
    settings = Settings(**_base(**overrides))
    config._validate(settings)
    return settings


def test_production_defaults_are_accepted(monkeypatch):
    settings = _load(monkeypatch)
    assert settings.is_production
    assert settings.cookie_secure is True


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"secret_key": "short"}, "at least 32 characters"),
        ({"secret_key": "dev-only-secret-change-me-please-0123456789"}, "development secret"),
        ({"cookie_secure": False}, "ST_COOKIE_SECURE"),
        ({"allowed_hosts": ()}, "ST_ALLOWED_HOSTS"),
        ({"allowed_hosts": ("*",)}, "ST_ALLOWED_HOSTS"),
        ({"cors_origins": ("*",)}, "wildcard CORS"),
        ({"base_url": "http://shadowtrace.example.com"}, "https"),
        ({"demo_mode": True}, "demo mode"),
        ({"session_idle_seconds": -1}, "session idle/absolute"),
        ({"session_absolute_seconds": 100, "session_idle_seconds": 200}, "session idle/absolute"),
        ({"max_requests_per_scan_hard_cap": 100_000}, "ST_MAX_REQUESTS_HARD_CAP"),
    ],
)
def test_insecure_production_configuration_fails_closed(monkeypatch, overrides, message):
    with pytest.raises(ConfigurationError) as excinfo:
        _load(monkeypatch, **overrides)
    assert message in str(excinfo.value)


def test_test_environment_allows_local_defaults(monkeypatch):
    settings = _load(monkeypatch, env="test", base_url="http://127.0.0.1:8000", allowed_hosts=("localhost",))
    assert settings.is_production is False


def test_settings_are_loaded_from_the_environment(monkeypatch):
    monkeypatch.setenv("ST_ENV", "test")
    monkeypatch.setenv("ST_ALLOWED_HOSTS", "localhost,127.0.0.1")
    monkeypatch.setenv("ST_PRIVATE_ALLOWLIST", "127.0.0.1:8099, localhost:8099")
    monkeypatch.setenv("ST_MAX_REQUESTS_HARD_CAP", "123")
    settings = load_settings()
    assert settings.allowed_hosts == ("localhost", "127.0.0.1")
    assert settings.private_allowlist == (("127.0.0.1", 8099), ("localhost", 8099))
    assert settings.scanning_enabled is True
    assert settings.max_requests_per_scan_hard_cap == 123
