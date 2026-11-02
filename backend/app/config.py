"""Environment-driven configuration with fail-closed production checks.

Every setting is read once at process start.  Production mode refuses to boot
when a security-relevant value is missing, weak or unsafe (see
docs/SECURITY_REQUIREMENTS.md#CFG).
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List, Tuple

log = logging.getLogger("shadowtrace.config")

# Rationale: sentinel, only used to reject it in production
DEV_SECRET = "dev-only-secret-change-me-please-0123456789"  # nosec B105
# Published in older start.cmd/start.sh/README revisions for the local training stack.
# A deployment that still uses it is not a deployment: refuse it in production exactly
# like DEV_SECRET, because it signs lab grants and anyone holding the archive has it.
LOCAL_DEMO_SECRET = "local-development-only-4f8c1d2a9b7e6f3c5a1d0b8e7c6f5a4d"  # nosec B105


class ConfigurationError(RuntimeError):
    """Raised when configuration is missing or unsafe. Production fails closed."""


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_raw(name: str) -> str:
    """Read a value verbatim. Used for secrets and passwords, which must not be trimmed."""
    return os.environ.get(name, "")


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if not raw:
        return default
    lowered = raw.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean, got {raw!r}")


def _parse_bool(name: str, raw: str) -> bool:
    lowered = raw.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be a boolean, got {raw!r}")


def _env_bool_preferring(name: str, deprecated: str, default: bool) -> bool:
    """Read ``name``; fall back to ``deprecated`` with a warning when it is unset.

    The legacy name is kept only so an existing deployment keeps its kill-switch
    setting across the rename.  A value under the current name always wins, and
    the fallback is logged so the operator can remove it.
    """
    raw = _env(name)
    if raw:
        return _parse_bool(name, raw)
    legacy = _env(deprecated)
    if legacy:
        log.warning(
            "deprecated_config_name env=%s use=%s value=%s", deprecated, name, legacy
        )
        return _parse_bool(deprecated, legacy)
    return default


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer, got {raw!r}") from exc


def _env_list(name: str, default: str = "") -> List[str]:
    raw = _env(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_allowlist(raw: List[str]) -> Tuple[Tuple[str, int], ...]:
    """Operator-only private destination allow-list, exact host:port pairs.

    This is the *only* path that permits a non-global destination.  It is read
    from the environment, never from the API or the UI.
    """
    parsed: List[Tuple[str, int]] = []
    for item in raw:
        if ":" not in item:
            raise ConfigurationError(f"ST_PRIVATE_ALLOWLIST entry {item!r} must be host:port")
        host, _, port_raw = item.rpartition(":")
        try:
            port = int(port_raw)
        except ValueError as exc:
            raise ConfigurationError(f"ST_PRIVATE_ALLOWLIST port invalid in {item!r}") from exc
        if not host or not (0 < port < 65536):
            raise ConfigurationError(f"ST_PRIVATE_ALLOWLIST entry invalid: {item!r}")
        parsed.append((host.lower().strip("[]"), port))
    return tuple(parsed)


def is_trusted_proxy(peer: str, entries: Tuple[str, ...]) -> bool:
    """True when ``peer`` is a configured proxy address or inside a trusted CIDR.

    Entries are literal addresses (``172.30.0.2``) or networks (``172.30.0.0/24``).
    An unparsable entry never matches, so a typo fails *closed*: the forwarded
    header is ignored and the socket peer is used instead.
    """
    if not peer or not entries:
        return False
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return any(entry == peer for entry in entries)
    for entry in entries:
        candidate = entry.strip()
        if not candidate:
            continue
        if "/" in candidate:
            try:
                if peer_ip in ipaddress.ip_network(candidate, strict=False):
                    return True
            except ValueError:
                continue
        else:
            try:
                if peer_ip == ipaddress.ip_address(candidate):
                    return True
            except ValueError:
                continue
    return False


@dataclass(frozen=True)
class Settings:
    env: str
    secret_key: str
    database_path: str
    base_url: str
    allowed_hosts: Tuple[str, ...]
    cors_origins: Tuple[str, ...]
    trusted_proxies: Tuple[str, ...]
    cookie_secure: bool
    session_idle_seconds: int
    session_absolute_seconds: int
    scanning_enabled: bool
    private_allowlist: Tuple[Tuple[str, int], ...]
    max_requests_per_scan_hard_cap: int
    max_pages_per_scan_hard_cap: int
    max_scan_seconds_hard_cap: int
    max_upload_bytes: int
    max_response_bytes: int
    scan_concurrency_per_org: int
    scans_per_day_per_org: int
    retention_days: int
    worker_poll_seconds: float
    worker_lease_seconds: int
    log_level: str
    demo_mode: bool
    lab_enabled: bool = False
    lab_host: str = "127.0.0.1"
    lab_port: int = 8099
    lab_autostart: bool = False
    bootstrap_admin_email: str = ""
    bootstrap_admin_password: str = field(default="", repr=False)
    bootstrap_org_name: str = "ShadowTrace Demo"

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def testing(self) -> bool:
        return self.env == "test"


def _validate(settings: Settings) -> None:
    errors: List[str] = []
    if len(settings.secret_key) < 32:
        errors.append("ST_SECRET_KEY must be at least 32 characters")
    if settings.is_production:
        if settings.secret_key in {DEV_SECRET, LOCAL_DEMO_SECRET}:
            errors.append("refusing to start in production with the development secret")
        if not settings.cookie_secure:
            errors.append("ST_COOKIE_SECURE must be enabled in production")
        if not settings.allowed_hosts or "*" in settings.allowed_hosts:
            errors.append("ST_ALLOWED_HOSTS must be an explicit allow-list in production")
        if "*" in settings.cors_origins:
            errors.append("wildcard CORS is not allowed in production")
        if not settings.base_url.startswith("https://"):
            errors.append("ST_BASE_URL must use https in production")
        if settings.demo_mode:
            errors.append("demo mode cannot be enabled in production")
    if settings.session_idle_seconds <= 0 or settings.session_absolute_seconds <= settings.session_idle_seconds:
        errors.append("session idle/absolute expiry values are inconsistent")
    if settings.max_requests_per_scan_hard_cap > 50_000:
        errors.append("ST_MAX_REQUESTS_HARD_CAP is unreasonably high")
    if settings.max_upload_bytes <= 0:
        errors.append("ST_MAX_UPLOAD_BYTES must be positive")
    if settings.max_response_bytes <= 0:
        errors.append("ST_MAX_RESPONSE_BYTES must be positive")
    if settings.scan_concurrency_per_org <= 0:
        errors.append("ST_SCAN_CONCURRENCY_PER_ORG must be positive")
    if not (0 < settings.lab_port < 65536):
        errors.append("ST_LAB_PORT must be a valid TCP port")
    if settings.lab_enabled:
        # The training lab is a deliberately vulnerable application. It is only ever
        # bound to loopback and only ever scanned through an explicit lab grant, so a
        # non-local bind or a production deployment is a configuration error, not a
        # warning: those combinations would publish a vulnerable app to the network.
        try:
            loopback = ipaddress.ip_address(settings.lab_host).is_loopback
        except ValueError:
            loopback = settings.lab_host in {"localhost", "localhost."}
        if not loopback:
            errors.append("ST_LAB_HOST must be a loopback address (the lab is never exposed)")
        if settings.is_production:
            errors.append("the training lab cannot be enabled in production (ST_LAB_ENABLED=false)")
    if errors:
        raise ConfigurationError("; ".join(errors))


def load_settings() -> Settings:
    env = _env("ST_ENV", "development").lower() or "development"
    if env not in {"development", "production", "test"}:
        raise ConfigurationError("ST_ENV must be development|production|test")
    settings = Settings(
        env=env,
        secret_key=_env("ST_SECRET_KEY", DEV_SECRET),
        database_path=_env("ST_DATABASE_PATH", "/data/shadowtrace.db"),
        base_url=_env("ST_BASE_URL", "http://localhost:8000"),
        allowed_hosts=tuple(h.lower() for h in _env_list("ST_ALLOWED_HOSTS", "localhost,127.0.0.1")),
        cors_origins=tuple(_env_list("ST_CORS_ORIGINS", "http://localhost:8000")),
        trusted_proxies=tuple(_env_list("ST_TRUSTED_PROXIES")),
        cookie_secure=_env_bool("ST_COOKIE_SECURE", env == "production"),
        session_idle_seconds=_env_int("ST_SESSION_IDLE_SECONDS", 1800),
        session_absolute_seconds=_env_int("ST_SESSION_ABSOLUTE_SECONDS", 43200),
        # `SCANNING_ENABLED` (no prefix) is the deprecated spelling; it still works as a
        # fallback so an existing deployment keeps its kill switch across the rename.
        scanning_enabled=_env_bool_preferring("ST_SCANNING_ENABLED", "SCANNING_ENABLED", True),
        private_allowlist=_parse_allowlist(_env_list("ST_PRIVATE_ALLOWLIST")),
        max_requests_per_scan_hard_cap=_env_int("ST_MAX_REQUESTS_HARD_CAP", 2000),
        max_pages_per_scan_hard_cap=_env_int("ST_MAX_PAGES_HARD_CAP", 200),
        max_scan_seconds_hard_cap=_env_int("ST_MAX_SCAN_SECONDS_HARD_CAP", 900),
        # These defaults are the published ones in `.env.example` (kept identical by
        # `tests/test_env_example.py`): 8 MiB uploads, 2 MiB responses, 2 concurrent scans.
        max_upload_bytes=_env_int("ST_MAX_UPLOAD_BYTES", 8 * 1024 * 1024),
        max_response_bytes=_env_int("ST_MAX_RESPONSE_BYTES", 2 * 1024 * 1024),
        scan_concurrency_per_org=_env_int("ST_SCAN_CONCURRENCY_PER_ORG", 2),
        scans_per_day_per_org=_env_int("ST_SCANS_PER_DAY_PER_ORG", 50),
        retention_days=_env_int("ST_RETENTION_DAYS", 90),
        worker_poll_seconds=float(_env_int("ST_WORKER_POLL_MS", 500)) / 1000.0,
        worker_lease_seconds=_env_int("ST_WORKER_LEASE_SECONDS", 30),
        log_level=_env("ST_LOG_LEVEL", "INFO").upper(),
        demo_mode=_env_bool("ST_DEMO_MODE", False),
        # The lab is on by default for development and test, and refused outright in
        # production (see `_validate`): it is a deliberately vulnerable target.
        lab_enabled=_env_bool("ST_LAB_ENABLED", env != "production"),
        lab_host=_env("ST_LAB_HOST", "127.0.0.1") or "127.0.0.1",
        lab_port=_env_int("ST_LAB_PORT", 8099),
        lab_autostart=_env_bool("ST_LAB_AUTOSTART", False),
        bootstrap_admin_email=_env("ST_BOOTSTRAP_ADMIN_EMAIL").lower(),
        bootstrap_admin_password=_env_raw("ST_BOOTSTRAP_ADMIN_PASSWORD"),
        bootstrap_org_name=_env("ST_BOOTSTRAP_ORG_NAME", "ShadowTrace Demo") or "ShadowTrace Demo",
    )
    _validate(settings)
    return settings


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()


def generate_secret() -> str:
    return secrets.token_urlsafe(48)


HOSTNAME_RE = re.compile(r"^[a-z0-9.-]+$")
