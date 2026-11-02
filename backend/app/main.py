"""ShadowTrace API application."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import admin, auth_routes, dashboard, inventory, lab, meta, scans, targets, users
from .api.deps import policy_guard, rate_limit
from .config import get_settings
from .core.logging import configure_logging
from .db import db, init_db
from .engine.safe_http import VERSION
from .services.lab import LabUnavailable, get_supervisor
from .security.errors import install_error_handlers
from .security.labgrant import sync_grants
from .security.middleware import (
    BodyLimitMiddleware,
    HostAllowlistMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)

log = logging.getLogger("shadowtrace.app")
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


def bootstrap_admin_if_configured() -> None:
    settings = get_settings()
    email = settings.bootstrap_admin_email
    # A blank or whitespace-only value means "not configured" (same rule as `app.cli`), so an
    # empty variable in a shell or .env file skips bootstrap instead of crashing startup.
    # A real but weak password still fails closed below.
    password = settings.bootstrap_admin_password if settings.bootstrap_admin_password.strip() else ""
    org_name = settings.bootstrap_org_name
    if not email or not password:
        return
    from .db import new_id, now
    from .security.passwords import hash_password, validate_password
    from .security import audit

    with db() as conn:
        if conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]:
            return
        try:
            validate_password(password, email=email)
        except Exception as exc:  # pragma: no cover - startup guard
            log.error("bootstrap_admin_rejected: %s", exc)
            raise
        org_id = new_id()
        user_id = new_id()
        timestamp = now()
        conn.execute("INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)", (org_id, org_name, timestamp))
        conn.execute(
            """
            INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at)
            VALUES (?, ?, ?, ?, 'admin', ?, 1, ?)
            """,
            (user_id, org_id, email, "Administrator", hash_password(password), timestamp),
        )
        audit.record(conn, action="system.bootstrap_admin", org_id=org_id, actor_type="system", details={"email": email})
    log.info("bootstrap_admin_created")


def _startup_diagnostics(settings) -> None:
    """Log the configuration the API actually resolved.

    The original `policy_blocked` report was a configuration-drift problem: the API had an
    allow-list entry and the worker did not. Printing the effective (non-secret) values at
    startup is what makes that class of bug visible in one line of log.
    """
    log.info(
        "startup_config env=%s database=%s allowlist=%s lab_enabled=%s lab_url=%s scanning=%s worker_poll_ms=%s",
        settings.env,
        settings.database_path,
        [f"{host}:{port}" for host, port in settings.private_allowlist] or "none",
        settings.lab_enabled,
        f"http://{settings.lab_host}:{settings.lab_port}" if settings.lab_enabled else "disabled",
        settings.scanning_enabled,
        int(settings.worker_poll_seconds * 1000),
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    init_db()
    bootstrap_admin_if_configured()
    _startup_diagnostics(settings)
    # Reconcile lab grants with the allow-list in force: issues missing grants and clears
    # stale ones, so revoking an allow-list entry takes effect on the next start.
    with db() as conn:
        counters = sync_grants(
            conn, secret=settings.secret_key, allowlist=settings.private_allowlist
        )
    if counters["issued"] or counters["cleared"]:
        log.info("lab_grants_reconciled %s", counters)
    supervisor = get_supervisor()
    if settings.lab_enabled and settings.lab_autostart:
        try:
            supervisor.start()
        except LabUnavailable as exc:
            # A demo convenience must not take the product down. A port race with a lab that
            # is already running, a missing entrypoint or a slow child used to abort the whole
            # startup here -- while start.cmd treated the same condition as a warning and the
            # README promised the rest of the app still works. All three policies now agree:
            # the Lab page carries last_error, the log carries the reason, the API serves.
            log.error("lab_start_failed error=%s", exc)
    elif not settings.lab_enabled:
        supervisor.mark_disabled()
    log.info("application_started env=%s version=%s", settings.env, VERSION)
    yield
    get_supervisor().stop(graceful=True)
    log.info("application_stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    docs_enabled = not settings.is_production
    app = FastAPI(
        title="ShadowTrace",
        version=VERSION,
        lifespan=lifespan,
        docs_url="/api/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs_enabled else None,
    )
    install_error_handlers(app)

    api_dependency = [Depends(rate_limit("api")), Depends(policy_guard)]
    for module in (targets, scans, inventory, dashboard, admin, users, meta, lab):
        app.include_router(module.router, dependencies=api_dependency)
    app.include_router(auth_routes.router, dependencies=[Depends(rate_limit("api")), Depends(policy_guard)])

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-CSRF-Token", "Idempotency-Key", "X-Har-Name", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Content-Disposition"],
        max_age=600,
    )
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_upload_bytes)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(HostAllowlistMiddleware)
    app.add_middleware(RequestContextMiddleware)

    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    index_file = FRONTEND_DIST / "index.html"

    @app.get("/", include_in_schema=False)
    def index():
        if index_file.is_file():
            return FileResponse(str(index_file), media_type="text/html")
        return JSONResponse({"name": "ShadowTrace", "version": VERSION, "api": "/api/v1/health"})

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str, request: Request):
        if full_path.startswith("api/"):
            return JSONResponse(
                {"error": {"code": "not_found", "message": "The requested resource was not found.", "request_id": getattr(request.state, "request_id", "")}},
                status_code=404,
            )
        if index_file.is_file():
            return FileResponse(str(index_file), media_type="text/html")
        return JSONResponse({"detail": "frontend not built"}, status_code=503)

    return app


app = create_app()
