"""One error format for the whole API.

{"error": {"code": "...", "message": "...", "request_id": "...", "fields": [...]}}

User-facing messages never contain stack traces, SQL, paths or internal detail.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("shadowtrace.errors")

_STATUS_CODES = {
    400: ("bad_request", "The request could not be processed."),
    401: ("unauthenticated", "Authentication is required."),
    403: ("forbidden", "You do not have permission to perform this action."),
    404: ("not_found", "The requested resource was not found."),
    405: ("method_not_allowed", "That method is not allowed for this resource."),
    409: ("conflict", "The request conflicts with the current state."),
    413: ("payload_too_large", "The request body is too large."),
    415: ("unsupported_media_type", "That content type is not supported."),
    422: ("validation_error", "The submitted data is invalid."),
    429: ("rate_limited", "Too many requests. Please retry later."),
    500: ("internal_error", "An unexpected error occurred."),
    503: ("unavailable", "The service is temporarily unavailable."),
}


class ApiError(Exception):
    """Business error with an explicit, user-safe message."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        fields: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.fields = fields or []
        self.headers = headers or {}
        super().__init__(message)


def not_found() -> ApiError:
    """Cross-tenant and missing objects are indistinguishable (no IDOR oracle)."""
    return ApiError(404, "not_found", "The requested resource was not found.")


def _payload(request: Request, code: str, message: str, fields: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "error": {
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", ""),
        }
    }
    if fields:
        body["error"]["fields"] = fields
    return body


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload(request, exc.code, exc.message, exc.fields),
            headers={**exc.headers, "Cache-Control": "no-store"},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code, message = _STATUS_CODES.get(exc.status_code, ("error", "The request could not be processed."))
        headers = dict(getattr(exc, "headers", None) or {})
        return JSONResponse(
            status_code=exc.status_code,
            content=_payload(request, code, message),
            headers={**headers, "Cache-Control": "no-store"},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = [
            {
                "location": ".".join(str(part) for part in error.get("loc", ())[:6]),
                "message": str(error.get("msg", ""))[:200],
                "type": str(error.get("type", ""))[:60],
            }
            for error in exc.errors()[:20]
        ]
        return JSONResponse(
            status_code=422,
            content=_payload(request, "validation_error", "The submitted data is invalid.", fields),
            headers={"Cache-Control": "no-store"},
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "-")
        log.exception("unhandled_error request_id=%s path=%s", request_id, request.url.path)
        return JSONResponse(
            status_code=500,
            content=_payload(request, "internal_error", "An unexpected error occurred."),
            headers={"Cache-Control": "no-store"},
        )
