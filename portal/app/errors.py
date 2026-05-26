"""Application-specific error types and exception handlers."""

from typing import Any, Dict, Optional

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class PortalError(Exception):
    """Structured application error."""

    def __init__(self, status_code, error_code, detail, meta=None):
        # type: (int, str, str, Optional[Dict[str, Any]]) -> None
        super().__init__(detail)
        self.status_code = status_code
        self.error_code = error_code
        self.detail = detail
        self.meta = meta or {}


def portal_error_response(exc, request_id):
    # type: (PortalError, str) -> JSONResponse
    body = {
        "detail": exc.detail,
        "error_code": exc.error_code,
        "request_id": request_id,
    }
    if exc.meta:
        body["meta"] = exc.meta
    return JSONResponse(status_code=exc.status_code, content=body)


async def handle_portal_error(request, exc):
    # type: (Request, PortalError) -> JSONResponse
    request_id = getattr(request.state, "request_id", "")
    return portal_error_response(exc, request_id)


async def handle_validation_error(request, exc):
    # type: (Request, RequestValidationError) -> JSONResponse
    request_id = getattr(request.state, "request_id", "")
    return JSONResponse(
        status_code=422,
        content={
            "detail": "Request validation failed",
            "error_code": "request_validation",
            "request_id": request_id,
            "errors": exc.errors(),
        },
    )
