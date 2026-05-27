"""FastAPI application factory for the Identity Research for Agent Management Using SPIFFE portal."""

import logging
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import httpx
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError

from .container import PortalContainer
from .errors import PortalError, handle_portal_error, handle_validation_error
from .logging import configure_logging, configure_observability
from .routers.api import router as api_router
from .routers.public import router as public_router
from .version import get_portal_version

logger = logging.getLogger("isp-portal")


def create_app(config_path="portal-config.json"):
    # type: (str) -> FastAPI
    configure_logging()
    configure_observability("isp-portal")

    @asynccontextmanager
    async def lifespan(app):
        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            verify=True,
        )
        container = await PortalContainer.create(config_path, http_client)
        app.state.container = container
        app.state.index_path = REPO_ROOT / "portal" / "index.html"
        logger.info(
            "Portal container initialized",
            extra={"runtime_environment": container.settings.runtime_environment},
        )
        try:
            yield
        finally:
            await http_client.aclose()

    app = FastAPI(
        title="Identity Research for Agent Management Using SPIFFE Control Panel",
        version=get_portal_version(),
        lifespan=lifespan,
    )
    app.add_exception_handler(PortalError, handle_portal_error)
    app.add_exception_handler(RequestValidationError, handle_validation_error)

    @app.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        request_id = request.headers.get("X-Request-ID", uuid.uuid4().hex)
        request.state.request_id = request_id
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.monotonic() - start) * 1000)
            logger.exception(
                "Unhandled request error",
                extra={
                    "request_id": request_id,
                    "path": request.url.path,
                    "method": request.method,
                    "duration_ms": duration_ms,
                },
            )
            raise
        duration_ms = int((time.monotonic() - start) * 1000)
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "Request completed",
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response

    app.include_router(public_router)
    app.include_router(api_router)
    return app
