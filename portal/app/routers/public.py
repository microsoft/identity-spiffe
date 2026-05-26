"""Public routes that do not require portal auth."""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from ..dependencies import get_container, get_request_id

router = APIRouter()


@router.get("/api/auth-config")
async def get_auth_config(request: Request):
    container = get_container(request)
    return container.auth.auth_config()


@router.get("/healthz/live")
async def healthz_live(request: Request):
    container = get_container(request)
    return container.health_service.live_status()


@router.get("/healthz/ready")
async def healthz_ready(request: Request):
    container = get_container(request)
    payload = await container.health_service.ready_status(get_request_id(request))
    return JSONResponse(status_code=200 if payload.get("ready") else 503, content=payload)


@router.get("/health")
async def health_alias(request: Request):
    container = get_container(request)
    return container.health_service.live_status()


@router.get("/favicon.ico")
@router.get("/apple-touch-icon.png")
@router.get("/apple-touch-icon-precomposed.png")
async def favicon():
    return Response(status_code=204)


@router.get("/", response_class=HTMLResponse)
async def serve_portal(request: Request):
    index_path = request.app.state.index_path
    if not index_path.exists():
        return HTMLResponse("<h1>index.html not found</h1>", status_code=500)
    return HTMLResponse(index_path.read_text(encoding="utf-8"))
