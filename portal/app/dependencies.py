"""FastAPI dependencies for container and auth."""

from fastapi import Request


def get_container(request):
    # type: (Request)
    return request.app.state.container


def get_request_id(request):
    # type: (Request) -> str
    return getattr(request.state, "request_id", "")


async def viewer_or_admin(request: Request):
    # type: (Request)
    container = get_container(request)
    return await container.auth.viewer_or_admin(request)


async def admin_only(request: Request):
    # type: (Request)
    container = get_container(request)
    return await container.auth.admin_only(request)
