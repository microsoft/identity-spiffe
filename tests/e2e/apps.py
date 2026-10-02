"""Launch real application handlers; replace identity issuance, never decisions."""
import argparse
from contextlib import asynccontextmanager
import importlib.util
import json
import logging
from pathlib import Path
import socket
import sys
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests" / "browser"))

from browser_fixture import IdentityBoundary


def local_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username or parsed.password or not parsed.port
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("Explicit loopback origin required")
    return value.rstrip("/")


class LocalHTTP:
    def __init__(self, origins):
        self.origins = {local_origin(value) for value in origins}

    async def check(self, request):
        url = request.url
        if (url.username or url.password
                or f"{url.scheme}://{url.host}:{url.port}" not in self.origins):
            raise ValueError("Unexpected application network destination")

    def AsyncClient(self, **kwargs):
        kwargs["trust_env"] = False
        kwargs["follow_redirects"] = False
        kwargs["event_hooks"] = {"request": [self.check]}
        return httpx.AsyncClient(**kwargs)

    def __getattr__(self, name):
        return getattr(httpx, name)


def load_app(folder):
    path = ROOT / "src" / folder / "app.py"
    spec = importlib.util.spec_from_file_location("connected_" + folder.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(module)
    return module


def instrument(app, route_prefix):
    state = {"requests": 0, "caller": ""}

    @app.middleware("http")
    async def observe(request, call_next):
        if request.url.path.startswith(route_prefix):
            state["requests"] += 1
            state["caller"] = request.headers.get("X-SPIFFE-Caller-ID", "")
        return await call_next(request)

    @app.get("/__test/evidence")
    async def evidence(request: Request):
        if not request.client or request.client.host != "127.0.0.1":
            return JSONResponse({"error": "loopback_required"}, status_code=403)
        return dict(state)

    @app.post("/__test/reset")
    async def reset(request: Request):
        if not request.client or request.client.host != "127.0.0.1":
            return JSONResponse({"error": "loopback_required"}, status_code=403)
        state.update(requests=0, caller="")
        return {"reset": True}

    return app


def backend_app():
    module = load_app("budget-backend")
    module.ALLOW_REMOTE_ACCESS = False
    return instrument(module.app, "/budget/")


def caller_app(config):
    network = LocalHTTP([config["egress_url"], config["control_url"]])
    module = load_app("budget-report")
    module.BACKEND_ENDPOINT = config["egress_url"]
    module.ADMIN_KEY = config["admin_key"]
    module.httpx = network

    async def token():
        async with network.AsyncClient(timeout=5) as client:
            response = await client.get(config["control_url"] + "/token")
            response.raise_for_status()
            value = response.json().get("access_token")
            if not isinstance(value, str):
                raise ValueError("Token fixture response invalid")
            return value

    module.get_entra_token_async = token
    module.get_last_token_error = lambda: None
    module.get_token_provenance = lambda: {"source": "local-test-issuer"}
    return instrument(module.app, "/call-backend-raw")


def portal_app(config, directory):
    from portal.app.container import PortalContainer
    from portal.app.main import create_app
    from portal.app.settings import AgentConfig, ControlPlaneConfig, PortalSettings

    network = LocalHTTP([config["caller_url"], config["management_url"]])
    caller_id = config["caller_spiffe_id"]
    settings = PortalSettings(
        mode="live", runtime_environment="local", trust_domain=urlsplit(caller_id).netloc,
        auth_client_id="browser-fixture-client", admin_group_id="fixture-admin-group",
        viewer_group_id="fixture-viewer-group", azure_tenant_id="fixture-tenant",
        mgmt_api_key=config["admin_key"], ca_risk_provider="sidecar",
        agents={
            "budget-report": AgentConfig(
                key="budget-report", name="BudgetReport", role="Read-only Caller",
                url=config["caller_url"], spiffe_id=caller_id, entra_agent_id="fixture-agent"),
            "budget-backend": AgentConfig(
                key="budget-backend", name="BudgetBackend", role="Protected Resource",
                url=config["management_url"], spiffe_id="spiffe://connected.test/backend",
                entra_agent_id="fixture-backend"),
        },
        control_plane=ControlPlaneConfig(
            "LocalControl", config["management_url"], "spiffe://connected.test/control", "fixture-control"),
        policy_store_path=str(directory / "policies.json"),
        external_agent_store_path=str(directory / "external.json"),
    )

    @asynccontextmanager
    async def lifespan(app):
        async with network.AsyncClient(timeout=10) as client:
            with patch("portal.app.container.load_settings", AsyncMock(return_value=settings)):
                container = await PortalContainer.create("not-read.json", client)
            container.auth._validator = IdentityBoundary()
            app.state.container = container
            app.state.index_path = ROOT / "portal" / "index.html"
            yield

    app = create_app()
    app.router.lifespan_context = lifespan
    return app


def security_app(config):
    path = ROOT / "securityportal-mock" / "server.py"
    spec = importlib.util.spec_from_file_location("connected_security_portal", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.AUTH_CLIENT_ID = "browser-fixture-client"
    module.ISP_ADMIN_GROUP_ID = "fixture-admin-group"
    module.ISP_VIEWER_GROUP_ID = "fixture-viewer-group"
    module._jwt_validator = IdentityBoundary()
    module.MGMT_URL = local_origin(config["management_url"]) + "/admin"
    module.MGMT_API_KEY = config["admin_key"]
    module.AGENT_CONFIG = {
        "budget-report": {"name": "BudgetReport", "role": "Read-only Caller",
                          "spiffe_id": config["caller_spiffe_id"], "entra_agent_id": "fixture-agent"}}
    module.httpx = LocalHTTP([config["management_url"]])

    async def external_risk(_oid, _risk):
        return {"entra_status": "skipped", "reason": "Local test does not change tenant risk"}

    module._push_risk_to_entra = external_risk
    return module.app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", choices=("backend", "caller", "portal", "security"), required=True)
    parser.add_argument("--socket-fd", type=int, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    logging.disable(logging.CRITICAL)
    factories = {"backend": backend_app, "caller": lambda: caller_app(config),
                 "portal": lambda: portal_app(config, args.config.parent),
                 "security": lambda: security_app(config)}
    app = factories[args.app]()
    with socket.socket(fileno=args.socket_fd) as listener:
        server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False))
        server.run(sockets=[listener])


if __name__ == "__main__":
    main()
