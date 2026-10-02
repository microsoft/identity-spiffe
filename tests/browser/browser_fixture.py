"""Serve the real apps with deterministic identity and HTTP client boundaries.

Only launched in a credential-free child process by the local browser adapter.
No cloud config loader, token endpoint or environment discovery is executed.
"""
import argparse
from contextlib import asynccontextmanager
import importlib.util
import json
import logging
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

AGENTS = {
    key: {"name": name, "role": role, "url": f"https://{key}.fixture.invalid",
          "spiffe_id": f"spiffe://browser.test/agent/{key}", "entra_agent_id": key}
    for key, name, role in [
        ("budget-report", "BudgetReport", "Read-only Caller"),
        ("budget-approval", "BudgetApproval", "Read and Submit Caller"),
        ("budget-backend", "BudgetBackend", "Protected Resource"),
    ]
}


class IdentityBoundary:
    def validate_token(self, token):
        if token not in {"fixture-admin", "fixture-viewer", "fixture-unassigned"}:
            raise ValueError("unknown fixture identity")
        return {"fixture_role": token.removeprefix("fixture-")}

    def check_role(self, claims):
        role = claims["fixture_role"]
        if role == "unassigned":
            raise PermissionError("fixture identity has no assigned role")
        return role

    def get_user_info(self, claims, role):
        return {"name": "Browser Fixture", "email": "", "role": role,
                "groups": [], "oid": "fixture-operator"}


class ControlPlaneBoundary:
    def __init__(self):
        self.policy = {
            "version": "browser-fixture", "trust_domain": "browser.test",
            "default_action": "deny",
            "admin_governance": {"enabled": True, "risk_enforcement": "off"},
            "policies": [
                {"name": key, "spiffe_id": value["spiffe_id"],
                 "rules": [{"path": "/budget/read", "methods": ["GET"], "action": "allow"}]}
                for key, value in AGENTS.items()
            ],
        }

    def handle(self, request):
        if request.url.host not in {
            "control.fixture.invalid", "budget-report.fixture.invalid",
            "budget-approval.fixture.invalid", "budget-backend.fixture.invalid",
        }:
            raise AssertionError("unexpected outbound fixture host")
        if request.url.path == "/call-backend-raw" and request.method == "POST":
            allowed = request.url.params.get("method") == "GET" and request.url.params.get("path") == "/budget/read"
            return httpx.Response(200, json={
                "http_status": 200 if allowed else 403,
                "layer": "rbac", "response": {"fixture": True, "allowed": allowed},
            })
        if request.method == "PUT" and request.url.path == "/admin/policy":
            import yaml
            self.policy = yaml.safe_load(request.content)
            return httpx.Response(200, json={"status": "updated"})
        payloads = {
            "/admin/health": {"status": "ok", "spiffe_id": AGENTS["budget-backend"]["spiffe_id"],
                              "svid_ready": True, "uptime_seconds": 100,
                              "risk_enforcement_control_supported": True,
                              "entra_risk_enforcement_supported": True},
            "/admin/policy": self.policy,
            "/admin/mtls-policy": {"allowed_ids": [a["spiffe_id"] for a in AGENTS.values()]},
            "/admin/audit": {"entries": []},
            "/admin/metrics": {"requests_total": 0},
            "/admin/oauth-status": {"enabled": True, "validator_ready": True},
            "/admin/agent-risk": {"risks": {"spiffe://browser.test/control": "low"}, "count": 1},
            "/admin/entra-risk": {"risks": {"spiffe://browser.test/control": "low"}, "source": "entra"},
            "/admin/agent-tags": {"tags": {}},
            "/admin/ca-policy-effective": {"policies": [], "source": "browser-fixture",
                                           "ready": True, "blocked_risk_levels": ["high"]},
        }
        if request.method == "GET" and request.url.path in payloads:
            return httpx.Response(200, json=payloads[request.url.path])
        raise AssertionError("unexpected fixture request")


def management_app(directory):
    from portal.app.container import PortalContainer
    from portal.app.main import create_app
    from portal.app.settings import AgentConfig, ControlPlaneConfig, PortalSettings
    from fastapi.responses import StreamingResponse

    settings = PortalSettings(
        mode="live", runtime_environment="local", trust_domain="browser.test",
        auth_client_id="browser-fixture-client", admin_group_id="fixture-admin-group",
        viewer_group_id="fixture-viewer-group", azure_tenant_id="fixture-tenant",
        ca_risk_provider="sidecar",
        agents={k: AgentConfig(key=k, **v) for k, v in AGENTS.items()},
        control_plane=ControlPlaneConfig("FixtureControl", "https://control.fixture.invalid",
                                        "spiffe://browser.test/control", "fixture-control"),
        policy_store_path=str(directory / "policies.json"),
        external_agent_store_path=str(directory / "external-agents.json"),
    )
    boundary = ControlPlaneBoundary()

    @asynccontextmanager
    async def lifespan(app):
        async with httpx.AsyncClient(transport=httpx.MockTransport(boundary.handle)) as client:
            with patch("portal.app.container.load_settings", AsyncMock(return_value=settings)):
                container = await PortalContainer.create("not-read.json", client)
            container.auth._validator = IdentityBoundary()
            async def stream(*_args):
                async def chunks():
                    yield ": fixture connected\n\n"
                return StreamingResponse(chunks(), media_type="text/event-stream")
            container.admin_client.open_stream = stream
            app.state.container = container
            app.state.index_path = ROOT / "portal" / "index.html"
            yield
    app = create_app()
    app.router.lifespan_context = lifespan
    return app


def security_app():
    spec = importlib.util.spec_from_file_location(
        "identity_browser_security_fixture", ROOT / "securityportal-mock" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.AUTH_CLIENT_ID = "browser-fixture-client"
    module.ISP_ADMIN_GROUP_ID = "fixture-admin-group"
    module.ISP_VIEWER_GROUP_ID = "fixture-viewer-group"
    module._jwt_validator = IdentityBoundary()
    module.AGENT_CONFIG = AGENTS
    module.MGMT_URL = "https://control.fixture.invalid/admin"
    boundary = ControlPlaneBoundary()
    module.httpx = SimpleNamespace(AsyncClient=lambda **_kwargs: httpx.AsyncClient(
        transport=httpx.MockTransport(boundary.handle)))
    return module.app


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--portal", choices=("management", "security"), required=True)
    parser.add_argument("--socket-fd", type=int, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    app = management_app(args.directory) if args.portal == "management" else security_app()
    logging.disable(logging.CRITICAL)
    server = uvicorn.Server(uvicorn.Config(app, log_config=None, access_log=False))
    with socket.socket(fileno=args.socket_fd) as listener:
        server.run(sockets=[listener])


if __name__ == "__main__":
    main()
