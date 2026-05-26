import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx

from portal.app.clients.admin_control_plane import AdminControlPlaneClient
from portal.app.clients.agent_invoker import AgentInvokerClient
from portal.app.clients.graph import GraphClient
from portal.app.errors import PortalError


def _request(method, url):
    return httpx.Request(method, url)


class TestGraphClient(unittest.IsolatedAsyncioTestCase):
    async def test_fetch_risky_agents_requires_graph_credentials(self):
        client = GraphClient(http_client=SimpleNamespace(), tenant_id="")

        with self.assertRaises(PortalError) as ctx:
            await client.fetch_risky_agents()

        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.error_code, "graph_not_configured")

    async def test_push_agent_risk_raises_when_graph_rejects_update(self):
        http_client = SimpleNamespace(
            post=AsyncMock(
                return_value=httpx.Response(
                    500,
                    request=_request("POST", "https://graph.microsoft.com/beta/identityProtection/riskyAgents/confirmCompromised"),
                    text="boom",
                )
            )
        )
        client = GraphClient(http_client=http_client, tenant_id="tenant-id", client_id="client-id", client_secret="secret")
        client.require_token = AsyncMock(return_value="graph-token")
        client.resolve_service_principal_object_id = AsyncMock(return_value="service-principal-oid")

        with self.assertRaises(PortalError) as ctx:
            await client.push_agent_risk("agent-app-id", "high")

        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(ctx.exception.error_code, "graph_risk_update_failed")

    async def test_read_custom_security_attribute_raises_on_graph_failure(self):
        fake_guid = "00000000-1111-2222-3333-444444444444"
        http_client = SimpleNamespace(
            get=AsyncMock(
                side_effect=[
                    httpx.Response(
                        403,
                        request=_request("GET", "https://graph.microsoft.com/v1.0/servicePrincipals/" + fake_guid),
                        text="forbidden",
                    ),
                    httpx.Response(
                        403,
                        request=_request("GET", "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId"),
                        text="forbidden",
                    ),
                ]
            )
        )
        client = GraphClient(http_client=http_client, tenant_id="tenant-id", client_id="client-id", client_secret="secret")
        client.require_token = AsyncMock(return_value="graph-token")

        with self.assertRaises(PortalError) as ctx:
            await client.read_custom_security_attribute(fake_guid, "AgentIdentity", "Department")

        self.assertEqual(ctx.exception.status_code, 502)
        self.assertEqual(ctx.exception.error_code, "graph_attribute_lookup_failed")


class TestAgentInvokerClient(unittest.IsolatedAsyncioTestCase):
    async def test_flush_token_wraps_transport_errors(self):
        http_client = SimpleNamespace(
            post=AsyncMock(
                side_effect=httpx.RequestError(
                    "connection refused",
                    request=_request("POST", "https://budget-report.example/flush-token"),
                )
            )
        )
        client = AgentInvokerClient(http_client)

        with self.assertRaises(PortalError) as ctx:
            await client.flush_token("https://budget-report.example", "super-secret", "req-123")

        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.error_code, "agent_unreachable")


class TestAdminControlPlaneClient(unittest.IsolatedAsyncioTestCase):
    async def test_get_json_retries_idempotent_request_errors(self):
        http_client = SimpleNamespace(
            request=AsyncMock(
                side_effect=[
                    httpx.RequestError("transient failure", request=_request("GET", "https://admin-control-plane.example/admin/health")),
                    httpx.Response(200, request=_request("GET", "https://admin-control-plane.example/admin/health"), json={"ok": True}),
                ]
            )
        )
        client = AdminControlPlaneClient(http_client, "https://admin-control-plane.example", "super-secret")

        payload = await client.get_json("health", "req-1")

        self.assertEqual(payload, {"ok": True})
        self.assertEqual(http_client.request.await_count, 2)

    async def test_put_json_does_not_retry_non_idempotent_transport_errors(self):
        http_client = SimpleNamespace(
            request=AsyncMock(
                side_effect=httpx.RequestError(
                    "connection refused",
                    request=_request("PUT", "https://admin-control-plane.example/admin/agent-risk"),
                )
            )
        )
        client = AdminControlPlaneClient(http_client, "https://admin-control-plane.example", "super-secret")

        with self.assertRaises(PortalError) as ctx:
            await client.put_json("agent-risk", {"spiffe_id": "x", "risk_level": "high"}, "req-2")

        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.error_code, "admin_control_plane_unreachable")
        self.assertEqual(http_client.request.await_count, 1)

    async def test_empty_base_url_fails_fast(self):
        client = AdminControlPlaneClient(SimpleNamespace(request=AsyncMock()), "", "super-secret")

        with self.assertRaises(PortalError) as ctx:
            await client.get_json("health", "req-3")

        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.error_code, "admin_control_plane_not_configured")
