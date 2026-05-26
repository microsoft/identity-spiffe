import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from portal.app.errors import PortalError
from portal.app.main import create_app
from portal.app.services.health import HealthService
from portal.app.settings import ControlPlaneConfig, PortalSettings


class _AdminAuth:
    async def viewer_or_admin(self, _request):
        return {"role": "admin"}

    async def admin_only(self, _request):
        return {"role": "admin"}


def _settings():
    return PortalSettings(
        mode="live",
        runtime_environment="cloud",
        trust_domain="aim.microsoft.com",
        control_plane=ControlPlaneConfig(
            name="AdminControlPlane",
            url="https://admin-control-plane.example",
            spiffe_id="spiffe://aim.microsoft.com/ests/bp/x/aid/admin",
            entra_agent_id="admin-app-id",
        ),
        agents={
            "budget-report": SimpleNamespace(
                name="BudgetReport",
                role="Read-only Caller",
                url="https://budget-report.example",
                spiffe_id="spiffe://aim.microsoft.com/ests/bp/x/aid/report",
                entra_agent_id="report-app-id",
            )
        },
    )


class _GraphClient:
    configured = False


class _HealthyStore:
    async def healthcheck(self):
        return {"status": "healthy", "backend": "file"}


class _FailingAdminClient:
    async def get_json(self, _path, _request_id):
        raise PortalError(503, "admin_control_plane_unreachable", "control plane unavailable")


class _FakeContainer:
    def __init__(self):
        self.settings = _settings()
        self.auth = _AdminAuth()
        self.health_service = SimpleNamespace(
            sidecar_health=AsyncMock(side_effect=PortalError(503, "admin_control_plane_unreachable", "control plane unavailable")),
            system_status=AsyncMock(
                return_value={
                    "status": "failed",
                    "components": [{"name": "admin_control_plane", "status": "failed"}],
                }
            ),
        )
        self.policy_service = SimpleNamespace(
            get_control_plane_spiffe_id=lambda: self.settings.control_plane.spiffe_id,
        )
        self.agent_invoker = SimpleNamespace()
        self.ca_service = SimpleNamespace()
        self.scan_service = SimpleNamespace()

    async def reload_local_settings(self):
        return None


class TestHealthService(unittest.IsolatedAsyncioTestCase):
    async def test_system_status_reports_failed_dependencies_truthfully(self):
        service = HealthService(_settings(), _FailingAdminClient(), _HealthyStore(), _GraphClient())

        payload = await service.system_status("req-1")
        ready = await service.ready_status("req-1")

        self.assertEqual(payload["status"], "failed")
        self.assertFalse(ready["ready"])
        admin_component = next(component for component in payload["components"] if component["name"] == "admin_control_plane")
        self.assertEqual(admin_component["status"], "failed")


class TestPortalApi(unittest.TestCase):
    @contextmanager
    def _client(self):
        fake_container = _FakeContainer()
        with patch("portal.app.main.PortalContainer.create", new=AsyncMock(return_value=fake_container)):
            app = create_app("unused.json")
            with TestClient(app) as client:
                yield client

    def test_reset_demo_route_is_not_present(self):
        with self._client() as client:
            response = client.post("/api/reset-demo")

        self.assertEqual(response.status_code, 404)

    def test_health_endpoint_returns_dependency_failure(self):
        with self._client() as client:
            response = client.get("/api/health")

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error_code"], "admin_control_plane_unreachable")

    def test_quick_fix_blocks_control_plane_removal(self):
        with self._client() as client:
            response = client.post(
                "/api/quick-fix",
                json={
                    "fix_type": "mtls-remove",
                    "fix_payload": {"remove_id": "spiffe://aim.microsoft.com/ests/bp/x/aid/admin"},
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error_code"], "invalid_fix_payload")

    def test_request_validation_uses_structured_error_envelope(self):
        with self._client() as client:
            response = client.post(
                "/api/execute",
                json={"caller": "budget-report", "method": "PATCH", "path": "/budget/read"},
            )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["error_code"], "request_validation")
