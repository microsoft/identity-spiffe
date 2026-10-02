import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from portal.app.errors import PortalError, handle_portal_error
from portal.app.routers.api import router


class TestRiskCacheAPI(unittest.TestCase):
    def client(self, role):
        async def admin_only(_request):
            if role != "admin":
                raise PortalError(403, "forbidden", "Administrator access required")
            return {"role": role}

        service = SimpleNamespace(set_cache_seconds=AsyncMock(return_value={"risk_cache_seconds": 0}))
        app = FastAPI()
        app.state.container = SimpleNamespace(
            auth=SimpleNamespace(admin_only=admin_only), risk_settings_service=service,
        )
        app.add_exception_handler(PortalError, handle_portal_error)
        app.include_router(router)
        return TestClient(app), service

    def test_cache_requires_admin(self):
        client, service = self.client("viewer")
        with client:
            self.assertEqual(client.put("/api/settings/risk-cache", json={"seconds": 0}).status_code, 403)
        service.set_cache_seconds.assert_not_awaited()

    def test_cache_accepts_zero_and_positive_whole_seconds(self):
        client, service = self.client("admin")
        with client:
            for seconds in (0, 90, 120):
                self.assertEqual(client.put("/api/settings/risk-cache", json={"seconds": seconds}).status_code, 200)
                service.set_cache_seconds.assert_awaited_with(seconds, "")

    def test_cache_rejects_malformed_values_before_mutation(self):
        client, service = self.client("admin")
        with client:
            for value in (None, True, -1, 1.5, "90", 9223372037):
                self.assertEqual(client.put("/api/settings/risk-cache", json={"seconds": value}).status_code, 422)
        service.set_cache_seconds.assert_not_awaited()
