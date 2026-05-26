"""Tests for GET /api/audit/stream SSE route."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

_repo_root = Path(__file__).resolve().parent.parent.parent
if str(_repo_root) not in sys.path:
    sys.path.insert(0, str(_repo_root))

from portal.app.dependencies import viewer_or_admin
from portal.app.errors import PortalError, handle_portal_error
from portal.app.routers import api as api_router


class TestAuditStreamRoute(unittest.TestCase):
    def _build_app(self, authorized):
        app = FastAPI()
        app.add_exception_handler(PortalError, handle_portal_error)

        fake_admin_client = SimpleNamespace(
            open_stream=AsyncMock(
                return_value=StreamingResponse(
                    iter([b"data: {\"decision\":\"allow\"}\n\n"]),
                    media_type="text/event-stream",
                )
            )
        )
        container = SimpleNamespace(admin_client=fake_admin_client)
        app.state.container = container

        app.include_router(api_router.router)

        async def _override_auth():
            if authorized:
                return {"role": "viewer"}
            raise PortalError(401, "unauthenticated", "not signed in")

        app.dependency_overrides[viewer_or_admin] = _override_auth
        return app, fake_admin_client

    def test_authorized_request_streams_payload(self):
        app, admin_client = self._build_app(authorized=True)
        with TestClient(app) as client:
            resp = client.get("/api/audit/stream")
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(resp.headers["content-type"].startswith("text/event-stream"))
            self.assertIn("data: ", resp.text)
            admin_client.open_stream.assert_awaited_once_with("audit/stream", "")

    def test_unauthorized_request_rejected(self):
        app, _ = self._build_app(authorized=False)
        with TestClient(app) as client:
            resp = client.get("/api/audit/stream")
            self.assertIn(resp.status_code, (401, 403))


if __name__ == "__main__":
    unittest.main()
