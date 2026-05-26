import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from portal.app.errors import PortalError
from portal.app.settings import _discover_cloud_agents, load_settings


class _FakeDiscoveryClient:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        if self.error is not None:
            raise self.error
        return self.response


class TestPortalSettings(unittest.IsolatedAsyncioTestCase):
    async def test_local_settings_require_mgmt_api_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "portal-config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "trust_domain": "aim.microsoft.com",
                        "agents": {},
                        "control_plane": {"url": "https://admin-control-plane.example"},
                    }
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                with self.assertRaises(PortalError) as ctx:
                    await load_settings(str(config_path))

        self.assertEqual(ctx.exception.error_code, "settings_missing")
        self.assertIn("MGMT API key", ctx.exception.detail)

    async def test_cloud_settings_fail_fast_on_missing_mgmt_api_key(self):
        env = {
            "PORTAL_MODE": "cloud",
            "ADMIN_CP_URL": "https://admin-control-plane.example",
            "AUTH_CLIENT_ID": "portal-client-id",
            "AIM_ADMIN_GROUP_ID": "admin-group-id",
            "AIM_VIEWER_GROUP_ID": "viewer-group-id",
            "AZURE_TENANT_ID": "tenant-id",
            "POLICY_CONFIG_BLOB_ACCOUNT_URL": "https://storage.example.blob.core.windows.net/",
            "POLICY_CONFIG_BLOB_CONTAINER": "portal-policy-configs",
            "POLICY_CONFIG_BLOB_NAME": "policy-configs.json",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(PortalError) as ctx:
                await load_settings("unused.json")

        self.assertEqual(ctx.exception.error_code, "settings_missing")
        self.assertEqual(ctx.exception.meta["name"], "MGMT_API_KEY")

    async def test_cloud_settings_default_to_blob_store(self):
        env = {
            "PORTAL_MODE": "cloud",
            "ADMIN_CP_URL": "https://admin-control-plane.example",
            "MGMT_API_KEY": "super-secret",
            "AUTH_CLIENT_ID": "portal-client-id",
            "AIM_ADMIN_GROUP_ID": "admin-group-id",
            "AIM_VIEWER_GROUP_ID": "viewer-group-id",
            "AZURE_TENANT_ID": "tenant-id",
            "POLICY_CONFIG_BLOB_ACCOUNT_URL": "https://storage.example.blob.core.windows.net/",
            "POLICY_CONFIG_BLOB_CONTAINER": "portal-policy-configs",
            "POLICY_CONFIG_BLOB_NAME": "policy-configs.json",
        }
        discovery = {
            "agents": {},
            "control_plane": {
                "name": "AdminControlPlane",
                "url": "https://admin-control-plane.example",
                "spiffe_id": "spiffe://aim.microsoft.com/ests/bp/x/aid/admin",
                "entra_agent_id": "admin-app-id",
                "role": "admin-control-plane",
            },
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("portal.app.settings._discover_cloud_agents", new=AsyncMock(return_value=discovery)):
                settings = await load_settings("unused.json")

        self.assertEqual(settings.runtime_environment, "cloud")
        self.assertEqual(settings.mode, "live")
        self.assertEqual(settings.policy_store_provider, "blob")
        self.assertEqual(settings.policy_store_container, "portal-policy-configs")
        self.assertEqual(settings.control_plane.url, "https://admin-control-plane.example")

    async def test_cloud_agent_discovery_failure_is_fatal(self):
        response = httpx.Response(
            503,
            request=httpx.Request("GET", "https://admin-control-plane.example/admin/agents"),
            text="service unavailable",
        )
        fake_client = _FakeDiscoveryClient(response=response)

        with patch("portal.app.settings.httpx.AsyncClient", return_value=fake_client):
            with self.assertRaises(PortalError) as ctx:
                await _discover_cloud_agents("https://admin-control-plane.example", "super-secret")

        self.assertEqual(ctx.exception.status_code, 503)
        self.assertEqual(ctx.exception.error_code, "agent_discovery_failed")
