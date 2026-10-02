"""Configuration refresh must retain risk-update serialization."""

import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from portal.app.container import PortalContainer


class TestContainerRiskSettings(unittest.IsolatedAsyncioTestCase):
    async def test_config_reload_retains_shared_risk_update_lock(self):
        container = object.__new__(PortalContainer)
        container.settings = SimpleNamespace(config_path="portal-config.json")
        container.http_client = object()
        lock = asyncio.Lock()
        container.risk_settings_service = SimpleNamespace(_update_lock=lock)
        refreshed = SimpleNamespace(
            risk_settings_service=SimpleNamespace(_update_lock=asyncio.Lock()),
            settings=container.settings,
            http_client=container.http_client,
        )
        with patch.object(PortalContainer, "create", AsyncMock(return_value=refreshed)):
            await container.reload_settings()
        self.assertIs(container.risk_settings_service._update_lock, lock)
