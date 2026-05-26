"""Health and system status services."""

from typing import Any, Dict

from ..version import get_portal_version


class HealthService:
    """Reports application and dependency health."""

    def __init__(self, settings, admin_client, policy_store, graph_client):
        # type: (Any, Any, Any, Any) -> None
        self.settings = settings
        self.admin_client = admin_client
        self.policy_store = policy_store
        self.graph_client = graph_client

    def live_status(self):
        # type: () -> Dict[str, Any]
        return {
            "status": "ok",
            "portal_version": get_portal_version(),
            "mode": self.settings.mode,
            "runtime_environment": self.settings.runtime_environment,
        }

    async def ready_status(self, request_id):
        # type: (str) -> Dict[str, Any]
        system_status = await self.system_status(request_id)
        system_status["ready"] = system_status["status"] == "healthy"
        return system_status

    async def sidecar_health(self, request_id):
        # type: (str) -> Dict[str, Any]
        result = await self.admin_client.get_json("health", request_id)
        result.update(
            {
                "portal_version": get_portal_version(),
                "mode": self.settings.mode,
                "runtime_environment": self.settings.runtime_environment,
            }
        )
        return result

    async def system_status(self, request_id):
        # type: (str) -> Dict[str, Any]
        components = []
        admin_error = None
        storage_error = None
        try:
            await self.admin_client.get_json("health", request_id)
            components.append({"name": "admin_control_plane", "status": "healthy"})
        except Exception as exc:
            admin_error = str(exc)
            components.append({"name": "admin_control_plane", "status": "failed", "detail": admin_error})
        try:
            storage_health = await self.policy_store.healthcheck()
            components.append({"name": "policy_store", **storage_health})
        except Exception as exc:
            storage_error = str(exc)
            components.append({"name": "policy_store", "status": "failed", "detail": storage_error})
        components.append(
            {
                "name": "graph",
                "status": "healthy" if self.graph_client.configured else "degraded",
                "detail": "client_credentials" if self.graph_client.configured else "not_configured",
            }
        )
        components.append(
            {
                "name": "agent_directory",
                "status": "healthy" if self.settings.agents else "degraded",
                "count": len(self.settings.agents),
            }
        )
        overall = "healthy"
        if admin_error or storage_error:
            overall = "failed"
        elif any(component.get("status") == "degraded" for component in components):
            overall = "degraded"
        return {
            "status": overall,
            "mode": self.settings.mode,
            "runtime_environment": self.settings.runtime_environment,
            "portal_version": get_portal_version(),
            "components": components,
        }
