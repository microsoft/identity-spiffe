"""Application container for shared runtime state."""

from dataclasses import dataclass
from typing import Any

import httpx

from .auth import PortalAuth
from .clients import AdminControlPlaneClient, AgentInvokerClient, GraphClient
from .settings import PortalSettings, load_settings
from .storage import BlobExternalAgentStore, BlobPolicyConfigStore, FileExternalAgentStore, FilePolicyConfigStore
from .services import CAService, HealthService, PolicyService, ScanService


@dataclass
class PortalContainer:
    settings: PortalSettings
    http_client: httpx.AsyncClient
    auth: PortalAuth
    admin_client: AdminControlPlaneClient
    agent_invoker: AgentInvokerClient
    graph_client: GraphClient
    policy_store: Any
    external_agent_store: Any
    policy_service: PolicyService
    scan_service: ScanService
    ca_service: CAService
    health_service: HealthService

    @classmethod
    async def create(cls, config_path, http_client):
        # type: (str, httpx.AsyncClient) -> "PortalContainer"
        settings = await load_settings(config_path)
        auth = PortalAuth(settings)
        admin_client = AdminControlPlaneClient(http_client, settings.control_plane.url, settings.mgmt_api_key)
        agent_invoker = AgentInvokerClient(http_client)
        graph_client = GraphClient(
            http_client=http_client,
            tenant_id=settings.azure_tenant_id,
            client_id=settings.graph_client_id,
            client_secret=settings.graph_client_secret,
        )
        if settings.policy_store_provider == "blob":
            policy_store = BlobPolicyConfigStore(
                account_url=settings.policy_store_account_url,
                container=settings.policy_store_container,
                blob_name=settings.policy_store_blob,
                managed_identity_client_id=settings.azure_client_id,
            )
        else:
            policy_store = FilePolicyConfigStore(settings.policy_store_path)
        if settings.external_agent_store_provider == "blob" and settings.external_agent_store_account_url:
            external_agent_store = BlobExternalAgentStore(
                account_url=settings.external_agent_store_account_url,
                container=settings.external_agent_store_container,
                blob_name=settings.external_agent_store_blob,
                managed_identity_client_id=settings.azure_client_id,
            )
        else:
            external_agent_store = FileExternalAgentStore(settings.external_agent_store_path)
        policy_service = PolicyService(settings, admin_client, policy_store)
        scan_service = ScanService(policy_service)
        ca_service = CAService(settings, admin_client, graph_client, agent_invoker)
        health_service = HealthService(settings, admin_client, policy_store, graph_client)
        return cls(
            settings=settings,
            http_client=http_client,
            auth=auth,
            admin_client=admin_client,
            agent_invoker=agent_invoker,
            graph_client=graph_client,
            policy_store=policy_store,
            external_agent_store=external_agent_store,
            policy_service=policy_service,
            scan_service=scan_service,
            ca_service=ca_service,
            health_service=health_service,
        )

    async def reload_local_settings(self):
        # type: () -> None
        refreshed = await type(self).create(self.settings.config_path, self.http_client)
        self.__dict__.update(refreshed.__dict__)
