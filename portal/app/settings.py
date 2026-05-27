"""Portal settings and configuration discovery."""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

import httpx

from .errors import PortalError

logger = logging.getLogger("isp-portal.settings")


TRUST_DOMAIN = "aim.microsoft.com"
MGMT_PLANE_AGENT_KEY = "admin-control-plane"


@dataclass
class AgentConfig:
    key: str
    name: str
    role: str
    url: str
    spiffe_id: str
    entra_agent_id: str
    app_name: str = ""
    agent_tag: str = ""
    transport: str = "spiffe"       # "spiffe" | "https_only"
    hosting_platform: str = ""      # e.g. "gcp", "external", "" for domestic

    def to_public_dict(self):
        # type: () -> Dict[str, str]
        return {
            "name": self.name,
            "role": self.role,
            "url": self.url,
            "spiffe_id": self.spiffe_id,
            "entra_agent_id": self.entra_agent_id,
            "app_name": self.app_name or self.key,
            "agent_tag": self.agent_tag,
            "transport": self.transport,
            "hosting_platform": self.hosting_platform,
        }


@dataclass
class ControlPlaneConfig:
    name: str
    url: str
    spiffe_id: str
    entra_agent_id: str
    app_name: str = MGMT_PLANE_AGENT_KEY
    role: str = "admin-control-plane"

    def to_public_dict(self):
        # type: () -> Dict[str, str]
        return {
            "name": self.name,
            "url": self.url,
            "spiffe_id": self.spiffe_id,
            "entra_agent_id": self.entra_agent_id,
            "app_name": self.app_name,
            "role": self.role,
        }


@dataclass
class PortalSettings:
    mode: str
    runtime_environment: str
    trust_domain: str
    agents: Dict[str, AgentConfig] = field(default_factory=dict)
    control_plane: ControlPlaneConfig = field(
        default_factory=lambda: ControlPlaneConfig(
            name="AdminControlPlane",
            url="",
            spiffe_id="",
            entra_agent_id="",
        )
    )
    mgmt_api_key: str = ""
    config_path: str = "portal-config.json"
    auth_client_id: str = ""
    admin_group_id: str = ""
    viewer_group_id: str = ""
    azure_tenant_id: str = ""
    graph_client_id: str = ""
    graph_client_secret: str = ""
    policy_store_provider: str = "file"
    policy_store_path: str = ""
    policy_store_account_url: str = ""
    policy_store_container: str = ""
    policy_store_blob: str = ""
    azure_client_id: str = ""
    applicationinsights_connection_string: str = ""
    # External (cross-cloud / federated) agent store
    external_agent_store_provider: str = "file"
    external_agent_store_path: str = ""
    external_agent_store_account_url: str = ""
    external_agent_store_container: str = ""
    external_agent_store_blob: str = ""

    @property
    def auth_required(self):
        # type: () -> bool
        return bool(self.auth_client_id)

    def to_public_dict(self):
        # type: () -> Dict[str, object]
        return {
            "mode": self.mode,
            "runtime_environment": self.runtime_environment,
            "trust_domain": self.trust_domain,
            "agents": {key: agent.to_public_dict() for key, agent in self.agents.items()},
            "control_plane": self.control_plane.to_public_dict(),
            "auth_required": self.auth_required,
        }


def _env_required(name):
    # type: (str) -> str
    value = os.getenv(name, "")
    if not value:
        raise PortalError(500, "settings_missing", "Missing required environment variable", {"name": name})
    return value


async def _discover_cloud_agents(admin_cp_url, mgmt_key):
    # type: (str, str) -> Dict[str, AgentConfig]
    cp_info = {
        "name": "AdminControlPlane",
        "url": admin_cp_url,
        "spiffe_id": "",
        "entra_agent_id": "",
        "role": "admin-control-plane",
    }
    agent_map = {}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, connect=3.0), verify=True) as client:
            resp = await client.get(
                "{0}/admin/agents".format(admin_cp_url.rstrip("/")),
                headers={"X-Spiffe-Admin-Key": mgmt_key},
            )
        if resp.status_code != 200:
            raise PortalError(
                503,
                "agent_discovery_failed",
                "Cloud agent discovery returned HTTP {0}".format(resp.status_code),
                {"status_code": resp.status_code, "body": resp.text[:500]},
            )
        discovered = resp.json().get("agents", {})
        for key, info in discovered.items():
            if key == MGMT_PLANE_AGENT_KEY:
                cp_info = {
                    "name": info.get("name", "AdminControlPlane"),
                    "url": info.get("url", admin_cp_url),
                    "spiffe_id": info.get("spiffe_id", ""),
                    "entra_agent_id": info.get("entra_agent_id", ""),
                    "role": info.get("role", "admin-control-plane"),
                }
                continue
            agent_map[key] = AgentConfig(
                key=key,
                name=info.get("name", key),
                role=info.get("role", ""),
                url=info.get("url", ""),
                spiffe_id=info.get("spiffe_id", ""),
                entra_agent_id=info.get("entra_agent_id", ""),
                app_name=info.get("app_name", key),
                agent_tag=info.get("agent_tag", ""),
                transport=info.get("transport", "spiffe"),
                hosting_platform=info.get("hosting_platform", ""),
            )
    except PortalError:
        raise
    except httpx.RequestError as exc:
        logger.exception("Cloud agent discovery request failed")
        raise PortalError(503, "agent_discovery_failed", "Cloud agent discovery failed", {"detail": str(exc)})
    except Exception:
        logger.exception("Cloud agent discovery failed")
        raise PortalError(503, "agent_discovery_failed", "Cloud agent discovery failed")
    return {"agents": agent_map, "control_plane": cp_info}


def _coerce_local_agents(raw_agents):
    # type: (Dict[str, dict]) -> Dict[str, AgentConfig]
    agents = {}
    for key, info in (raw_agents or {}).items():
        agents[key] = AgentConfig(
            key=key,
            name=info.get("name", key),
            role=info.get("role", ""),
            url=info.get("url", ""),
            spiffe_id=info.get("spiffe_id", ""),
            entra_agent_id=info.get("entra_agent_id", ""),
            app_name=info.get("app_name", key),
            agent_tag=info.get("agent_tag", ""),
            transport=info.get("transport", "spiffe"),
            hosting_platform=info.get("hosting_platform", ""),
        )
    return agents


async def load_settings(config_path):
    # type: (str) -> PortalSettings
    runtime_environment = "cloud" if os.getenv("PORTAL_MODE") == "cloud" else "local"
    auth_client_id = os.getenv("AUTH_CLIENT_ID", "")
    admin_group_id = os.getenv("ISP_ADMIN_GROUP_ID", "")
    viewer_group_id = os.getenv("ISP_VIEWER_GROUP_ID", "")
    azure_tenant_id = os.getenv("AZURE_TENANT_ID", "")
    graph_client_id = os.getenv("GRAPH_CLIENT_ID", "") or os.getenv("ENTRA_AGENTID_CLIENT_ID", "")
    graph_client_secret = os.getenv("GRAPH_CLIENT_SECRET", "") or os.getenv("ENTRA_AGENTID_CLIENT_SECRET", "")
    appinsights_connection_string = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING", "")
    azure_client_id = os.getenv("AZURE_CLIENT_ID", "")

    if runtime_environment == "cloud":
        admin_cp_url = _env_required("ADMIN_CP_URL")
        mgmt_api_key = _env_required("MGMT_API_KEY")
        auth_client_id = _env_required("AUTH_CLIENT_ID")
        admin_group_id = _env_required("ISP_ADMIN_GROUP_ID")
        viewer_group_id = _env_required("ISP_VIEWER_GROUP_ID")
        azure_tenant_id = _env_required("AZURE_TENANT_ID")
        policy_store_provider = os.getenv("POLICY_CONFIG_STORE_PROVIDER", "blob")
        policy_store_account_url = _env_required("POLICY_CONFIG_BLOB_ACCOUNT_URL")
        policy_store_container = _env_required("POLICY_CONFIG_BLOB_CONTAINER")
        policy_store_blob = _env_required("POLICY_CONFIG_BLOB_NAME")
        # External agent store — optional; falls back to empty in-memory list if unset
        ext_store_provider = os.getenv("EXTERNAL_AGENT_STORE_PROVIDER", "blob")
        ext_store_account_url = os.getenv("EXTERNAL_AGENT_STORE_BLOB_ACCOUNT_URL", "")
        ext_store_container = os.getenv("EXTERNAL_AGENT_STORE_BLOB_CONTAINER", "")
        ext_store_blob = os.getenv("EXTERNAL_AGENT_STORE_BLOB_NAME", "external-agents.json")
        discovery = await _discover_cloud_agents(admin_cp_url, mgmt_api_key)
        control_plane = ControlPlaneConfig(
            name=discovery["control_plane"].get("name", "AdminControlPlane"),
            url=discovery["control_plane"].get("url", admin_cp_url),
            spiffe_id=discovery["control_plane"].get("spiffe_id", ""),
            entra_agent_id=discovery["control_plane"].get("entra_agent_id", ""),
            role=discovery["control_plane"].get("role", "admin-control-plane"),
        )
        return PortalSettings(
            mode="live",
            runtime_environment=runtime_environment,
            trust_domain=TRUST_DOMAIN,
            agents=discovery["agents"],
            control_plane=control_plane,
            mgmt_api_key=mgmt_api_key,
            config_path=config_path,
            auth_client_id=auth_client_id,
            admin_group_id=admin_group_id,
            viewer_group_id=viewer_group_id,
            azure_tenant_id=azure_tenant_id,
            graph_client_id=graph_client_id,
            graph_client_secret=graph_client_secret,
            policy_store_provider=policy_store_provider,
            policy_store_account_url=policy_store_account_url,
            policy_store_container=policy_store_container,
            policy_store_blob=policy_store_blob,
            azure_client_id=azure_client_id,
            applicationinsights_connection_string=appinsights_connection_string,
            external_agent_store_provider=ext_store_provider,
            external_agent_store_account_url=ext_store_account_url,
            external_agent_store_container=ext_store_container,
            external_agent_store_blob=ext_store_blob,
        )

    path = Path(config_path)
    if not path.exists():
        raise PortalError(500, "settings_missing", "Portal config file not found", {"path": config_path})
    with path.open(encoding="utf-8") as handle:
        raw = json.load(handle)
    mgmt_api_key = raw.get("mgmt_api_key", "") or os.getenv("MGMT_API_KEY", "")
    if not mgmt_api_key:
        raise PortalError(500, "settings_missing", "MGMT API key is required for local portal use")
    control_plane_data = raw.get("control_plane", {})
    control_plane = ControlPlaneConfig(
        name=control_plane_data.get("name", "AdminControlPlane"),
        url=control_plane_data.get("url", ""),
        spiffe_id=control_plane_data.get("spiffe_id", ""),
        entra_agent_id=control_plane_data.get("entra_agent_id", ""),
        app_name=control_plane_data.get("app_name", MGMT_PLANE_AGENT_KEY),
        role=control_plane_data.get("role", "admin-control-plane"),
    )
    return PortalSettings(
        mode="live",
        runtime_environment=runtime_environment,
        trust_domain=raw.get("trust_domain", TRUST_DOMAIN),
        agents=_coerce_local_agents(raw.get("agents", {})),
        control_plane=control_plane,
        mgmt_api_key=mgmt_api_key,
        config_path=config_path,
        auth_client_id=auth_client_id,
        admin_group_id=admin_group_id,
        viewer_group_id=viewer_group_id,
        azure_tenant_id=azure_tenant_id,
        graph_client_id=graph_client_id,
        graph_client_secret=graph_client_secret,
        policy_store_provider=os.getenv("POLICY_CONFIG_STORE_PROVIDER", "file"),
        policy_store_path=os.getenv(
            "POLICY_CONFIG_FILE",
            str(path.parent / "policy-configs.json"),
        ),
        azure_client_id=azure_client_id,
        applicationinsights_connection_string=appinsights_connection_string,
        external_agent_store_provider=os.getenv("EXTERNAL_AGENT_STORE_PROVIDER", "file"),
        external_agent_store_path=os.getenv(
            "EXTERNAL_AGENT_STORE_FILE",
            str(path.parent / "external-agents.json"),
        ),
    )
