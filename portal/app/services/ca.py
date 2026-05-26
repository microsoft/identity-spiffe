"""Conditional Access and Graph-backed management helpers."""

import asyncio
from typing import Any, Dict

from ..errors import PortalError


class CAService:
    """Coordinates admin-control-plane and Graph operations."""

    def __init__(self, settings, admin_client, graph_client, agent_invoker):
        # type: (Any, Any, Any, Any) -> None
        self.settings = settings
        self.admin_client = admin_client
        self.graph_client = graph_client
        self.agent_invoker = agent_invoker

    def _resolve_agent_oid(self, spiffe_id):
        # type: (str) -> str
        if "/aid/" in spiffe_id:
            return spiffe_id.split("/aid/")[-1]
        for agent in self.settings.agents.values():
            if agent.spiffe_id == spiffe_id:
                return agent.entra_agent_id
        return ""

    async def get_ca_status(self, request_id):
        # type: (str) -> Dict[str, Any]
        policy_task = self.admin_client.get_json("policy", request_id)
        risk_task = self.admin_client.get_json("agent-risk", request_id)
        tag_task = self.admin_client.get_json("agent-tags", request_id)
        ca_effective_task = self.admin_client.get_json("ca-policy-effective", request_id)
        policy_data, risk_data, tag_data, ca_effective = await asyncio.gather(
            policy_task,
            risk_task,
            tag_task,
            ca_effective_task,
        )
        risky_agents = await self.graph_client.fetch_risky_agents()
        sp_oid_to_key = {}
        if risky_agents and self.graph_client.configured:
            for key, agent in self.settings.agents.items():
                if agent.entra_agent_id:
                    sp_oid = await self.graph_client.resolve_service_principal_object_id(agent.entra_agent_id)
                    if sp_oid:
                        sp_oid_to_key[sp_oid] = key
        entra_risk_states = {}
        for sp_oid, info in risky_agents.items():
            agent_key = sp_oid_to_key.get(sp_oid)
            if agent_key:
                entra_risk_states[agent_key] = info

        agent_statuses = []
        admin_governance = policy_data.get("admin_governance", {})
        blocked_levels = ca_effective.get("blocked_risk_levels") or []
        tag_store = tag_data.get("tags", {}) if isinstance(tag_data, dict) else {}
        risk_store = risk_data.get("risks", {}) if isinstance(risk_data, dict) else {}
        for entry in policy_data.get("policies", []):
            agent_key = entry.get("name", "")
            if agent_key == "budget-backend":
                continue
            agent = self.settings.agents.get(agent_key)
            spiffe_id = agent.spiffe_id if agent else (self.settings.control_plane.spiffe_id if agent_key == "admin-control-plane" else "")
            ca = entry.get("ca", {})
            current_risk = "low"
            for stored_id, risk_level in risk_store.items():
                if stored_id == spiffe_id:
                    current_risk = risk_level
                    break
            graph_tag = tag_store.get(spiffe_id)
            yaml_tag = ca.get("agent_tag", "")
            effective_tag = graph_tag if graph_tag is not None else yaml_tag
            entra_risk = entra_risk_states.get(agent_key, {})
            entra_risk_level = entra_risk.get("risk_level", "none")
            risk_in_sync = (current_risk == "low" and entra_risk_level in ("none", "low")) or current_risk == entra_risk_level
            name = agent.name if agent else self.settings.control_plane.name
            tag_in_sync = graph_tag is None or graph_tag.lower() == yaml_tag.lower() if yaml_tag else True
            risk_policy_gap = admin_governance.get("enabled", False) and not blocked_levels
            agent_statuses.append(
                {
                    "name": name,
                    "key": agent_key,
                    "spiffe_id": spiffe_id,
                    "agent_state": ca.get("agent_state", "enabled"),
                    "agent_tag": effective_tag,
                    "graph_tag": graph_tag,
                    "yaml_tag": yaml_tag,
                    "tag_source": "graph" if graph_tag is not None else "yaml",
                    "tag_in_sync": tag_in_sync,
                    "blocked_risk_levels": blocked_levels,
                    "risk_policy_gap": risk_policy_gap,
                    "current_risk": current_risk,
                    "entra_risk_level": entra_risk_level,
                    "entra_risk_state": entra_risk.get("risk_state", "notAtRisk"),
                    "risk_in_sync": risk_in_sync,
                    "tag_matches_target": effective_tag.lower() == admin_governance.get("target_agent_tag", "").lower(),
                }
            )
        return {
            "admin_governance": admin_governance,
            "agents": agent_statuses,
            "risk_store": risk_store,
            "entra_risk_states": entra_risk_states,
            "tag_store": tag_store,
            "policy_version": policy_data.get("version", "unknown"),
        }

    async def update_agent_risk(self, spiffe_id, risk_level, request_id):
        # type: (str, str, str) -> Dict[str, Any]
        agent_oid = self._resolve_agent_oid(spiffe_id)
        if not agent_oid:
            raise PortalError(400, "entra_agent_not_resolved", "Could not resolve Entra agent identity for the selected agent")
        entra_result = await self.graph_client.push_agent_risk(agent_oid, risk_level)
        sidecar_result = await self.admin_client.put_json(
            "agent-risk",
            {"spiffe_id": spiffe_id, "risk_level": risk_level},
            request_id,
        )
        flush_result = {}
        for agent_key, agent in self.settings.agents.items():
            if agent.spiffe_id == spiffe_id and agent.url:
                flush_result = await self.agent_invoker.flush_token(agent.url, self.settings.mgmt_api_key, request_id)
                flush_result["flushed"] = agent_key
                break
        return {**sidecar_result, "entra": entra_result, "token_flush": flush_result}

    async def flush_all_tokens(self, request_id):
        # type: (str) -> Dict[str, Any]
        results = []
        for agent_key, agent in self.settings.agents.items():
            if not agent.url:
                results.append({"agent": agent_key, "status": "skipped", "reason": "no URL"})
                continue
            if ".internal." in agent.url:
                results.append({"agent": agent_key, "status": "skipped", "reason": "internal-only"})
                continue
            try:
                result = await self.agent_invoker.flush_token(agent.url, self.settings.mgmt_api_key, request_id)
                if result.get("status_code") == 200:
                    results.append({"agent": agent_key, "status": "flushed"})
                else:
                    results.append({"agent": agent_key, "status": "error", "code": result.get("status_code")})
            except Exception as exc:
                results.append({"agent": agent_key, "status": "error", "detail": str(exc)})
        return {
            "status": "completed",
            "flushed": sum(1 for item in results if item["status"] == "flushed"),
            "total": len(results),
            "results": results,
        }

    async def sync_attributes(self, request_id):
        # type: (str) -> Dict[str, Any]
        synced = []
        attribute_set = "AgentIdentity"
        attribute_name = "Department"
        for agent_key, agent in self.settings.agents.items():
            if not agent.entra_agent_id or not agent.spiffe_id:
                continue
            tag_value = await self.graph_client.read_custom_security_attribute(agent.entra_agent_id, attribute_set, attribute_name)
            if tag_value is not None:
                await self.admin_client.put_json(
                    "agent-tags",
                    {"spiffe_id": agent.spiffe_id, "tag": tag_value},
                    request_id,
                )
                synced.append({"agent": agent_key, "spiffe_id": agent.spiffe_id, "tag": tag_value, "source": "graph"})
            else:
                synced.append(
                    {
                        "agent": agent_key,
                        "spiffe_id": agent.spiffe_id,
                        "tag": None,
                        "source": "graph",
                        "note": "no custom security attribute set",
                    }
                )
        return {
            "status": "synced",
            "attribute_set": attribute_set,
            "attribute_name": attribute_name,
            "agents": synced,
            "count": len([item for item in synced if item.get("tag")]),
        }
