"""Graph API client helpers."""

import logging
import re
from typing import Dict, List, Optional

import httpx

from shared.graph_token import get_graph_token

from ..errors import PortalError

logger = logging.getLogger("isp-portal.clients.graph")

_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)

GRAPH_BETA = "https://graph.microsoft.com/beta"


class GraphClient:
    """Thin Graph client with shared token caching."""

    def __init__(self, http_client, tenant_id, client_id="", client_secret=""):
        # type: (httpx.AsyncClient, str, str, str) -> None
        self.http_client = http_client
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._sp_oid_cache = {}  # type: Dict[str, str]

    @staticmethod
    def _odata_escape(value):
        # type: (str) -> str
        return str(value).replace("'", "''")

    @property
    def configured(self):
        # type: () -> bool
        return bool(self.tenant_id and self.client_id and self.client_secret)

    async def get_token(self):
        # type: () -> Optional[str]
        if not self.configured:
            return None
        return await get_graph_token(
            client_id=self.client_id,
            client_secret=self.client_secret,
            tenant_id=self.tenant_id,
        )

    async def require_token(self):
        # type: () -> str
        token = await self.get_token()
        if not token:
            raise PortalError(503, "graph_not_configured", "Graph API credentials not configured")
        return token

    async def resolve_service_principal_object_id(self, app_id):
        # type: (str) -> Optional[str]
        if not app_id or not _GUID_RE.match(app_id):
            return None
        if app_id in self._sp_oid_cache:
            return self._sp_oid_cache[app_id]
        token = await self.require_token()
        headers = {"Authorization": "Bearer {0}".format(token), "ConsistencyLevel": "eventual"}

        # Try direct lookup first — Agent Identity SPs support /servicePrincipals/{id}
        # but NOT the $filter=appId OData query (returns Request_UnsupportedQuery).
        try:
            direct = await self.http_client.get(
                "https://graph.microsoft.com/v1.0/servicePrincipals/{0}".format(app_id),
                params={"$select": "id,displayName"},
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "graph_unreachable", "Could not reach Microsoft Graph", {"detail": str(exc)})
        if direct.status_code == 200:
            sp_oid = direct.json().get("id", app_id)
            self._sp_oid_cache[app_id] = sp_oid
            return sp_oid

        # Fall back to $filter query for standard (non-Agent Identity) SPs
        try:
            response = await self.http_client.get(
                "https://graph.microsoft.com/v1.0/servicePrincipals",
                params={"$filter": "appId eq '{0}'".format(self._odata_escape(app_id)), "$select": "id,displayName"},
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "graph_unreachable", "Could not reach Microsoft Graph", {"detail": str(exc)})
        if response.status_code == 200:
            values = response.json().get("value", [])
            if values:
                sp_oid = values[0]["id"]
                self._sp_oid_cache[app_id] = sp_oid
                return sp_oid

        # Neither path found the SP — return None (not an error)
        return None

    async def push_agent_risk(self, agent_oid, risk_level):
        # type: (str, str) -> Dict[str, str]
        if not agent_oid:
            raise PortalError(400, "entra_agent_not_resolved", "Agent Entra identity is not resolved")
        token = await self.require_token()
        sp_oid = await self.resolve_service_principal_object_id(agent_oid)
        if not sp_oid:
            sp_oid = agent_oid
        action = "confirmCompromised" if risk_level == "high" else "confirmSafe"
        try:
            response = await self.http_client.post(
                "{0}/identityProtection/riskyAgents/{1}".format(GRAPH_BETA, action),
                json={"agentIds": [sp_oid]},
                headers={
                    "Authorization": "Bearer {0}".format(token),
                    "Content-Type": "application/json",
                },
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "graph_unreachable", "Could not reach Microsoft Graph", {"detail": str(exc)})
        if response.status_code == 204:
            return {"entra_status": "success", "action": action, "sp_object_id": sp_oid}
        raise PortalError(
            502,
            "graph_risk_update_failed",
            "Microsoft Graph rejected the risk update",
            {"action": action, "status_code": response.status_code, "detail": response.text[:500]},
        )

    async def fetch_risky_agents(self):
        # type: () -> Dict[str, dict]
        token = await self.require_token()
        try:
            response = await self.http_client.get(
                "{0}/identityProtection/riskyAgents".format(GRAPH_BETA),
                headers={"Authorization": "Bearer {0}".format(token), "ConsistencyLevel": "eventual"},
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "graph_unreachable", "Could not reach Microsoft Graph", {"detail": str(exc)})
        if response.status_code != 200:
            raise PortalError(
                502,
                "graph_risky_agents_failed",
                "Failed to fetch risky agents from Microsoft Graph",
                {"status_code": response.status_code, "body": response.text[:500]},
            )
        result = {}
        for entry in response.json().get("value", []):
            result[entry.get("id", "")] = {
                "risk_state": entry.get("riskState", "unknown"),
                "risk_level": entry.get("riskLevel", "unknown"),
            }
        return result

    async def fetch_ca_policies(self, display_name_filter="Identity Research for Agent Management Using SPIFFE:"):
        # type: (str) -> List[Dict]
        """Fetch Conditional Access policies from Graph beta API."""
        token = await self.require_token()
        try:
            response = await self.http_client.get(
                "{0}/identity/conditionalAccess/policies".format(GRAPH_BETA),
                headers={"Authorization": "Bearer {0}".format(token)},
                params={"$top": "999"},
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "graph_unreachable", "Could not reach Microsoft Graph", {"detail": str(exc)})
        if response.status_code != 200:
            raise PortalError(
                502,
                "graph_ca_policies_failed",
                "Failed to fetch CA policies from Microsoft Graph",
                {"status_code": response.status_code, "body": response.text[:500]},
            )
        policies = []
        for entry in response.json().get("value", []):
            name = entry.get("displayName", "")
            if display_name_filter and not name.startswith(display_name_filter):
                continue
            policies.append({
                "id": entry.get("id", ""),
                "displayName": name,
                "state": entry.get("state", "unknown"),
                "conditions": entry.get("conditions", {}),
                "grantControls": entry.get("grantControls", {}),
            })
        return policies

    async def read_custom_security_attribute(self, entra_id, attribute_set, attribute_name):
        # type: (str, str, str) -> Optional[str]
        if not _GUID_RE.match(entra_id or ""):
            return None
        token = await self.require_token()
        headers = {
            "Authorization": "Bearer {0}".format(token),
            "ConsistencyLevel": "eventual",
        }
        urls = [
            "https://graph.microsoft.com/v1.0/servicePrincipals/{0}?$select=id,displayName,customSecurityAttributes".format(entra_id),
            "https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{0}'&$select=id,displayName,customSecurityAttributes&$count=true".format(
                self._odata_escape(entra_id)
            ),
        ]
        failures = []
        for url in urls:
            try:
                response = await self.http_client.get(url, headers=headers)
            except httpx.RequestError as exc:
                raise PortalError(503, "graph_unreachable", "Could not reach Microsoft Graph", {"detail": str(exc)})
            if response.status_code in (400, 404):
                logger.debug("SP lookup returned %d for %s (expected for placeholders)", response.status_code, entra_id[:40])
                continue
            if response.status_code != 200:
                failures.append({"url": url, "status_code": response.status_code, "body": response.text[:200]})
                continue
            data = response.json()
            sp_data = data if "id" in data else (data.get("value", [{}])[0] if data.get("value") else {})
            attrs = sp_data.get("customSecurityAttributes") or {}
            scoped = attrs.get(attribute_set) or {}
            value = scoped.get(attribute_name)
            if value is not None:
                return value
        if failures:
            raise PortalError(
                502,
                "graph_attribute_lookup_failed",
                "Failed to read custom security attribute from Microsoft Graph",
                {"entra_id": entra_id, "failures": failures},
            )
        return None
