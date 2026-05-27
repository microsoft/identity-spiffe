"""Client for invoking agent-facing endpoints."""

import logging
import time
from typing import Any, Dict

import httpx

from ..errors import PortalError

logger = logging.getLogger("isp-portal.clients.agents")


class AgentInvokerClient:
    """Calls external agent endpoints through the pooled AsyncClient."""

    def __init__(self, http_client):
        # type: (httpx.AsyncClient) -> None
        self.http_client = http_client

    async def execute_backend(self, caller_url, method, path, request_id, mgmt_api_key=""):
        # type: (str, str, str, str, str) -> Dict[str, Any]
        if not caller_url:
            raise PortalError(400, "no_invoke_url", "Caller has no invoke URL configured. External agents need their invoke_url set via PUT /api/external-agents/{name}.")
        start = time.monotonic()
        headers = {"X-Request-ID": request_id}
        if mgmt_api_key:
            headers["X-Spiffe-Admin-Key"] = mgmt_api_key
        try:
            response = await self.http_client.post(
                "{0}/call-backend-raw".format(caller_url.rstrip("/")),
                params={"method": method, "path": path},
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "agent_unreachable", "Could not reach caller agent", {"detail": str(exc)})
        latency = int((time.monotonic() - start) * 1000)
        try:
            body = response.json()
        except Exception:
            body = {"raw": response.text[:2000]}
        inner_status = body.get("http_status", response.status_code)
        return {
            "status": inner_status,
            "body": body,
            "latency_ms": latency,
            "layer": "live (via SPIFFE egress proxy)",
            "blocked": inner_status >= 400 or inner_status == 0,
            "mode": "live",
        }

    async def execute_a2a(self, caller_url, target, request_id, mgmt_api_key=""):
        # type: (str, str, str, str) -> Dict[str, Any]
        if not caller_url:
            raise PortalError(400, "no_invoke_url", "Caller has no invoke URL configured. External agents need their invoke_url set via PUT /api/external-agents/{name}.")
        start = time.monotonic()
        headers = {"X-Request-ID": request_id}
        if mgmt_api_key:
            headers["X-Spiffe-Admin-Key"] = mgmt_api_key
        try:
            response = await self.http_client.get(
                "{0}/call-agent".format(caller_url.rstrip("/")),
                params={"target": target},
                headers=headers,
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "agent_unreachable", "Could not reach caller agent", {"detail": str(exc)})
        latency = int((time.monotonic() - start) * 1000)
        try:
            body = response.json()
        except Exception:
            body = {"raw": response.text[:2000]}
        inner_status = body.get("http_status", response.status_code)
        inner_resp = body.get("response", {}) if isinstance(body, dict) else {}
        enforcement = {}
        if isinstance(inner_resp, dict):
            enforcement = inner_resp.get("enforcement", {})
            if not enforcement and inner_resp.get("enforcement_layer"):
                enforcement = {
                    "enforcement_layer": inner_resp.get("enforcement_layer", ""),
                    "caller_tag": inner_resp.get("caller_tag", ""),
                    "target_tag": inner_resp.get("target_tag", ""),
                    "agent_risk": inner_resp.get("agent_risk", ""),
                }
        if not enforcement and isinstance(body, dict) and body.get("enforcement_layer"):
            enforcement = {
                "enforcement_layer": body.get("enforcement_layer", ""),
                "caller_tag": body.get("caller_tag", ""),
                "target_tag": body.get("target_tag", ""),
                "agent_risk": body.get("agent_risk", ""),
            }
        return {
            "status": inner_status,
            "body": body,
            "latency_ms": latency,
            "layer": "A2A live (direct HTTPS call)",
            "blocked": inner_status >= 400 or inner_status == 0,
            "mode": "live",
            "a2a": True,
            "enforcement": enforcement,
        }

    async def flush_token(self, agent_url, mgmt_api_key, request_id):
        # type: (str, str, str) -> Dict[str, Any]
        try:
            response = await self.http_client.post(
                "{0}/flush-token".format(agent_url.rstrip("/")),
                headers={
                    "X-Spiffe-Admin-Key": mgmt_api_key,
                    "X-Request-ID": request_id,
                },
            )
        except httpx.RequestError as exc:
            raise PortalError(503, "agent_unreachable", "Could not flush agent token cache", {"detail": str(exc)})
        return {"status_code": response.status_code}
