"""Client for admin-control-plane operations."""

import asyncio
import json
import logging
from typing import Any, Dict, Optional

import httpx

from ..errors import PortalError

logger = logging.getLogger("isp-portal.clients.admin")


class AdminControlPlaneClient:
    """Thin client over the admin control-plane REST API."""

    def __init__(self, http_client, base_url, admin_key):
        # type: (httpx.AsyncClient, str, str) -> None
        self.http_client = http_client
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key

    def _headers(self, request_id, extra=None):
        # type: (str, Optional[Dict[str, str]]) -> Dict[str, str]
        headers = {"X-Spiffe-Admin-Key": self.admin_key}
        if request_id:
            headers["X-Request-ID"] = request_id
        if extra:
            headers.update(extra)
        return headers

    async def _request(self, method, path, request_id, idempotent=True, **kwargs):
        # type: (str, str, str, bool, Any) -> httpx.Response
        if not self.base_url:
            raise PortalError(503, "admin_control_plane_not_configured", "Admin control-plane URL not configured")
        url = "{0}/admin/{1}".format(self.base_url, path.lstrip("/"))
        attempts = 2 if idempotent else 1
        last_error = None
        headers = kwargs.pop("headers", None)
        merged_headers = self._headers(request_id, headers)
        for attempt in range(1, attempts + 1):
            try:
                response = await self.http_client.request(method, url, headers=merged_headers, **kwargs)
                if response.status_code >= 500 and attempt < attempts and idempotent:
                    await asyncio.sleep(0.15)
                    continue
                return response
            except httpx.RequestError as exc:
                last_error = exc
                if attempt < attempts and idempotent:
                    await asyncio.sleep(0.15)
                    continue
                break
        raise PortalError(
            503,
            "admin_control_plane_unreachable",
            "Could not reach admin control plane",
            {"detail": str(last_error) if last_error else "unknown"},
        )

    @staticmethod
    def _json_or_text(response):
        # type: (httpx.Response) -> Any
        try:
            return response.json()
        except Exception:
            return {"raw": response.text[:2000]}

    async def get_json(self, path, request_id):
        # type: (str, str) -> Any
        response = await self._request("GET", path, request_id, idempotent=True)
        if response.status_code != 200:
            raise PortalError(
                502,
                "admin_control_plane_error",
                "Admin control plane returned HTTP {0}".format(response.status_code),
                {"path": path, "body": response.text[:500]},
            )
        return self._json_or_text(response)

    async def put_yaml(self, path, yaml_text, request_id):
        # type: (str, str, str) -> Any
        response = await self._request(
            "PUT",
            path,
            request_id,
            idempotent=False,
            content=yaml_text.encode("utf-8"),
            headers={"Content-Type": "application/x-yaml"},
        )
        if response.status_code >= 400:
            raise PortalError(
                502,
                "admin_control_plane_error",
                "Admin control plane rejected YAML update",
                {"path": path, "status_code": response.status_code, "body": response.text[:500]},
            )
        return self._json_or_text(response)

    async def put_json(self, path, payload, request_id):
        # type: (str, Dict[str, Any], str) -> Any
        response = await self._request(
            "PUT",
            path,
            request_id,
            idempotent=False,
            json=payload,
        )
        if response.status_code >= 400:
            raise PortalError(
                502,
                "admin_control_plane_error",
                "Admin control plane rejected JSON update",
                {"path": path, "status_code": response.status_code, "body": response.text[:500]},
            )
        return self._json_or_text(response)

    async def open_stream(self, path, request_id):
        # type: (str, str) -> Any
        """Open a Server-Sent Events stream and return a FastAPI StreamingResponse.

        Unlike the other helpers this does NOT use self.http_client — SSE needs
        its own long-lived httpx client so the shared pool isn't tied up, and
        we want to control the timeout independently (no read timeout).
        """
        from fastapi.responses import StreamingResponse  # local import keeps this module FastAPI-agnostic for unit tests
        import httpx as _httpx

        if not self.base_url:
            raise PortalError(
                503,
                "admin_control_plane_not_configured",
                "Admin control-plane URL not configured",
            )

        url = "{0}/admin/{1}".format(self.base_url, path.lstrip("/"))
        headers = self._headers(request_id, {"Accept": "text/event-stream"})

        async def _iter():
            # No read timeout: stream is long-lived. Separate client so we can
            # close it when the generator is cancelled (client disconnect).
            timeout = _httpx.Timeout(None, connect=10.0)
            try:
                async with _httpx.AsyncClient(timeout=timeout) as client:
                    async with client.stream("GET", url, headers=headers) as upstream:
                        if upstream.status_code == 401:
                            yield b": unauthorized\n\n"
                            return
                        if upstream.status_code != 200:
                            yield b": upstream_error\n\n"
                            return
                        async for chunk in upstream.aiter_raw():
                            if chunk:
                                yield chunk
            except _httpx.RequestError:
                yield b": upstream_unreachable\n\n"

        return StreamingResponse(
            _iter(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )
