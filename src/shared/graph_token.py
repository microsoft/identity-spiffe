"""
Shared Graph API Token Cache for Identity Research for Agent Management Using SPIFFE Portals
===============================================
Provides a cached client-credentials token for Microsoft Graph API calls.
Used by portal/server.py and securityportal-mock/server.py to avoid duplicating
the token acquisition and caching logic.

Usage:
    from graph_token import get_graph_token

    token = await get_graph_token()  # Returns cached token or acquires new one
"""
import logging
import os
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# In-memory cache: token string + expiry timestamp
_cache = {"token": None, "expires_at": 0}  # type: dict


async def get_graph_token(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[str]:
    """Get a Graph API token via client credentials flow.

    Caches the token and reuses it until 60 seconds before expiry.
    Returns None if credentials are not configured.

    Args:
        client_id: Override for GRAPH_CLIENT_ID / ENTRA_AGENTID_CLIENT_ID env var.
        client_secret: Override for GRAPH_CLIENT_SECRET / ENTRA_AGENTID_CLIENT_SECRET env var.
        tenant_id: Override for AZURE_TENANT_ID env var.
    """
    cid = client_id or os.getenv("ENTRA_AGENTID_CLIENT_ID", "") or os.getenv("GRAPH_CLIENT_ID", "")
    secret = client_secret or os.getenv("ENTRA_AGENTID_CLIENT_SECRET", "") or os.getenv("GRAPH_CLIENT_SECRET", "")
    tid = tenant_id or os.getenv("AZURE_TENANT_ID", "")

    if not cid or not secret or not tid:
        return None

    now = time.time()
    if _cache["token"] and _cache["expires_at"] > now + 60:
        return _cache["token"]

    token_url = f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(token_url, data={
            "client_id": cid,
            "client_secret": secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        })
        if resp.status_code == 200:
            data = resp.json()
            _cache["token"] = data["access_token"]
            _cache["expires_at"] = now + data.get("expires_in", 3600)
            return data["access_token"]
        logger.error("Graph token acquisition failed: %d", resp.status_code)
        return None


def clear_cache():
    """Clear the token cache (useful for testing)."""
    _cache["token"] = None
    _cache["expires_at"] = 0
