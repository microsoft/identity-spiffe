"""
Admin Control Plane
===================
Dedicated management service for BudgetBackend's SPIFFE sidecar management API.

This service is intentionally separate from the business agents so management
and recovery operations do not depend on a governed caller like BudgetApproval.
"""
import os
import logging

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(os.getenv("AGENT_NAME", "admin-control-plane"))

app = FastAPI(
    title="Admin Control Plane",
    description="Dedicated management service for BudgetBackend control-plane operations",
    version="0.1.0",
)

BACKEND_ENDPOINT = os.getenv("BACKEND_ENDPOINT", "http://localhost:8080")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", os.getenv("MGMT_API_KEY", ""))
AGENT_NAME = os.getenv("AGENT_NAME", "admin-control-plane")


def require_admin(request: Request):
    if not ADMIN_API_KEY:
        raise HTTPException(status_code=500, detail="admin_api_key_not_configured")
    if request.headers.get("X-AIM-Admin-Key") != ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "agent": AGENT_NAME,
        "role": "admin-control-plane",
        "backend_endpoint": BACKEND_ENDPOINT,
    }


# ── Agent discovery (must be registered BEFORE the catch-all /admin/{path} proxy) ──
# Azure Container Apps injects CONTAINER_APP_ENV_DNS_SUFFIX at runtime.
# Any app's FQDN = <app-name>.<dns-suffix>. This lets us derive URLs for
# any agent in the environment without static env vars or hardcoded lists.
_ENV_DNS_SUFFIX = os.getenv("CONTAINER_APP_ENV_DNS_SUFFIX", "")

# Role hints for well-known agents. Agents not in this map (e.g. dynamic
# demo agents) get role "dynamic-caller".
_KNOWN_ROLES = {
    "budget-report": "caller-allowed",
    "budget-backend": "resource-mcp-server",
    "employee-menus": "caller-blocked",
    "budget-approval": "caller-allowed",
    "admin-control-plane": "admin-control-plane",
}


def _agent_url(name):
    # type: (str) -> str
    """Derive an agent's external URL from the environment DNS suffix."""
    if _ENV_DNS_SUFFIX:
        return "https://{}.{}".format(name, _ENV_DNS_SUFFIX)
    return ""


@app.get("/admin/agents")
async def list_agents(request: Request):
    """Discover agents dynamically from RBAC policy + environment DNS."""
    require_admin(request)

    # The RBAC policy is the source of truth for which agents exist and
    # their SPIFFE IDs. It updates when agents are added/removed.
    spiffe_by_name = {}  # type: dict
    federated_by_name = {}  # type: dict  — name -> {trust_domain, spiffe_id}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(5.0, connect=2.0)) as client:
            resp = await client.get(
                "{}/mgmt/policy".format(BACKEND_ENDPOINT),
                headers={"X-Caller-Agent": AGENT_NAME, "X-AIM-Admin-Key": ADMIN_API_KEY},
            )
            if resp.status_code == 200:
                import yaml as _yaml
                policy_yaml = resp.json().get("yaml", "")
                if policy_yaml:
                    policy = _yaml.safe_load(policy_yaml)
                else:
                    policy = resp.json()
                for p in policy.get("policies", []):
                    name = p.get("name", "")
                    sid = p.get("spiffe_id", "") or p.get("spiffe_id_prefix", "")
                    if name and sid:
                        spiffe_by_name[name] = sid
                for fp in policy.get("federated_policies", []):
                    name = fp.get("name", "")
                    sid = fp.get("spiffe_id", "")
                    trust_domain = fp.get("trust_domain", "")
                    if name and (sid or fp.get("jwt_only")):
                        federated_by_name[name] = {
                            "spiffe_id": sid,
                            "trust_domain": trust_domain,
                        }
    except Exception as e:
        logger.warning("Failed to fetch RBAC policy for agent discovery: %s", e)

    # Always include well-known agents even if the RBAC policy fetch failed,
    # so the portal shows placeholders rather than an empty list.
    all_agent_names = set(spiffe_by_name.keys()) | set(_KNOWN_ROLES.keys())

    agents = {}
    for name in sorted(all_agent_names):
        sid = spiffe_by_name.get(name, "")
        agents[name] = {
            "name": name,
            "spiffe_id": sid,
            "entra_agent_id": sid.split("/aid/")[-1] if "/aid/" in sid else "",
            "role": _KNOWN_ROLES.get(name, "dynamic-caller"),
            "url": _agent_url(name),
            "transport": "spiffe",
            "hosting_platform": "",
        }

    # Append federated callers (url="" — portal overlays from external-agent store)
    for name, info in sorted(federated_by_name.items()):
        sid = info["spiffe_id"]
        trust_domain = info["trust_domain"]
        # Infer hosting platform from trust domain prefix
        if trust_domain.startswith("gcp."):
            hosting_platform = "gcp"
        else:
            hosting_platform = "external"
        agents[name] = {
            "name": name,
            "spiffe_id": sid,
            "entra_agent_id": sid.split("/aid/")[-1] if "/aid/" in sid else "",
            "role": "federated-caller",
            "url": "",  # portal overlays invoke_url from external-agent store
            "transport": "spiffe",
            "hosting_platform": hosting_platform,
        }

    return {"agents": agents, "count": len(agents)}


@app.get("/admin/audit/stream")
async def admin_audit_stream(request: Request):
    """Passthrough Server-Sent Events stream from BudgetBackend's mgmt API.

    Registered before the catch-all `/admin/{mgmt_path:path}` so FastAPI
    routes SSE through this handler instead of the JSON proxy.
    """
    require_admin(request)

    backend_url = "{0}/mgmt/audit/stream".format(BACKEND_ENDPOINT)
    headers = {
        "X-Caller-Agent": AGENT_NAME,
        "X-AIM-Admin-Key": ADMIN_API_KEY,
        "Accept": "text/event-stream",
    }

    async def passthrough():
        # No read timeout on the upstream stream; only connect timeout.
        timeout = httpx.Timeout(None, connect=10.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream("GET", backend_url, headers=headers) as upstream:
                    if upstream.status_code != 200:
                        logger.warning(
                            "[%s] audit stream upstream status %s", AGENT_NAME, upstream.status_code
                        )
                        yield b": upstream_error\n\n"
                        return
                    async for chunk in upstream.aiter_raw():
                        if not chunk:
                            continue
                        yield chunk
        except httpx.RequestError as exc:
            logger.error("[%s] audit stream upstream error: %s", AGENT_NAME, exc)
            yield b": upstream_unreachable\n\n"

    return StreamingResponse(
        passthrough(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.api_route("/admin/{mgmt_path:path}", methods=["GET", "PUT"])
async def admin_proxy(mgmt_path: str, request: Request):
    """Proxy approved management operations to BudgetBackend's /mgmt/* API."""
    require_admin(request)

    url = f"{BACKEND_ENDPOINT}/mgmt/{mgmt_path}"
    headers = {
        "X-Caller-Agent": AGENT_NAME,
        "X-AIM-Admin-Key": ADMIN_API_KEY,
        "Content-Type": request.headers.get("content-type", "application/json"),
    }
    body = await request.body()

    logger.info("[%s] Admin proxy: %s /mgmt/%s", AGENT_NAME, request.method, mgmt_path)

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body or None,
            )

        logger.info("[%s] Admin proxy response: %s", AGENT_NAME, resp.status_code)
        try:
            resp_body = resp.json()
        except Exception:
            resp_body = {"raw": resp.text[:2000]}
        return JSONResponse(resp_body, status_code=resp.status_code)
    except httpx.RequestError as exc:
        logger.error("[%s] Admin proxy failed: %s", AGENT_NAME, exc)
        return JSONResponse(
            {"error": "backend_mgmt_unreachable", "detail": str(exc)},
            status_code=502,
        )
