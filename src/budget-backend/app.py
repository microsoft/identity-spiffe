"""
BudgetBackend - Protected MCP Server (Budget Backend Scenario)
================================================================
The protected resource in the Identity Research for Agent Management Using SPIFFE PoC. Exposes budget operations that other
agents (BudgetReport, EmployeeMenus, BudgetApproval) attempt to call.

Endpoints:
  GET  /budget/read   — Read budget data (BudgetReport: allowed, BudgetApproval: allowed)
  POST /budget/submit — Submit budget entries (BudgetApproval: allowed, BudgetReport: denied by RBAC)

Three-layer auth (all enforced by the SPIFFE sidecar proxy — zero auth code here):
  Layer 1 (transport): SPIFFE mTLS — only trusted agents can connect
  Layer 2 (application): RBAC — path/method restrictions per caller
  Layer 3 (token): Entra OAuth2 — JWT validation + app role checks

The backend echoes token metadata in responses (read-only, no validation).
This proves agents need zero auth code — the sidecar handles all three layers.

Maps to the Budget Backend demo scenario.
"""
import hmac
import os
import json
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse

ALLOW_REMOTE_ACCESS = os.getenv("ALLOW_REMOTE_ACCESS", "").lower() == "true"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("budget-backend")


def _read_token_metadata(request: Request):
    """Read-only token echo — extract and display token metadata from
    Authorization header without any validation. The sidecar already
    validated the JWT (Layer 3); this just echoes what it saw for demo visibility."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return {"present": False}

    token = auth_header[7:]
    try:
        # Decode the payload (middle segment) without verification — read-only echo.
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            return {"present": True, "error": "malformed JWT (not 3 parts)"}

        # Add padding for base64url decoding.
        payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        # Return safe subset of claims for demo visibility.
        safe_claims = {k: v for k, v in payload.items()
                       if k in ("iss", "aud", "oid", "sub", "azp", "appid",
                                "iat", "exp", "nbf", "tid", "ver", "roles")}
        return {
            "present": True,
            "audience": payload.get("aud", ""),
            "roles": payload.get("roles", []),
            "oid": payload.get("oid", ""),
            "app_id": payload.get("azp") or payload.get("appid", ""),
            "claims": safe_claims,
        }
    except Exception as e:
        return {"present": True, "error": str(e)}


app = FastAPI(
    title="BudgetBackend - Protected MCP Server",
    description="Identity Research for Agent Management Using SPIFFE: Budget Backend API (SPIFFE-protected)",
    version="0.3.0",
)


@app.middleware("http")
async def enforce_localhost_only(request: Request, call_next):
    """Ensure requests come from the SPIFFE sidecar proxy (localhost only).

    The sidecar strips and re-injects X-SPIFFE-Caller-ID, but the FastAPI app
    listens on port 8000. If any path bypasses the sidecar, caller identity is
    spoofable. This middleware rejects non-loopback traffic on all routes except
    health and OpenAPI spec.
    """
    normalized_path = request.url.path.rstrip("/") or "/"
    if normalized_path not in ("/health", "/openapi.json"):
        if ALLOW_REMOTE_ACCESS:
            return await call_next(request)
        client_host = request.client.host if request.client else None
        if client_host not in ("127.0.0.1", "::1"):
            return JSONResponse(
                {"error": "direct_access_denied", "message": "Must access through SPIFFE proxy"},
                status_code=403,
            )
    return await call_next(request)


@app.get("/health")
async def health():
    return {"status": "healthy", "agent": "budget-backend", "role": "resource-mcp-server"}

@app.get("/agent-info")
async def agent_info():
    return {
        "name": os.getenv("AGENT_NAME", "budget-backend"),
        "role": os.getenv("AGENT_ROLE", "resource-mcp-server"),
        "project_endpoint": os.getenv("PROJECT_ENDPOINT", "not-set"),
    }

@app.api_route("/budget/read", methods=["GET", "POST"])
async def budget_read(request: Request):
    """Read budget data. RBAC allows BudgetReport (read-only) and BudgetApproval."""
    caller = request.headers.get("X-SPIFFE-Caller-ID", request.headers.get("X-Caller-Agent", "unknown"))
    entra_agent_id = request.headers.get("X-SPIFFE-Entra-Agent-ID", "")
    token_info = _read_token_metadata(request)
    logger.info(f"Budget read from '{caller}': {request.method} /budget/read (token: {token_info.get('present', False)})")
    response = {
        "status": "success",
        "caller": caller,
        "identity_chain": {
            "spiffe_id": caller,
            "entra_agent_id": entra_agent_id or None,
            "entra_token": token_info,
        },
        "data": {
            "fiscal_year": "FY2026",
            "department": "Engineering",
            "total_budget": 2500000,
            "spent": 1875000,
            "remaining": 625000,
            "phase": "Q3",
        },
    }
    return response

@app.post("/budget/submit")
async def budget_submit(request: Request):
    """Submit a budget entry. RBAC allows BudgetApproval only."""
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        logger.warning(f"Falling back to empty request body for /budget/submit due to JSON parse error: {exc}")
        body = {}
    caller = request.headers.get("X-SPIFFE-Caller-ID", request.headers.get("X-Caller-Agent", "unknown"))
    entra_agent_id = request.headers.get("X-SPIFFE-Entra-Agent-ID", "")
    token_info = _read_token_metadata(request)
    amount = body.get("amount", 0)
    description = body.get("description", "No description")
    logger.info(f"Budget submission from '{caller}': ${amount} - {description} (token: {token_info.get('present', False)})")

    return JSONResponse({
        "status": "success",
        "caller": caller,
        "identity_chain": {
            "spiffe_id": caller,
            "entra_agent_id": entra_agent_id or None,
            "entra_token": token_info,
        },
        "result": {
            "entry_id": "BUD-2026-0042",
            "amount": amount,
            "description": description,
            "approved": True,
            "message": f"Budget entry submitted by {caller}",
        },
    })

@app.delete("/budget/admin")
async def budget_admin(request: Request):
    """Administrative deletion. RBAC denies this for all callers by default."""
    caller = request.headers.get("X-SPIFFE-Caller-ID", request.headers.get("X-Caller-Agent", "unknown"))
    logger.info(f"Budget admin DELETE from '{caller}'")
    return JSONResponse({
        "status": "success",
        "caller": caller,
        "result": {
            "action": "admin_delete",
            "message": f"Administrative deletion executed by {caller}",
            "warning": "This operation is irreversible",
        },
    })


@app.post("/execute")
async def execute_function(request: Request):
    """Legacy /execute endpoint — kept for backward compatibility."""
    body = await request.json()
    action = body.get("action", "echo")
    params = body.get("params", {})
    caller = request.headers.get("X-Caller-Agent", "unknown")
    logger.info(f"Received call from '{caller}' - action: {action}")

    if action == "echo":
        return JSONResponse({
            "status": "success",
            "caller": caller,
            "result": f"Echo: {params.get('message', 'hello')}",
        })
    elif action == "compute":
        a = params.get("a", 0)
        b = params.get("b", 0)
        return JSONResponse({
            "status": "success",
            "caller": caller,
            "result": {"sum": a + b, "product": a * b},
        })
    elif action == "get_status":
        return JSONResponse({
            "status": "success",
            "caller": caller,
            "result": {"system": "operational", "phase": "poc"},
        })
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {action}")

# =============================================================================
# Management API Proxy
# =============================================================================
# The SPIFFE sidecar's management API runs on localhost:9443 inside this
# container. These routes proxy external requests to it, enabling the
# Identity Research for Agent Management Using SPIFFE Control Panel to read/update policy, health, and audit in real-time.
#
# Auth: simple shared-secret header check. Not production auth — this is
# a demo tool for exec walkthroughs. Set MGMT_API_KEY env var to override.
# =============================================================================

import httpx

MGMT_API_URL = os.getenv("MGMT_API_URL", "http://127.0.0.1:9443")
MGMT_API_KEY = os.getenv("MGMT_API_KEY", "")


def _check_mgmt_auth(request: Request):
    """Validate the X-Spiffe-Admin-Key header for management routes."""
    if not MGMT_API_KEY:
        raise HTTPException(status_code=500, detail="mgmt_api_key_not_configured")
    key = request.headers.get("X-Spiffe-Admin-Key", "")
    if not hmac.compare_digest(key.encode(), MGMT_API_KEY.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing X-Spiffe-Admin-Key header")


@app.get("/mgmt/health")
async def mgmt_health(request: Request):
    """Proxy GET /health from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/health")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy /health failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/policy")
async def mgmt_get_policy(request: Request):
    """Proxy GET /policy from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/policy")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.put("/mgmt/policy")
async def mgmt_put_policy(request: Request):
    """Proxy PUT /policy to the sidecar management API (live policy swap)."""
    _check_mgmt_auth(request)
    max_body_bytes = 65536
    content_length = request.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > max_body_bytes:
                return JSONResponse(
                    {"error": "payload_too_large", "max_bytes": max_body_bytes},
                    status_code=413,
                )
        except ValueError:
            pass

    chunks = []
    total_bytes = 0
    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > max_body_bytes:
            return JSONResponse(
                {"error": "payload_too_large", "max_bytes": max_body_bytes},
                status_code=413,
            )
        chunks.append(chunk)

    body = b"".join(chunks)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.put(
                f"{MGMT_API_URL}/policy",
                content=body,
                headers={"Content-Type": "application/x-yaml"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/audit")
async def mgmt_audit(request: Request):
    """Proxy GET /audit from the sidecar management API."""
    _check_mgmt_auth(request)
    # Forward query params (limit, spiffe_id, decision)
    params = dict(request.query_params)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/audit", params=params)
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/audit/stream")
async def mgmt_audit_stream(request: Request):
    """Passthrough Server-Sent Events from the sidecar management API.

    The Go spiffe-proxy sidecar exposes /audit/stream on 127.0.0.1:9443
    via its AccessLogger pub/sub fan-out. This handler forwards the byte
    stream verbatim so the admin-control-plane and portal can subscribe
    over the mTLS tunnel without needing direct access to the sidecar.
    """
    _check_mgmt_auth(request)

    headers = {"Accept": "text/event-stream"}
    admin_key = request.headers.get("x-aim-admin-key")
    if admin_key:
        headers["X-Spiffe-Admin-Key"] = admin_key

    async def _iter():
        # Long-lived stream: no read timeout, only a connect timeout. A
        # dedicated AsyncClient ensures the shared pool isn't held open.
        timeout = httpx.Timeout(None, connect=10.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                async with client.stream(
                    "GET", f"{MGMT_API_URL}/audit/stream", headers=headers
                ) as upstream:
                    if upstream.status_code != 200:
                        logger.warning(
                            "Audit stream upstream status %s", upstream.status_code
                        )
                        yield b": upstream_error\n\n"
                        return
                    async for chunk in upstream.aiter_raw():
                        if chunk:
                            yield chunk
        except httpx.RequestError:
            logger.exception("Audit stream upstream error")
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


@app.get("/mgmt/metrics")
async def mgmt_metrics(request: Request):
    """Proxy GET /metrics from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/metrics")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/mtls-policy")
async def mgmt_get_mtls_policy(request: Request):
    """Proxy GET /mtls-policy from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/mtls-policy")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.put("/mgmt/mtls-policy")
async def mgmt_put_mtls_policy(request: Request):
    """Proxy PUT /mtls-policy to the sidecar management API (live mTLS allow list update)."""
    _check_mgmt_auth(request)
    body = await request.body()
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.put(
                f"{MGMT_API_URL}/mtls-policy",
                content=body,
                headers={"Content-Type": "application/json"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/oauth-status")
async def mgmt_oauth_status(request: Request):
    """Proxy GET /oauth-status from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/oauth-status")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/agent-risk")
async def mgmt_agent_risk_get(request: Request):
    """Proxy GET /agent-risk from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/agent-risk")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.put("/mgmt/agent-risk")
async def mgmt_agent_risk_put(request: Request):
    """Proxy PUT /agent-risk to the sidecar management API."""
    _check_mgmt_auth(request)
    body = await request.body()
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.put(
                f"{MGMT_API_URL}/agent-risk",
                content=body,
                headers={"Content-Type": "application/json"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/agent-tags")
async def mgmt_agent_tags(request: Request):
    """Proxy GET /agent-tags from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/agent-tags")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.put("/mgmt/agent-tags")
async def mgmt_agent_tags_put(request: Request):
    """Proxy PUT /agent-tags to the sidecar management API."""
    _check_mgmt_auth(request)
    body = await request.body()
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.put(
                f"{MGMT_API_URL}/agent-tags",
                content=body,
                headers={"Content-Type": "application/json"},
            )
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/mgmt/ca-policy-effective")
async def mgmt_ca_policy_effective(request: Request):
    """Proxy GET /ca-policy-effective from the sidecar management API."""
    _check_mgmt_auth(request)
    async with httpx.AsyncClient(timeout=5) as client:
        try:
            resp = await client.get(f"{MGMT_API_URL}/ca-policy-effective")
            return JSONResponse(resp.json(), status_code=resp.status_code)
        except httpx.RequestError:
            logger.exception("Management proxy request failed")
            return JSONResponse(
                {"error": "mgmt_unreachable"},
                status_code=502,
            )


@app.get("/openapi.json")
async def openapi_spec():
    return app.openapi()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
