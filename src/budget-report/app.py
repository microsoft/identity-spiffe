"""
BudgetReport - Read-only Caller Agent
=======================================
Can read budget data (/budget/read) but cannot submit (/budget/submit → 403).
Demonstrates RBAC path restriction (Smart microsegmentation).
"""
import os
import re
import logging
import secrets
import threading
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import time as _time
from entra_token_exchange import get_entra_token_async, flush_cached_token, get_last_token_error, get_token_provenance

try:
    import jwt as pyjwt
    from jwt import PyJWKClient, ExpiredSignatureError, InvalidTokenError
    _JWT_AVAILABLE = True
except ImportError:
    _JWT_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(os.getenv("AGENT_NAME", "budget-report"))

app = FastAPI(
    title=f"Agent {os.getenv('AGENT_NAME', 'budget-report')}",
    description="Identity Research for Agent Management Using SPIFFE: BudgetReport — read-only caller",
    version="0.2.0",
)

BACKEND_ENDPOINT = os.getenv("BACKEND_ENDPOINT", os.getenv("A2_RESOURCE_ENDPOINT", "http://budget-backend:8000"))

# Path validation: only allow /budget/* paths. Blocks SSRF to /mgmt/* and path traversal.
ALLOWED_PATH_PATTERN = re.compile(r"^/budget/[a-zA-Z0-9_\-\.]+$")
ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE"}
ADMIN_KEY = os.getenv("MGMT_API_KEY", "")

# OAuth2 token acquisition — uses Managed Identity + Workload Identity Federation
# to acquire an Entra Agent ID token. The MI is federated to the Agent Blueprint.
ENTRA_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
ENTRA_AUDIENCE = os.getenv("ENTRA_OAUTH2_AUDIENCE", "")
_jwks_client = None
_jwks_lock = threading.Lock()


def _get_jwks_client():
    global _jwks_client
    if _jwks_client is not None:
        return _jwks_client
    with _jwks_lock:
        if _jwks_client is not None:
            return _jwks_client
        if not ENTRA_TENANT_ID:
            return None
        jwks_url = (
            f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}"
            f"/discovery/v2.0/keys"
        )
        _jwks_client = PyJWKClient(jwks_url, cache_keys=True, lifespan=3600)
        return _jwks_client


def validate_entra_jwt(token_str: str):
    if not _JWT_AVAILABLE:
        logger.error("PyJWT not installed — cannot validate JWTs")
        return None
    if not ENTRA_TENANT_ID or not ENTRA_AUDIENCE:
        logger.warning("JWT validation not configured (missing AZURE_TENANT_ID or ENTRA_OAUTH2_AUDIENCE)")
        return None

    jwks = _get_jwks_client()
    if jwks is None:
        return None

    try:
        signing_key = jwks.get_signing_key_from_jwt(token_str)
    except Exception as e:
        logger.warning(f"JWKS key lookup failed: {e}")
        return None

    valid_issuers = [
        f"https://sts.windows.net/{ENTRA_TENANT_ID}/",
        f"https://login.microsoftonline.com/{ENTRA_TENANT_ID}/v2.0",
    ]

    valid_audiences = [ENTRA_AUDIENCE]
    if not ENTRA_AUDIENCE.startswith("api://"):
        valid_audiences.append(f"api://{ENTRA_AUDIENCE}")
    else:
        valid_audiences.append(ENTRA_AUDIENCE.removeprefix("api://"))

    try:
        claims = pyjwt.decode(
            token_str,
            signing_key.key,
            algorithms=["RS256"],
            issuer=valid_issuers,
            audience=valid_audiences,
            options={"require": ["exp", "iss", "aud"]},
        )
        return {
            "oid": claims.get("oid", ""),
            "appid": claims.get("appid", claims.get("azp", "")),
            "roles": claims.get("roles", []),
            "tid": claims.get("tid", ""),
            "sub": claims.get("sub", ""),
            "iss": claims.get("iss", ""),
            "aud": claims.get("aud", ""),
        }
    except ExpiredSignatureError:
        logger.warning("JWT expired")
        return None
    except InvalidTokenError as e:
        logger.warning(f"JWT validation failed: {e}")
        return None

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "agent": os.getenv("AGENT_NAME", "budget-report"),
        "role": os.getenv("AGENT_ROLE", "caller"),
    }

@app.post("/flush-token")
async def flush_token(request: Request):
    """Clear the cached Entra token so the next request acquires a fresh one.
    Use after app role assignments change — new tokens will include updated roles."""
    if not ADMIN_KEY:
        return JSONResponse({"error": "mgmt_api_key_not_configured"}, status_code=500)
    if request.headers.get("X-Spiffe-Admin-Key") != ADMIN_KEY:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    flush_cached_token()
    return {"status": "flushed", "message": "Token cache cleared. Next request will acquire a fresh token."}

@app.post("/call-backend")
async def call_backend(action: str = "echo", message: str = "hello from caller"):
    agent_name = os.getenv("AGENT_NAME", "budget-report")
    payload = {"action": action, "params": {"message": message}}
    headers = {"X-Caller-Agent": agent_name, "Content-Type": "application/json"}

    logger.info(f"[{agent_name}] Calling BudgetBackend at {BACKEND_ENDPOINT}/budget/read")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(f"{BACKEND_ENDPOINT}/budget/read", json=payload, headers=headers)
        logger.info(f"[{agent_name}] BudgetBackend responded with status {response.status_code}")
        return {
            "caller": agent_name,
            "target": "budget-backend",
            "http_status": response.status_code,
            "response": response.json() if response.status_code == 200 else response.text,
        }
    except Exception:
        logger.exception(f"[{agent_name}] Failed to call BudgetBackend")
        return {"caller": agent_name, "target": "budget-backend", "http_status": 0, "error": "request_failed"}

@app.post("/call-backend-raw")
async def call_backend_raw(request: Request, method: str = "GET", path: str = "/budget/read", body: str = ""):
    """Send an HTTP request to BudgetBackend via the SPIFFE egress proxy."""
    agent_name = os.getenv("AGENT_NAME", "budget-report")
    # Require admin key for raw proxy endpoint (closes #20)
    if not ADMIN_KEY:
        return JSONResponse({"error": "management API key not configured"}, status_code=500)
    if not secrets.compare_digest(request.headers.get("X-Spiffe-Admin-Key", ""), ADMIN_KEY):
        return JSONResponse(
            {"caller": agent_name, "http_status": 401, "error": "unauthorized"},
            status_code=401,
        )

    if method.upper() not in ALLOWED_METHODS:
        return {"caller": agent_name, "error": f"Method not allowed: {method}", "http_status": 400}
    if not ALLOWED_PATH_PATTERN.match(path):
        return {"caller": agent_name, "error": f"Path not allowed: {path}", "http_status": 400}

    url = f"{BACKEND_ENDPOINT}{path}"
    headers = {"X-Caller-Agent": agent_name, "Content-Type": "application/json"}

    # Include Entra Agent ID token if available (OAuth2 layer)
    entra_token = await get_entra_token_async()
    last_err = get_last_token_error()
    if entra_token:
        headers["Authorization"] = f"Bearer {entra_token}"
    elif last_err and "AADSTS53003" in last_err:
        # CA policy blocked token issuance — report immediately
        return {
            "caller": agent_name,
            "target": "budget-backend",
            "method": method.upper(),
            "path": path,
            "http_status": 403,
            "response": {
                "error": "ca_policy_blocked",
                "enforcement_layer": "conditional_access",
                "detail": last_err,
                "message": "Conditional Access policy denied token issuance (AADSTS53003).",
            },
        }
    else:
        return {
            "caller": agent_name,
            "target": "budget-backend",
            "method": method.upper(),
            "path": path,
            "http_status": 401,
            "response": {
                "error": "token_acquisition_failed",
                "enforcement_layer": "authentication",
                "detail": last_err or "No Entra token available",
                "message": "Could not acquire an Entra token for authentication.",
            },
        }

    request_body = body if body else None
    if not request_body and method.upper() in ("POST", "PUT", "PATCH"):
        request_body = '{"amount": 5000, "description": "RBAC test from BudgetReport"}'

    logger.info(f"[{agent_name}] Raw call: {method} {url}")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.request(
                method=method.upper(),
                url=url,
                headers=headers,
                content=request_body,
            )
        logger.info(f"[{agent_name}] BudgetBackend responded: {response.status_code}")

        try:
            resp_body = response.json()
        except Exception:
            resp_body = response.text

        result = {
            "caller": agent_name,
            "target": "budget-backend",
            "method": method.upper(),
            "path": path,
            "http_status": response.status_code,
            "response": resp_body,
        }

        # Include token provenance so callers can see the full exchange tree
        provenance = get_token_provenance()
        if provenance:
            result["token_provenance"] = provenance

        return result
    except Exception as e:
        logger.error(f"[{agent_name}] Raw call failed: {e}")
        return {
            "caller": agent_name,
            "target": "budget-backend",
            "method": method.upper(),
            "path": path,
            "http_status": 0,
            "error": "request_failed",
        }

# ---------------------------------------------------------------------------
# A2A Endpoints — Direct caller path and direct target path
# ---------------------------------------------------------------------------

APPROVAL_ENDPOINT = os.getenv("APPROVAL_ENDPOINT", "")
ADMIN_CONTROL_PLANE_ENDPOINT = os.getenv("ADMIN_CONTROL_PLANE_ENDPOINT", "")
MGMT_API_KEY = os.getenv("MGMT_API_KEY", "")
AGENT_TAG = os.getenv("AGENT_TAG", "finance")

# Build A2A target URLs dynamically from all A2A_TARGET_URL_* env vars.
# This supports dynamic agents added via add-demo-agent.sh without code changes.
A2A_TARGET_URLS = {}
_A2A_PREFIX = "A2A_TARGET_URL_"
for _key, _val in os.environ.items():
    if _key.startswith(_A2A_PREFIX) and _val:
        _agent = _key[len(_A2A_PREFIX):].lower().replace("_", "-")
        A2A_TARGET_URLS[_agent] = _val
# Legacy fallback: APPROVAL_ENDPOINT maps to budget-approval
if APPROVAL_ENDPOINT and "budget-approval" not in A2A_TARGET_URLS:
    A2A_TARGET_URLS["budget-approval"] = APPROVAL_ENDPOINT

# Build MI client ID → agent name mapping dynamically from all MI_CLIENT_ID_* env vars.
# This supports dynamic agents whose JWT appid needs resolution.
_MI_TO_AGENT = {}
_MI_PREFIX = "MI_CLIENT_ID_"
for _key, _val in os.environ.items():
    if _key.startswith(_MI_PREFIX) and _val:
        _agent = _key[len(_MI_PREFIX):].lower().replace("_", "-")
        _MI_TO_AGENT[_val] = _agent

_ENTRA_ID_TO_AGENT = {}
_ENTRA_ID_PREFIX = "ENTRA_AGENT_ID_"
for _key, _val in os.environ.items():
    if _key.startswith(_ENTRA_ID_PREFIX) and _val and _key != "ENTRA_AGENT_ID":
        _agent = _key[len(_ENTRA_ID_PREFIX):].lower().replace("_", "-")
        _ENTRA_ID_TO_AGENT[_val] = _agent


def resolve_caller_name(jwt_claims):
    if jwt_claims:
        appid = jwt_claims.get("appid", "")
        if appid in _ENTRA_ID_TO_AGENT:
            return _ENTRA_ID_TO_AGENT[appid]
        if appid in _MI_TO_AGENT:
            return _MI_TO_AGENT[appid]
    return ""


def _spiffe_id_matches_caller(spiffe_id: str, caller_identifier: str) -> bool:
    """Check if a SPIFFE ID matches a caller identifier (name or UUID)."""
    if not spiffe_id or not caller_identifier:
        return False
    if spiffe_id.endswith("/" + caller_identifier) or caller_identifier == spiffe_id:
        return True
    return False


async def _query_risk_store(caller_identifier: str) -> str:
    if not ADMIN_CONTROL_PLANE_ENDPOINT:
        return "low"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            headers = {}
            if MGMT_API_KEY:
                headers["X-Spiffe-Admin-Key"] = MGMT_API_KEY
            resp = await client.get(f"{ADMIN_CONTROL_PLANE_ENDPOINT}/admin/agent-risk", headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for spiffe_id, risk in data.get("risks", {}).items():
                    if _spiffe_id_matches_caller(spiffe_id, caller_identifier):
                        return risk
            # If caller is a resolved name, look up its SPIFFE ID from policy
            if caller_identifier and not caller_identifier.startswith("spiffe://"):
                pol_resp = await client.get(f"{ADMIN_CONTROL_PLANE_ENDPOINT}/admin/policy", headers=headers)
                if pol_resp.status_code == 200:
                    policy = pol_resp.json()
                    caller_spiffe = ""
                    for p in policy.get("policies", []):
                        if p.get("name") == caller_identifier:
                            caller_spiffe = p.get("spiffe_id_prefix", "") or p.get("spiffe_id", "")
                            break
                    if caller_spiffe:
                        for spiffe_id, risk in data.get("risks", {}).items():
                            if spiffe_id.startswith(caller_spiffe) or spiffe_id == caller_spiffe:
                                return risk
    except Exception as e:
        logger.warning(f"Risk store query failed: {e}")
    return "low"


async def _query_caller_ca(caller_identifier: str) -> dict:
    """Query admin control-plane for a caller's CA config (state + tag)."""
    if not ADMIN_CONTROL_PLANE_ENDPOINT:
        return {"agent_state": "", "agent_tag": ""}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            headers = {}
            if MGMT_API_KEY:
                headers["X-Spiffe-Admin-Key"] = MGMT_API_KEY
            resp = await client.get(f"{ADMIN_CONTROL_PLANE_ENDPOINT}/admin/policy", headers=headers)
            if resp.status_code == 200:
                policy = resp.json()
                for p in policy.get("policies", []):
                    eid = p.get("entra_agent_id", "")
                    name = p.get("name", "")
                    spiffe_id = p.get("spiffe_id_prefix", "") or p.get("spiffe_id", "")
                    if (eid and caller_identifier == eid) or (caller_identifier == name) or (caller_identifier in spiffe_id):
                        ca = p.get("ca", {})
                        return {
                            "agent_state": ca.get("agent_state", "enabled"),
                            "agent_tag": ca.get("agent_tag", ""),
                        }
    except Exception as e:
        logger.warning(f"Policy store query failed: {e}")
    return {"agent_state": "", "agent_tag": ""}


async def _call_target(target: str):
    agent_name = os.getenv("AGENT_NAME", "budget-report")
    target_url = (A2A_TARGET_URLS.get(target) or "").rstrip("/")
    if not target_url:
        return {"caller": agent_name, "target": target, "http_status": 0, "error": f"Target not configured: {target}"}

    headers = {"X-Caller-Agent": agent_name, "Content-Type": "application/json"}
    entra_token = await get_entra_token_async()
    if entra_token:
        headers["Authorization"] = f"Bearer {entra_token}"
    else:
        # Token acquisition failed — check for specific CA policy block error
        is_ca_block = get_last_token_error() and "AADSTS53003" in get_last_token_error()
        return {
            "caller": agent_name,
            "target": target,
            "http_status": 403 if is_ca_block else 401,
            "response": {
                "error": "ca_policy_blocked" if is_ca_block else "token_acquisition_failed",
                "enforcement_layer": "conditional_access" if is_ca_block else "authentication",
                "detail": get_last_token_error() or "No Entra token available",
                "message": "Conditional Access policy denied token issuance for this agent (AADSTS53003). "
                           "The agent is flagged as high-risk and the CA policy blocks high-risk agents."
                           if is_ca_block else "Could not acquire an Entra token for A2A authentication.",
            },
        }

    logger.info(f"[{agent_name}] A2A call to {target} at {target_url}/a2a/status")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{target_url}/a2a/status", headers=headers)
        try:
            resp_body = resp.json()
        except Exception:
            resp_body = resp.text
        return {
            "caller": agent_name,
            "target": target,
            "http_status": resp.status_code,
            "response": resp_body,
        }
    except Exception:
        logger.exception(f"[{agent_name}] A2A call failed")
        return {"caller": agent_name, "target": target, "http_status": 0, "error": "request_failed"}


@app.get("/call-agent")
async def call_agent(target: str):
    return await _call_target(target)


@app.get("/call-approval")
async def call_approval():
    return await _call_target("budget-approval")


@app.get("/a2a/status")
async def a2a_status(request: Request):
    """Direct A2A target endpoint with JWT + CA checks."""
    agent_name = os.getenv("AGENT_NAME", "budget-report")
    auth_header = request.headers.get("Authorization", "")

    jwt_claims = None
    if auth_header.startswith("Bearer "):
        token_str = auth_header[7:]
        jwt_claims = validate_entra_jwt(token_str)
        if jwt_claims is None:
            return JSONResponse({
                "error": "invalid_token",
                "enforcement_layer": "jwt",
                "message": "JWT validation failed (signature, issuer, audience, or expiration)",
            }, status_code=401)
        caller_id = resolve_caller_name(jwt_claims) or jwt_claims["oid"] or jwt_claims["appid"]
    else:
        return JSONResponse({
            "error": "missing_token",
            "enforcement_layer": "jwt",
            "message": "Authorization header with Bearer token is required",
        }, status_code=401)

    # --- Layer 4b: Agent state check (admin kill switch) ---
    caller_ca = await _query_caller_ca(caller_id)
    if caller_ca["agent_state"] == "disabled":
        logger.warning(f"[{agent_name}] A2A blocked: {caller_id} agent_state=disabled")
        return JSONResponse({
            "error": "agent_disabled",
            "enforcement_layer": "conditional_access",
            "caller": caller_id,
        }, status_code=403)

    # --- Layer 4b: Risk check (CA policy-driven) ---
    caller_oid = jwt_claims["oid"] or jwt_claims["appid"]
    fallback_risk = await _query_risk_store(caller_id)
    from ca_evaluator import get_evaluator
    ca_eval = get_evaluator()
    blocked, ca_details = await ca_eval.should_block_caller(caller_oid, fallback_risk=fallback_risk)
    if blocked:
        return JSONResponse({
            "error": "agent_risk_blocked",
            "enforcement_layer": "conditional_access",
            "agent_risk": ca_details.get("agent_risk", "unknown"),
            "caller": caller_id,
            "enforcement": {
                "jwt_validated": True,
                "jwt_oid": jwt_claims["oid"],
                "jwt_roles": jwt_claims["roles"],
                "risk_level": ca_details.get("agent_risk", "unknown"),
                "enforcement_source": ca_details.get("enforcement_source", "unknown"),
                "blocked_risk_levels": ca_details.get("blocked_risk_levels", []),
                "ca_policy_ids": ca_details.get("ca_policy_ids", []),
                "tag_match": False,
                "caller_tag": None,
                "target_tag": AGENT_TAG,
                "layer": "3_jwt + 4b_ca_policy",
            },
        }, status_code=403)

    caller_tag = caller_ca["agent_tag"]
    if caller_tag.lower() != AGENT_TAG.lower():
        return JSONResponse({
            "error": "agent_tag_mismatch",
            "enforcement_layer": "conditional_access",
            "caller_tag": caller_tag,
            "target_tag": AGENT_TAG,
            "caller": caller_id,
            "enforcement": {
                "jwt_validated": True,
                "jwt_oid": jwt_claims["oid"],
                "jwt_roles": jwt_claims["roles"],
                "risk_level": fallback_risk,
                "tag_match": False,
                "caller_tag": caller_tag,
                "target_tag": AGENT_TAG,
                "layer": "3_jwt + 4b_app_layer",
            },
        }, status_code=403)

    return {
        "status": "ok",
        "agent": agent_name,
        "caller": caller_id,
        "resource": "budget-report",
        "summary": "Direct A2A status from BudgetReport",
        "enforcement": {
            "jwt_validated": True,
            "jwt_oid": jwt_claims["oid"],
            "jwt_roles": jwt_claims["roles"],
            "risk_level": fallback_risk,
            "tag_match": True,
            "caller_tag": caller_tag,
            "target_tag": AGENT_TAG,
            "layer": "3_jwt + 4b_app_layer",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
