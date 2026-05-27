"""
Security Portal Mock — Agent Risk Signal Source
=====================================================
Simulates an external threat detection service that pushes agent risk levels to the
Identity Research for Agent Management Using SPIFFE sidecar's management API.

This demonstrates:
1. External EDR integration with the sidecar risk store
2. Real-time agent risk changes affecting enforcement
3. The same /agent-risk endpoint can be called by any threat signal source

Usage:
    python3 securityportal-mock/server.py

Automatically reads portal/portal-config.json to discover the admin-control-plane
URL, mgmt API key, agent SPIFFE IDs, and Entra agent OIDs. No arguments needed.

Optional overrides:
    python3 securityportal-mock/server.py --port 8560 --config path/to/portal-config.json
    python3 securityportal-mock/server.py --mgmt-url https://admin-control-plane.xyz.azurecontainerapps.io/admin
"""
import json
import os
import copy
import logging
import argparse
import sys
from typing import Optional, Dict, Any, List
from pathlib import Path

import httpx
import yaml
from fastapi import FastAPI
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securityportal-mock")

# Add shared module path for JWT validator
REPO_ROOT = Path(__file__).resolve().parent.parent
SHARED_DIR = REPO_ROOT / "src" / "shared"
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))

try:
    from jwt_validator import EntraJWTValidator
except ImportError:
    EntraJWTValidator = None  # type: ignore[misc,assignment]

app = FastAPI(
    title="Security Portal Mock — Agent Risk Portal",
    description="External threat signal source for Identity Research for Agent Management Using SPIFFE agent risk enforcement",
    version="3.0.0",
)


@app.on_event("startup")
async def startup_config():
    """Initialize config when running under uvicorn (main() not called)."""
    if not MGMT_URL and os.getenv("PORTAL_MODE") == "cloud":
        default_config = str(Path(__file__).resolve().parent.parent / "portal" / "portal-config.json")
        _load_portal_config(default_config)
        _load_graph_creds_from_azd()
        _init_securityportal_auth()
        logger.info("Startup config loaded: MGMT_URL=%s", MGMT_URL)

# ---------------------------------------------------------------------------
# Auth — Entra JWT validation (disabled when AUTH_CLIENT_ID env var not set)
# ---------------------------------------------------------------------------

AUTH_CLIENT_ID = os.getenv("AUTH_CLIENT_ID", "")
ISP_ADMIN_GROUP_ID = os.getenv("ISP_ADMIN_GROUP_ID", "")
ISP_VIEWER_GROUP_ID = os.getenv("ISP_VIEWER_GROUP_ID", "")
_jwt_validator = None  # type: Optional[EntraJWTValidator]

_PUBLIC_PATHS = {"/api/auth-config", "/api/health", "/health", "/", "/favicon.ico",
                 "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png"}


def _init_securityportal_auth():
    """Initialize JWT validator if AUTH_CLIENT_ID is set."""
    global _jwt_validator
    if not AUTH_CLIENT_ID or EntraJWTValidator is None:
        logger.info("AUTH_CLIENT_ID not set — auth disabled (local dev mode)")
        return
    tenant_id = os.getenv("AZURE_TENANT_ID", "")
    if not tenant_id:
        logger.warning("AUTH_CLIENT_ID set but AZURE_TENANT_ID missing — auth disabled")
        return
    _jwt_validator = EntraJWTValidator(
        tenant_id=tenant_id,
        client_id=AUTH_CLIENT_ID,
        admin_group_id=ISP_ADMIN_GROUP_ID,
        viewer_group_id=ISP_VIEWER_GROUP_ID,
    )
    logger.info("Entra JWT auth enabled (client_id=%s)", AUTH_CLIENT_ID)


def _html_escape(s):
    # type: (str) -> str
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


@app.get("/api/auth-config")
async def get_auth_config():
    """Return auth config for MSAL.js init. No auth required."""
    tenant_id = os.getenv("AZURE_TENANT_ID", "")
    return {
        "auth_required": bool(AUTH_CLIENT_ID),
        "client_id": AUTH_CLIENT_ID,
        "authority": "https://login.microsoftonline.com/%s" % tenant_id if tenant_id else "",
        "admin_group_id": ISP_ADMIN_GROUP_ID,
        "viewer_group_id": ISP_VIEWER_GROUP_ID,
    }


@app.middleware("http")
async def auth_middleware(request, call_next):
    """Validate JWT on API routes. Viewers can GET but not PUT."""
    path = request.url.path
    from starlette.requests import Request as _Req

    if path in _PUBLIC_PATHS or not path.startswith(("/api/", "/set-risk", "/agents", "/isolate-agent", "/restore-agent")):
        if path == "/":
            response = await call_next(request)
            return response
        response = await call_next(request)
        return response

    if _jwt_validator is None:
        response = await call_next(request)
        return response

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    token = auth_header[7:]
    try:
        claims = _jwt_validator.validate_token(token)
    except ValueError as e:
        logger.error("JWT validation failed (JWKS): %s", e)
        return JSONResponse(status_code=401, content={"detail": "invalid_token"})
    except Exception as e:
        logger.exception("JWT validation failed (unexpected): %s", e)
        return JSONResponse(status_code=401, content={"detail": "invalid_token"})

    try:
        role = _jwt_validator.check_role(claims)
    except PermissionError as e:
        logger.warning("JWT role check denied: %s", e)
        return JSONResponse(status_code=403, content={"detail": "forbidden"})

    # Viewers can read but not change risk levels or isolate agents
    if role == "viewer" and request.method.upper() in ("PUT", "POST"):
        return JSONResponse(
            status_code=403,
            content={"detail": "Viewer role does not have permission for this action"}
        )

    response = await call_next(request)
    return response

# ── Configuration (populated at startup from portal-config.json) ──────────────
# Management API base URL (admin-control-plane /admin prefix)
MGMT_URL = ""
# API key for admin-control-plane authentication
MGMT_API_KEY = ""
# Agent metadata loaded from config
AGENT_CONFIG = {}  # type: Dict[str, Dict[str, Any]]

# Tag mapping: derive department tag from agent key name
_AGENT_TAGS = {
    "budget-report": "finance",
    "budget-backend": "finance",
    "budget-approval": "finance",
    "employee-menus": "",
    "admin-control-plane": "admin",
}

# Graph API credentials for pushing risk to Entra ID Protection
# Uses: IdentityRiskyAgent.ReadWrite.All permission
GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID", "")
GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET", "")
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
GRAPH_BETA = "https://graph.microsoft.com/beta"

# SPIFFE ID → Entra agent OID mapping (set by deploy.sh or loaded from config)
# Format: AGENT_OID_<NAME>=<oid>
AGENT_OIDS = {}  # type: Dict[str, str]
for key, val in os.environ.items():
    if key.startswith("AGENT_OID_"):
        agent_name = key[len("AGENT_OID_"):].lower().replace("_", "-")
        AGENT_OIDS[agent_name] = val

# In-memory Graph token cache
_graph_token_cache = {"token": None, "expires_at": 0}  # type: Dict[str, Any]

# Pre-isolation snapshots for restore (keyed by agent name)
# Stores: { "policy_entry": <original YAML dict for this agent>, "mtls_ids": [<full allow list>] }
_isolation_snapshots = {}  # type: Dict[str, Dict[str, Any]]


def _load_graph_creds_from_azd():
    # type: () -> None
    """Load Graph API credentials from azd env if not already set via env vars."""
    global GRAPH_CLIENT_ID, GRAPH_CLIENT_SECRET, AZURE_TENANT_ID
    if GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET and AZURE_TENANT_ID:
        return  # Already configured via env vars

    import subprocess
    try:
        result = subprocess.run(
            ["azd", "env", "get-values"],
            capture_output=True, text=True, timeout=10,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
        if result.returncode != 0:
            logger.warning("azd env get-values failed (rc=%d) — Graph creds not loaded", result.returncode)
            return
        for line in result.stdout.splitlines():
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            val = val.strip('"').strip("'")
            if key == "ENTRA_AGENTID_CLIENT_ID" and not GRAPH_CLIENT_ID:
                GRAPH_CLIENT_ID = val
            elif key == "ENTRA_AGENTID_CLIENT_SECRET" and not GRAPH_CLIENT_SECRET:
                GRAPH_CLIENT_SECRET = val
            elif key == "AZURE_TENANT_ID" and not AZURE_TENANT_ID:
                AZURE_TENANT_ID = val
        if GRAPH_CLIENT_ID and AZURE_TENANT_ID:
            logger.info("Graph API credentials loaded from azd env")
        else:
            logger.warning("Graph API credentials not found in azd env — Entra risk push will be skipped")
    except FileNotFoundError:
        logger.warning("azd CLI not found — Graph creds not loaded")
    except Exception as e:
        logger.warning("Failed to load Graph creds from azd: %s", e)


def _load_portal_config(config_path):  # type: (str) -> Dict[str, Any]
    """Load config from file or environment variables (cloud mode)."""
    global MGMT_URL, MGMT_API_KEY, AGENT_CONFIG, AGENT_OIDS

    # Cloud mode: build config from env vars
    if os.getenv("PORTAL_MODE") == "cloud":
        admin_cp_url = os.getenv("ADMIN_CP_URL", "")
        if admin_cp_url:
            MGMT_URL = admin_cp_url.rstrip("/") + "/admin"
            logger.info("Cloud mode — Management API: %s", MGMT_URL)
        MGMT_API_KEY = os.getenv("MGMT_API_KEY", "")
        if MGMT_API_KEY:
            logger.info("Admin API key loaded from env")

        # Discover agents from admin-control-plane (same as portal/server.py)
        if admin_cp_url and MGMT_API_KEY:
            try:
                import httpx as _httpx
                resp = _httpx.get(
                    admin_cp_url.rstrip("/") + "/admin/agents",
                    headers={"X-Spiffe-Admin-Key": MGMT_API_KEY},
                    timeout=10,
                )
                if resp.status_code == 200:
                    discovered = resp.json().get("agents", {})
                    for key, info in discovered.items():
                        # Hide admin-control-plane — it's infrastructure, not
                        # a governed business agent.  No one should change its
                        # risk level from the SOC portal.
                        if key == "admin-control-plane":
                            continue
                        AGENT_CONFIG[key] = {
                            "name": info.get("name", key),
                            "role": info.get("role", ""),
                            "url": info.get("url", ""),
                            "spiffe_id": info.get("spiffe_id", ""),
                            "entra_agent_id": info.get("entra_agent_id", ""),
                            "agent_tag": info.get("agent_tag", ""),
                        }
                        oid = info.get("entra_agent_id", "")
                        if oid and key not in AGENT_OIDS:
                            AGENT_OIDS[key] = oid
                    logger.info("Discovered %d agents from admin-control-plane", len(AGENT_CONFIG))
                else:
                    logger.warning("Agent discovery returned %d", resp.status_code)
            except Exception as e:
                logger.warning("Agent discovery failed: %s", e)

        return {"mode": "cloud"}

    path = Path(config_path)
    if not path.exists():
        logger.warning("Config not found at %s — mgmt calls will fail", config_path)
        return {}

    with open(str(path), "r") as f:
        config = json.load(f)

    # Derive mgmt URL from control_plane.url (same pattern as portal/server.py)
    control_plane = config.get("control_plane", {})
    cp_url = control_plane.get("url", "")
    if cp_url:
        MGMT_URL = cp_url.rstrip("/") + "/admin"
        logger.info("Management API: %s", MGMT_URL)

    # API key
    MGMT_API_KEY = config.get("mgmt_api_key", "")
    if MGMT_API_KEY:
        logger.info("Admin API key loaded from config")

    # Agent metadata
    AGENT_CONFIG = config.get("agents", {})

    # Populate AGENT_OIDS from config (env vars take precedence)
    for agent_key, agent_info in AGENT_CONFIG.items():
        oid = agent_info.get("entra_agent_id", "")
        if oid and agent_key not in AGENT_OIDS:
            AGENT_OIDS[agent_key] = oid

    logger.info("Loaded %d agents from config", len(AGENT_CONFIG))
    return config


def _mgmt_headers(extra=None):  # type: (Optional[Dict[str, str]]) -> Dict[str, str]
    """Build headers for admin-control-plane requests (X-Spiffe-Admin-Key)."""
    headers = {}  # type: Dict[str, str]
    if MGMT_API_KEY:
        headers["X-Spiffe-Admin-Key"] = MGMT_API_KEY
    if extra:
        headers.update(extra)
    return headers


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the risk management UI."""
    html_path = Path(__file__).parent / "index.html"
    return HTMLResponse(html_path.read_text())


async def _get_graph_token() -> Optional[str]:
    """Get a Graph API token via client credentials flow. Returns None if not configured."""
    import time

    if not GRAPH_CLIENT_ID or not GRAPH_CLIENT_SECRET or not AZURE_TENANT_ID:
        return None

    now = time.time()
    if _graph_token_cache["token"] and _graph_token_cache["expires_at"] > now + 60:
        return _graph_token_cache["token"]

    token_url = f"https://login.microsoftonline.com/{AZURE_TENANT_ID}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(token_url, data={
            "client_id": GRAPH_CLIENT_ID,
            "client_secret": GRAPH_CLIENT_SECRET,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        })
        if resp.status_code == 200:
            data = resp.json()
            _graph_token_cache["token"] = data["access_token"]
            _graph_token_cache["expires_at"] = now + data.get("expires_in", 3600)
            return data["access_token"]
        logger.error(f"Graph token acquisition failed: {resp.status_code} {resp.text}")
        return None


def _resolve_agent_oid(spiffe_id: str) -> Optional[str]:
    """Extract agent OID from SPIFFE ID or look up from AGENT_OIDS mapping."""
    # Try to extract from SPIFFE ID: spiffe://aim.microsoft.com/ests/bp/<bp>/aid/<agent-oid>
    if "/aid/" in spiffe_id:
        return spiffe_id.split("/aid/")[-1]
    # Fallback: match by agent name in AGENT_OIDS mapping
    for name, oid in AGENT_OIDS.items():
        if name in spiffe_id:
            return oid
    return None


# Cache: appId -> SP object ID
_app_id_to_sp_oid = {}  # type: Dict[str, str]


async def _resolve_sp_object_id(app_id, token):
    # type: (str, str) -> Optional[str]
    """Resolve an appId (client ID) to the service principal's object ID via Graph.

    confirmCompromised/confirmSafe require SP object IDs, not appIds.
    """
    if app_id in _app_id_to_sp_oid:
        return _app_id_to_sp_oid[app_id]

    url = ("https://graph.microsoft.com/v1.0/servicePrincipals"
           "?$filter=appId eq '%s'&$select=id,displayName" % app_id)
    headers = {"Authorization": "Bearer %s" % token, "ConsistencyLevel": "eventual"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("value"):
                    sp_oid = data["value"][0]["id"]
                    display = data["value"][0].get("displayName", "")
                    logger.info("Resolved appId %s -> SP OID %s (%s)", app_id, sp_oid, display)
                    _app_id_to_sp_oid[app_id] = sp_oid
                    return sp_oid
            logger.warning("SP lookup for appId %s returned %d", app_id, resp.status_code)
    except Exception as e:
        logger.warning("SP lookup failed for appId %s: %s", app_id, e)
    return None


async def _push_risk_to_entra(agent_oid: str, risk_level: str) -> dict:
    """Push risk level to Entra ID Protection via Graph API.

    Uses:
    - POST /beta/identityProtection/riskyAgents/confirmCompromised (high risk)
    - POST /beta/identityProtection/riskyAgents/confirmSafe (low/clear risk)

    Returns dict with status info. Does not raise on failure.
    """
    token = await _get_graph_token()
    if not token:
        return {"entra_status": "skipped", "reason": "Graph credentials not configured"}

    # Resolve appId to SP object ID (Graph API needs SP OID, not appId)
    sp_oid = await _resolve_sp_object_id(agent_oid, token)
    if not sp_oid:
        logger.warning("Could not resolve appId %s to SP object ID, using raw value", agent_oid)
        sp_oid = agent_oid

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    if risk_level == "high":
        url = f"{GRAPH_BETA}/identityProtection/riskyAgents/confirmCompromised"
        body = {"agentIds": [sp_oid]}
    elif risk_level in ("low", "medium"):
        # confirmSafe clears risk state — no Graph API for 'medium' specifically
        url = f"{GRAPH_BETA}/identityProtection/riskyAgents/confirmSafe"
        body = {"agentIds": [sp_oid]}
    else:
        return {"entra_status": "skipped", "reason": f"unknown risk level: {risk_level}"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json=body, headers=headers)
            if resp.status_code == 204:
                action = "confirmCompromised" if risk_level == "high" else "confirmSafe"
                logger.info("Entra risk updated: appId=%s SP_OID=%s -> %s",
                            agent_oid, sp_oid, action)
                return {"entra_status": "success", "action": action,
                        "agent_oid": agent_oid, "sp_object_id": sp_oid}
            else:
                logger.warning(f"Entra risk update returned {resp.status_code}: {resp.text}")
                return {"entra_status": "error", "code": resp.status_code, "detail": resp.text[:200]}
    except Exception as e:
        logger.error(f"Failed to push risk to Entra: {e}")
        return {"entra_status": "error", "detail": "entra_push_failed"}


@app.get("/api/agents")
async def api_agents():
    """Return enriched agent metadata from portal-config.json for the frontend."""
    agents = []  # type: List[Dict[str, Any]]
    for agent_key, info in AGENT_CONFIG.items():
        agents.append({
            "key": agent_key,
            "name": info.get("name", agent_key),
            "spiffe_id": info.get("spiffe_id", ""),
            "entra_agent_id": info.get("entra_agent_id", ""),
            "role": info.get("role", ""),
            "tag": _AGENT_TAGS.get(agent_key, ""),
        })
    return {"agents": agents}


@app.get("/agents")
async def list_agents():
    """List all agents with current risk levels from the central risk store."""
    if not MGMT_URL:
        return {"error": "No management URL configured", "risks": {}}
    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            resp = await client.get(
                "{0}/agent-risk".format(MGMT_URL),
                headers=_mgmt_headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            return {"error": "Risk store returned {0}".format(resp.status_code), "risks": {}}
    except Exception as e:
        logger.warning("Failed to query risk store: %s", e)
        return {"error": "risk_store_unreachable", "risks": {}, "count": 0}


@app.put("/set-risk")
async def set_risk(spiffe_id: str, risk_level: str):
    """Push a risk level update to both Entra ID Protection and the sidecar risk store.

    Two-phase push:
    1. Entra ID Protection (Graph API) — sets agent risk in the identity platform
       so CA policies with agentIdRiskLevels condition take effect at token issuance.
    2. Sidecar risk store (management API) — updates the data-plane enforcement layer
       for immediate blocking of in-flight requests.
    """
    if risk_level not in ("low", "medium", "high"):
        return JSONResponse(
            {"error": f"Invalid risk level: {risk_level}. Must be low, medium, or high."},
            status_code=400,
        )

    result = {"spiffe_id": spiffe_id, "risk_level": risk_level}

    # Phase 1: Push to Entra ID Protection (Graph API)
    agent_oid = _resolve_agent_oid(spiffe_id)
    if agent_oid:
        entra_result = await _push_risk_to_entra(agent_oid, risk_level)
        result["entra"] = entra_result
    else:
        result["entra"] = {"entra_status": "skipped", "reason": "could not resolve agent OID"}
        logger.warning(f"Could not resolve agent OID from SPIFFE ID: {spiffe_id}")

    # Phase 2: Push to sidecar risk store (data-plane enforcement)
    if not MGMT_URL:
        result["sidecar"] = {"error": "No management URL configured"}
        return result

    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            resp = await client.put(
                "{0}/agent-risk".format(MGMT_URL),
                json={"spiffe_id": spiffe_id, "risk_level": risk_level},
                headers=_mgmt_headers(),
            )
            sidecar_result = resp.json()
            result["sidecar"] = sidecar_result
            entra_status = result.get("entra", {}).get("entra_status", "unknown")
            logger.info("Risk updated: %s -> %s (entra: %s, sidecar: ok)",
                        spiffe_id, risk_level, entra_status)
    except Exception as e:
        logger.error("Failed to push risk to sidecar: %s", e)
        result["sidecar"] = {"error": "sidecar_unreachable"}

    return result


# ---------------------------------------------------------------------------
# Agent Isolation — SOC "Kill Switch" (all 4 enforcement layers)
# ---------------------------------------------------------------------------


def _find_agent_spiffe_id(agent_key):
    # type: (str) -> Optional[str]
    """Resolve SPIFFE ID for an agent from config."""
    agent = AGENT_CONFIG.get(agent_key, {})
    if agent.get("spiffe_id"):
        return agent["spiffe_id"]
    return None


@app.post("/isolate-agent")
async def isolate_agent(request: Request):
    """SOC kill switch: isolate an agent across ALL 4 enforcement layers.

    Orchestrates:
      1. CA Risk (Layer 4b): Set risk to HIGH + Entra confirmCompromised
      2. CA + RBAC Policy (Layers 4b + 2): Set agent_state=disabled, all rules->deny
      3. mTLS (Layer 1): Remove agent from allow list
      4. OAuth (Layer 3): Implicit — blocked before JWT check reaches Layer 3

    Body: {"agent_key": "budget-report"}
    """
    body = await request.json()
    agent_key = body.get("agent_key", "")

    if not agent_key:
        return JSONResponse({"error": "agent_key is required"}, status_code=400)

    if agent_key == "admin-control-plane":
        return JSONResponse(
            {"error": "Cannot isolate admin-control-plane — would cause management self-lockout"},
            status_code=400,
        )

    if agent_key not in AGENT_CONFIG and agent_key not in _AGENT_TAGS:
        return JSONResponse({"error": "Unknown agent: %s" % agent_key}, status_code=404)

    spiffe_id = _find_agent_spiffe_id(agent_key)
    if not spiffe_id:
        return JSONResponse(
            {"error": "No SPIFFE ID found for %s" % agent_key}, status_code=400
        )

    if not MGMT_URL:
        return JSONResponse({"error": "No management URL configured"}, status_code=502)

    result = {
        "agent": agent_key,
        "spiffe_id": spiffe_id,
        "action": "isolated",
        "layers": {},
    }  # type: Dict[str, Any]

    # ── Step 1: CA Risk (Layer 4b) — Set to HIGH ──
    agent_oid = _resolve_agent_oid(spiffe_id)
    entra_result = {"entra_status": "skipped", "reason": "could not resolve agent OID"}
    if agent_oid:
        entra_result = await _push_risk_to_entra(agent_oid, "high")

    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.put(
                "{0}/agent-risk".format(MGMT_URL),
                json={"spiffe_id": spiffe_id, "risk_level": "high"},
                headers=_mgmt_headers(),
            )
            risk_result = resp.json() if resp.status_code == 200 else {"error": resp.text[:200]}
    except Exception as e:
        risk_result = {"error": "risk_update_failed"}

    result["layers"]["ca_risk"] = {
        "status": "success" if risk_result.get("status") == "updated" else "error",
        "risk_level": "high",
        "entra": entra_result,
        "sidecar": risk_result,
    }

    # ── Step 2: CA + RBAC Policy (Layers 4b + 2) — Disable agent ──
    policy_result = {}  # type: Dict[str, Any]
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            # Fetch current policy
            get_resp = await client.get(
                "{0}/policy".format(MGMT_URL),
                headers=_mgmt_headers(),
            )
            if get_resp.status_code != 200:
                raise Exception("Failed to fetch policy: %d" % get_resp.status_code)

            policy_data = get_resp.json()
            policy_yaml_str = policy_data.get("yaml", "")
            if not policy_yaml_str:
                # Some versions return the policy directly as JSON
                policy_doc = policy_data
            else:
                policy_doc = yaml.safe_load(policy_yaml_str)

            if not policy_doc or not isinstance(policy_doc, dict):
                raise Exception("Invalid policy document")

            # Find and snapshot the agent's policy entry
            policies = policy_doc.get("policies", [])
            agent_entry = None
            agent_idx = -1
            for i, p in enumerate(policies):
                if p.get("name") == agent_key:
                    agent_entry = p
                    agent_idx = i
                    break

            if agent_entry is None:
                policy_result = {"status": "error", "detail": "Agent not found in RBAC policy"}
            else:
                # Save snapshot for restore (deep copy)
                if agent_key not in _isolation_snapshots:
                    _isolation_snapshots[agent_key] = {}
                _isolation_snapshots[agent_key]["policy_entry"] = copy.deepcopy(agent_entry)

                # Modify: set agent_state=disabled, all rules->deny
                if "ca" not in agent_entry:
                    agent_entry["ca"] = {}
                agent_entry["ca"]["agent_state"] = "disabled"

                rules_denied = 0
                for rule in agent_entry.get("rules", []):
                    if rule.get("action") != "deny":
                        rule["action"] = "deny"
                        rules_denied += 1

                # Push updated policy
                # Remove empty spiffe_id when spiffe_id_prefix is set
                for p in policies:
                    if not p.get("spiffe_id") and p.get("spiffe_id_prefix"):
                        p.pop("spiffe_id", None)
                updated_yaml = yaml.safe_dump(policy_doc, sort_keys=False, default_flow_style=None)
                put_resp = await client.put(
                    "{0}/policy".format(MGMT_URL),
                    content=updated_yaml.encode("utf-8"),
                    headers=_mgmt_headers({"Content-Type": "application/x-yaml"}),
                )
                if put_resp.status_code == 200:
                    policy_result = {
                        "status": "success",
                        "agent_state": "disabled",
                        "rules_denied": rules_denied,
                    }
                else:
                    policy_result = {"status": "error", "detail": put_resp.text[:200]}
    except Exception as e:
        logger.error("Isolation policy update failed for %s: %s", agent_key, e)
        policy_result = {"status": "error", "detail": "policy_update_failed"}

    result["layers"]["ca_policy"] = policy_result
    result["layers"]["rbac"] = {
        "status": policy_result.get("status", "error"),
        "rules_denied": policy_result.get("rules_denied", 0),
    }

    # ── Step 3: mTLS (Layer 1) — Remove from allow list ──
    mtls_result = {}  # type: Dict[str, Any]
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            get_resp = await client.get(
                "{0}/mtls-policy".format(MGMT_URL),
                headers=_mgmt_headers(),
            )
            if get_resp.status_code != 200:
                raise Exception("Failed to fetch mTLS policy: %d" % get_resp.status_code)

            mtls_data = get_resp.json()
            current_ids = mtls_data.get("allowed_ids", [])

            # Save snapshot for restore
            if agent_key not in _isolation_snapshots:
                _isolation_snapshots[agent_key] = {}
            _isolation_snapshots[agent_key]["mtls_ids"] = list(current_ids)

            # Filter out the agent's SPIFFE ID
            new_ids = [sid for sid in current_ids if sid != spiffe_id]
            removed = len(current_ids) - len(new_ids)

            if removed > 0:
                put_resp = await client.put(
                    "{0}/mtls-policy".format(MGMT_URL),
                    json={"allowed_ids": new_ids},
                    headers=_mgmt_headers({"Content-Type": "application/json"}),
                )
                if put_resp.status_code == 200:
                    mtls_result = {"status": "success", "removed_from_allowlist": True}
                else:
                    mtls_result = {"status": "error", "detail": put_resp.text[:200]}
            else:
                mtls_result = {"status": "success", "removed_from_allowlist": False,
                               "note": "Agent was not in mTLS allow list"}
    except Exception as e:
        logger.error("Isolation mTLS update failed for %s: %s", agent_key, e)
        mtls_result = {"status": "error", "detail": "mtls_update_failed"}

    result["layers"]["mtls"] = mtls_result

    # OAuth (Layer 3) is implicit — denied at RBAC/CA before JWT check
    result["layers"]["oauth"] = {
        "status": "implicit",
        "note": "Blocked at RBAC + CA layers before JWT validation runs",
    }

    logger.info("AGENT ISOLATED: %s — all 4 enforcement layers locked down", agent_key)
    return result


@app.post("/restore-agent")
async def restore_agent(request: Request):
    """Restore an isolated agent — undo all 4 enforcement layer lockdowns.

    Reverses isolation by:
      1. Restoring original RBAC policy entry (agent_state, rules)
      2. Re-adding agent to mTLS allow list
      3. Setting risk to LOW + Entra confirmSafe

    Body: {"agent_key": "budget-report"}
    """
    body = await request.json()
    agent_key = body.get("agent_key", "")

    if not agent_key:
        return JSONResponse({"error": "agent_key is required"}, status_code=400)

    spiffe_id = _find_agent_spiffe_id(agent_key)
    if not spiffe_id:
        return JSONResponse(
            {"error": "No SPIFFE ID found for %s" % agent_key}, status_code=400
        )

    if not MGMT_URL:
        return JSONResponse({"error": "No management URL configured"}, status_code=502)

    snapshot = _isolation_snapshots.get(agent_key, {})

    result = {
        "agent": agent_key,
        "spiffe_id": spiffe_id,
        "action": "restored",
        "layers": {},
    }  # type: Dict[str, Any]

    # ── Step 1: Restore RBAC policy (Layers 4b + 2) ──
    policy_result = {}  # type: Dict[str, Any]
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            get_resp = await client.get(
                "{0}/policy".format(MGMT_URL),
                headers=_mgmt_headers(),
            )
            if get_resp.status_code != 200:
                raise Exception("Failed to fetch policy: %d" % get_resp.status_code)

            policy_data = get_resp.json()
            policy_yaml_str = policy_data.get("yaml", "")
            if not policy_yaml_str:
                policy_doc = policy_data
            else:
                policy_doc = yaml.safe_load(policy_yaml_str)

            if not policy_doc or not isinstance(policy_doc, dict):
                raise Exception("Invalid policy document")

            policies = policy_doc.get("policies", [])
            original_entry = snapshot.get("policy_entry")

            if original_entry:
                # Replace the agent's policy entry with the snapshot
                replaced = False
                for i, p in enumerate(policies):
                    if p.get("name") == agent_key:
                        policies[i] = original_entry
                        replaced = True
                        break
                if not replaced:
                    policies.append(original_entry)

                # Remove empty spiffe_id when spiffe_id_prefix is set
                # (sidecar rejects having both)
                for p in policies:
                    if not p.get("spiffe_id") and p.get("spiffe_id_prefix"):
                        p.pop("spiffe_id", None)

                updated_yaml = yaml.safe_dump(policy_doc, sort_keys=False, default_flow_style=None)
                put_resp = await client.put(
                    "{0}/policy".format(MGMT_URL),
                    content=updated_yaml.encode("utf-8"),
                    headers=_mgmt_headers({"Content-Type": "application/x-yaml"}),
                )
                if put_resp.status_code == 200:
                    policy_result = {
                        "status": "success",
                        "agent_state": original_entry.get("ca", {}).get("agent_state", "enabled"),
                    }
                else:
                    policy_result = {"status": "error", "detail": put_resp.text[:200]}
            else:
                # No snapshot — just re-enable the agent state
                # Don't flip rule actions: can't know which were originally allow vs deny
                for p in policies:
                    if p.get("name") == agent_key:
                        if "ca" in p:
                            p["ca"]["agent_state"] = "enabled"
                        break

                # Remove empty spiffe_id when spiffe_id_prefix is set
                for p in policies:
                    if not p.get("spiffe_id") and p.get("spiffe_id_prefix"):
                        p.pop("spiffe_id", None)

                updated_yaml = yaml.safe_dump(policy_doc, sort_keys=False, default_flow_style=None)
                put_resp = await client.put(
                    "{0}/policy".format(MGMT_URL),
                    content=updated_yaml.encode("utf-8"),
                    headers=_mgmt_headers({"Content-Type": "application/x-yaml"}),
                )
                if put_resp.status_code == 200:
                    policy_result = {"status": "success", "agent_state": "enabled",
                                     "note": "No snapshot — used best-effort restore"}
                else:
                    policy_result = {"status": "error", "detail": put_resp.text[:200]}
    except Exception as e:
        logger.error("Restore policy failed for %s: %s", agent_key, e)
        policy_result = {"status": "error", "detail": "policy_update_failed"}

    result["layers"]["ca_policy"] = policy_result
    result["layers"]["rbac"] = {"status": policy_result.get("status", "error")}

    # ── Step 2: Restore mTLS allow list (Layer 1) ──
    mtls_result = {}  # type: Dict[str, Any]
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            get_resp = await client.get(
                "{0}/mtls-policy".format(MGMT_URL),
                headers=_mgmt_headers(),
            )
            if get_resp.status_code != 200:
                raise Exception("Failed to fetch mTLS policy: %d" % get_resp.status_code)

            mtls_data = get_resp.json()
            current_ids = mtls_data.get("allowed_ids", [])

            if spiffe_id not in current_ids:
                new_ids = current_ids + [spiffe_id]
                put_resp = await client.put(
                    "{0}/mtls-policy".format(MGMT_URL),
                    json={"allowed_ids": new_ids},
                    headers=_mgmt_headers({"Content-Type": "application/json"}),
                )
                if put_resp.status_code == 200:
                    mtls_result = {"status": "success", "added_to_allowlist": True}
                else:
                    mtls_result = {"status": "error", "detail": put_resp.text[:200]}
            else:
                mtls_result = {"status": "success", "added_to_allowlist": False,
                               "note": "Agent was already in mTLS allow list"}
    except Exception as e:
        logger.error("Restore mTLS failed for %s: %s", agent_key, e)
        mtls_result = {"status": "error", "detail": "mtls_update_failed"}

    result["layers"]["mtls"] = mtls_result

    # ── Step 3: CA Risk (Layer 4b) — Set to LOW ──
    agent_oid = _resolve_agent_oid(spiffe_id)
    entra_result = {"entra_status": "skipped", "reason": "could not resolve agent OID"}
    if agent_oid:
        entra_result = await _push_risk_to_entra(agent_oid, "low")

    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.put(
                "{0}/agent-risk".format(MGMT_URL),
                json={"spiffe_id": spiffe_id, "risk_level": "low"},
                headers=_mgmt_headers(),
            )
            risk_result = resp.json() if resp.status_code == 200 else {"error": resp.text[:200]}
    except Exception as e:
        risk_result = {"error": "risk_update_failed"}

    result["layers"]["ca_risk"] = {
        "status": "success" if risk_result.get("status") == "updated" else "error",
        "risk_level": "low",
        "entra": entra_result,
        "sidecar": risk_result,
    }

    result["layers"]["oauth"] = {
        "status": "implicit",
        "note": "Restored — OAuth enforcement follows RBAC rules",
    }

    # Clean up snapshot
    _isolation_snapshots.pop(agent_key, None)

    logger.info("AGENT RESTORED: %s — all 4 enforcement layers re-enabled", agent_key)
    return result


@app.get("/api/isolation-status")
async def get_isolation_status():
    """Return which agents are currently isolated (have snapshots)."""
    return {"isolated_agents": list(_isolation_snapshots.keys())}


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "securityportal-mock",
        "mgmt_url": MGMT_URL,
    }


if __name__ == "__main__":
    import uvicorn

    # Default config path: ../portal/portal-config.json relative to this script
    default_config = str(Path(__file__).resolve().parent.parent / "portal" / "portal-config.json")

    parser = argparse.ArgumentParser(description="Security Portal Mock")
    parser.add_argument("--port", type=int, default=8560, help="Port to listen on")
    parser.add_argument("--config", type=str, default=default_config,
                        help="Path to portal-config.json (default: ../portal/portal-config.json)")
    parser.add_argument("--mgmt-url", type=str, default=None,
                        help="Override management API URL (default: auto-discovered from config)")
    args = parser.parse_args()

    # Load config first
    _load_portal_config(args.config)

    # Load Graph API credentials from azd env (if not set via env vars)
    _load_graph_creds_from_azd()

    # Initialize Entra JWT auth (if AUTH_CLIENT_ID is configured)
    _init_securityportal_auth()

    # CLI --mgmt-url overrides config-derived URL
    if args.mgmt_url:
        MGMT_URL = args.mgmt_url

    logger.info("Starting Security Portal Mock: http://localhost:%d", args.port)
    logger.info("Pushing risk updates to: %s", MGMT_URL)
    logger.info("Agents loaded: %s", ", ".join(AGENT_CONFIG.keys()) if AGENT_CONFIG else "(none)")
    uvicorn.run(app, host="127.0.0.1", port=args.port)
