"""Authenticated API routes."""

import re
from typing import Any

from fastapi import APIRouter, Depends, Request
import yaml

from ..dependencies import admin_only, get_container, get_request_id, viewer_or_admin
from ..errors import PortalError

_AGENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
from ..schemas import (
    ExecuteA2ARequest,
    ExecuteRequest,
    ExternalAgentEntry,
    MTLSPolicyUpdate,
    PolicyConfigCreate,
    QuickFixRequest,
    UpdateAgentRiskRequest,
)

router = APIRouter(prefix="/api")


async def _resolve_external_invoke_url(container, agent_key):
    # type: (Any, str) -> str
    """Look up invoke_url from the external agent store for federated callers."""
    try:
        agents = await container.external_agent_store.list_agents()
        for agent in agents:
            if agent.get("name") == agent_key:
                return agent.get("invoke_url", "")
    except Exception:
        pass
    return ""


@router.get("/config")
async def get_config(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return container.settings.to_public_dict()


@router.get("/system-status")
async def get_system_status(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.health_service.system_status(get_request_id(request))


@router.post("/execute")
async def execute_request(payload: ExecuteRequest, request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    caller = container.settings.agents.get(payload.caller)
    if not caller:
        raise PortalError(400, "unknown_caller", "Unknown caller: {0}".format(payload.caller))
    caller_url = caller.url or await _resolve_external_invoke_url(container, payload.caller)
    return await container.agent_invoker.execute_backend(caller_url, payload.method.value, payload.path, get_request_id(request), container.settings.mgmt_api_key)


@router.post("/a2a-call")
async def execute_a2a_call(payload: ExecuteA2ARequest, request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    caller = container.settings.agents.get(payload.caller)
    target = container.settings.agents.get(payload.target)
    if not caller:
        raise PortalError(400, "unknown_caller", "Unknown caller: {0}".format(payload.caller))
    if not target:
        raise PortalError(400, "unknown_target", "Unknown target: {0}".format(payload.target))
    if payload.caller == payload.target:
        raise PortalError(400, "invalid_target", "Caller and target must be different agents")
    caller_url = caller.url or await _resolve_external_invoke_url(container, payload.caller)
    return await container.agent_invoker.execute_a2a(caller_url, payload.target, get_request_id(request), container.settings.mgmt_api_key)


@router.get("/health")
async def get_health(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.health_service.sidecar_health(get_request_id(request))


@router.get("/policy")
async def get_policy(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.policy_service.get_policy(get_request_id(request))


@router.put("/policy")
async def put_policy(request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    body = await request.body()
    yaml_text = body.decode("utf-8", errors="replace")
    return await container.policy_service.put_policy(yaml_text, get_request_id(request))


@router.get("/audit")
async def get_audit(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.policy_service.get_audit(get_request_id(request))


@router.get("/audit/stream")
async def audit_stream(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.admin_client.open_stream("audit/stream", get_request_id(request))


@router.get("/mtls-policy")
async def get_mtls_policy(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.policy_service.get_mtls_policy(get_request_id(request))


@router.put("/mtls-policy")
async def put_mtls_policy(payload: MTLSPolicyUpdate, request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    return await container.policy_service.put_mtls_policy(payload.allowed_ids, get_request_id(request))


@router.get("/metrics")
async def get_metrics(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.policy_service.get_metrics(get_request_id(request))


@router.get("/oauth-status")
async def get_oauth_status(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.policy_service.get_oauth_status(get_request_id(request))


@router.get("/ca-sample")
async def get_ca_sample(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    agents = container.settings.agents
    policies = [
        {
            "displayName": "Require compliant device for Budget agents",
            "state": "enabledForReportingButNotEnforced",
            "conditions": {
                "applications": {"includeApplications": ["api://isp-budget-backend"]},
                "users": {"includeUsers": [agent.entra_agent_id or "N/A" for agent in agents.values()]},
            },
            "grantControls": {"operator": "OR", "builtInControls": ["compliantDevice"]},
        },
        {
            "displayName": "Block unmanaged agent identities",
            "state": "enabled",
            "conditions": {
                "applications": {"includeApplications": ["All"]},
                "users": {
                    "includeUsers": ["All"],
                    "excludeUsers": [agent.entra_agent_id or "N/A" for agent in agents.values()],
                },
                "clientAppTypes": ["servicePrincipal"],
            },
            "grantControls": {"operator": "OR", "builtInControls": ["block"]},
        },
    ]
    return {"source": "sample", "policies": policies}


@router.get("/ca-policies")
async def get_ca_policies(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    if not container.graph_client.configured:
        return {
            "source": "unavailable",
            "error": "Graph API credentials not configured",
            "policies": [],
        }
    policies = await container.graph_client.fetch_ca_policies()
    return {"source": "live", "policies": policies}


@router.get("/policy-configs")
async def get_policy_configs(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.policy_service.list_policy_configs()


@router.post("/policy-configs")
async def save_policy_config(payload: PolicyConfigCreate, request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    return await container.policy_service.save_policy_config(payload)


@router.delete("/policy-configs/{name}")
async def delete_policy_config(name: str, request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    return await container.policy_service.delete_policy_config(name)


@router.get("/preset-policies")
async def get_preset_policies(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    import yaml as _yaml
    hardened_yaml = container.policy_service.build_hardened_rbac_yaml()
    permissive_yaml = container.policy_service.build_permissive_rbac_yaml()
    return {
        "hardened": hardened_yaml,
        "permissive": permissive_yaml,
        "hardened_parsed": _yaml.safe_load(hardened_yaml),
        "permissive_parsed": _yaml.safe_load(permissive_yaml),
    }


@router.post("/scan")
async def run_scan(request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    return await container.scan_service.run_scan(get_request_id(request))


@router.post("/quick-fix")
async def apply_quick_fix(payload: QuickFixRequest, request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    request_id = get_request_id(request)
    if payload.fix_type.value == "mtls-remove":
        remove_id = payload.fix_payload.remove_id or ""
        if not remove_id:
            raise PortalError(400, "invalid_fix_payload", "Missing remove_id in fix_payload")
        if remove_id == container.policy_service.get_control_plane_spiffe_id():
            raise PortalError(
                400,
                "invalid_fix_payload",
                "Cannot remove admin-control-plane from mTLS allow list — management API access routes through its SPIFFE tunnel.",
            )
        current = await container.policy_service.get_mtls_policy(request_id)
        current_ids = current.get("allowed_ids", [])
        new_ids = [sid for sid in current_ids if sid != remove_id]
        if len(new_ids) == len(current_ids):
            return {"status": "no_change", "detail": "{0} was not in the allow list".format(remove_id)}
        result = await container.policy_service.put_mtls_policy(new_ids, request_id)
        return {"status": "applied", "fix_type": payload.fix_type.value, "removed": remove_id, "result": result}
    if payload.fix_type.value == "rbac-policy":
        fallback_yaml = payload.fix_payload.yaml or ""
        current_policy = await container.policy_service.get_policy(request_id)
        try:
            merged_policy = container.policy_service.harden_policy_additive(current_policy)
            yaml_body = yaml.safe_dump(merged_policy, sort_keys=False)
        except Exception:
            if not fallback_yaml:
                raise PortalError(502, "policy_merge_failed", "Could not build additive RBAC quick fix policy")
            yaml_body = fallback_yaml
        result = await container.policy_service.put_policy(yaml_body, request_id)
        return {"status": "applied", "fix_type": payload.fix_type.value, "result": result}
    raise PortalError(400, "invalid_fix_type", "Unknown fix_type: {0}".format(payload.fix_type.value))


@router.post("/reload-config")
async def reload_config(request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    if container.settings.runtime_environment != "local":
        raise PortalError(403, "forbidden", "Config reload is only available in local mode")
    await container.reload_local_settings()
    return {"status": "reloaded", "agents": list(container.settings.agents.keys())}


@router.get("/identity-mapping")
async def get_identity_mapping(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return container.policy_service.get_identity_mapping()


@router.get("/ca-status")
async def get_ca_status(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    return await container.ca_service.get_ca_status(get_request_id(request))


@router.put("/agent-risk")
async def update_agent_risk(payload: UpdateAgentRiskRequest, request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    return await container.ca_service.update_agent_risk(payload.spiffe_id, payload.risk_level.value, get_request_id(request))


@router.post("/flush-all-tokens")
async def flush_all_tokens(request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    return await container.ca_service.flush_all_tokens(get_request_id(request))


# ─── External (Cross-Cloud / Federated) Agent Endpoints ───


@router.get("/external-agents")
async def list_external_agents(request: Request, _user=Depends(viewer_or_admin)):
    """Return all external agent entries from the store."""
    container = get_container(request)
    agents = await container.external_agent_store.list_agents()
    return {"agents": agents}


@router.put("/external-agents/{name}")
async def put_external_agent(name: str, payload: ExternalAgentEntry, request: Request, _user=Depends(admin_only)):
    """Upsert an external agent entry.  URL ``name`` is the canonical key."""
    if not _AGENT_NAME_RE.match(name):
        raise PortalError(400, "invalid_agent_name", "Agent name must be lowercase alphanumeric with hyphens, 1-63 chars")
    container = get_container(request)
    if payload.name != name:
        raise PortalError(
            400,
            "name_mismatch",
            "Body name {0!r} does not match URL name {1!r}".format(payload.name, name),
        )
    config = payload.dict()
    await container.external_agent_store.put_agent(name, config)
    return {"status": "ok", "name": name}


@router.delete("/external-agents/{name}")
async def delete_external_agent(name: str, request: Request, _user=Depends(admin_only)):
    """Remove an external agent entry."""
    if not _AGENT_NAME_RE.match(name):
        raise PortalError(400, "invalid_agent_name", "Agent name must be lowercase alphanumeric with hyphens, 1-63 chars")
    container = get_container(request)
    await container.external_agent_store.delete_agent(name)
    return {"status": "ok", "name": name}


@router.post("/refresh-agents")
async def refresh_agents(request: Request, _user=Depends(admin_only)):
    """Re-run agent discovery from admin-CP and refresh container state.

    Cloud mode only.  In local mode, use /api/reload-config.
    """
    container = get_container(request)
    if container.settings.runtime_environment != "cloud":
        raise PortalError(403, "forbidden", "Agent refresh is only available in cloud mode; use /api/reload-config in local mode")
    refreshed = await type(container).create(container.settings.config_path, container.http_client)
    request.app.state.container = refreshed
    return {"status": "refreshed", "agents": list(refreshed.settings.agents.keys())}


@router.post("/sync-attributes")
async def sync_attributes(request: Request, _user=Depends(admin_only)):
    container = get_container(request)
    return await container.ca_service.sync_attributes(get_request_id(request))


@router.get("/enforcement-matrix")
async def get_enforcement_matrix(request: Request, _user=Depends(viewer_or_admin)):
    container = get_container(request)
    request_id = get_request_id(request)
    mtls_policy = await container.policy_service.get_mtls_policy(request_id)
    policy_doc = await container.policy_service.get_policy(request_id)
    ca_status = await container.ca_service.get_ca_status(request_id)
    return container.policy_service.build_enforcement_matrix(mtls_policy, policy_doc, ca_status)
