#!/usr/bin/env python3
"""
create-entra-agent-ids.py
=========================
Creates an Agent Identity Blueprint and per-agent Agent Identities in
Microsoft Entra ID via the Graph beta API. Stores the resulting IDs as
azd environment variables.

This provisions Entra Agent Identities for OAuth2 token acquisition
in the agent-to-agent authorization chain:

  Entra Agent ID (UUID) → SPIFFE ID → mTLS → RBAC

Usage:
    python3 scripts/create-entra-agent-ids.py

Prerequisites:
    - az login has been run (DefaultAzureCredential)
    - Agent ID Developer or Agent ID Administrator role in Entra ID
    - Microsoft Graph permissions: AgentIdentityBlueprint.ReadWrite.All,
      AgentIdentityBlueprintPrincipal.Create
"""
import os
import sys
import time

import requests
from entra_provisioning import (
    ProvisionerBootstrapError,
    build_required_permission_values,
    build_sponsors_bind,
    get_azd_env,
    get_graph_token as get_provisioner_graph_token,
    get_signed_in_user_id,
    load_azd_env,
    run_az,
    set_azd_env,
)
from entra_scope import (
    ScopeResolutionError,
    agent_identity_display_name,
    blueprint_display_name,
    fic_name as scoped_fic_name,
    resolve_scope,
)

GRAPH_BASE = "https://graph.microsoft.com/beta"


def odata_escape(value):
    """Escape single quotes for OData filter strings (doubles them per OData spec)."""
    return value.replace("'", "''")

# Dedicated app registration for Agent ID provisioning.
# Azure CLI tokens include Directory.AccessAsUser.All which Agent APIs reject.
# The script auto-creates an app registration via `az ad` CLI if needed.
# Override with env vars or azd env:
#   ENTRA_AGENTID_CLIENT_ID     — App registration client ID
#   ENTRA_AGENTID_CLIENT_SECRET — App registration client secret
#   AZURE_TENANT_ID             — Entra tenant ID (usually already set)
PROVISIONER_APP_DISPLAY_NAME = "Identity Research for Agent Management Using SPIFFE Agent ID Provisioner"

# Microsoft Graph API ID (constant across all tenants)
MS_GRAPH_API_ID = "00000003-0000-0000-c000-000000000000"
# Application.ReadWrite.All (Application permission) — required for Agent Identity APIs
APP_READWRITE_ALL_ID = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
# AppRoleAssignment.ReadWrite.All (Application permission) — required for assigning
# app roles (Budget.Read, Budget.Submit) to agent managed identity service principals
APP_ROLE_ASSIGNMENT_READWRITE_ALL_ID = "06b708a9-e830-4db3-a914-8e69da51d44f"

# Agent definitions
AGENTS = [
    {"name": "budget-report",   "env_key": "ENTRA_AGENT_ID_BUDGET_REPORT"},
    {"name": "budget-backend",  "env_key": "ENTRA_AGENT_ID_BUDGET_BACKEND"},
    {"name": "employee-menus",  "env_key": "ENTRA_AGENT_ID_EMPLOYEE_MENUS"},
    {"name": "budget-approval", "env_key": "ENTRA_AGENT_ID_BUDGET_APPROVAL"},
    {"name": "admin-control-plane", "env_key": "ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE"},
]

_SCOPE = None


def get_scope():
    """Resolve and cache the current azd environment's Entra naming scope."""
    global _SCOPE
    if _SCOPE is None:
        _SCOPE = resolve_scope(env_get=get_azd_env, env_set=set_azd_env)
    return _SCOPE


def print_scope_preflight():
    """Print the exact Entra object names this run will touch."""
    scope = get_scope()
    print("Entra scope:")
    print(f"  AIM_ENV_SCOPE_MODE: {scope.mode} ({scope.mode_source})")
    print(f"  AIM_ENV_SCOPE_KEY:  {scope.scope_key} ({scope.key_source})")
    print(f"  Blueprint:          {blueprint_display_name(scope)}")
    for agent_def in AGENTS:
        print(
            f"  Agent Identity [{agent_def['name']}]: "
            f"{agent_identity_display_name(agent_def['name'], scope)}"
        )
    for agent in CALLING_AGENTS:
        print(f"  FIC [{agent['name']}]: {scoped_fic_name(agent['name'], scope)}")
    print("")

def get_graph_token():
    """Get an access token for Microsoft Graph.

    Auto-creates a dedicated app registration via az CLI to avoid the
    Directory.AccessAsUser.All permission that Azure CLI tokens include,
    which Agent APIs explicitly reject.
    """
    try:
        print("  Using dedicated provisioner app registration for Agent ID provisioning")
        return get_provisioner_graph_token(build_required_permission_values(include_ca=True))
    except ProvisionerBootstrapError as exc:
        print(f"  ERROR: {exc}")
        sys.exit(1)


def graph_request(method, path, token, json_body=None, retry=True):
    """Make a request to the Microsoft Graph beta API."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    url = f"{GRAPH_BASE}{path}"
    resp = requests.request(method, url, headers=headers, json=json_body)

    # Retry once on 429 (throttling) or 5xx
    if retry and resp.status_code in (429, 500, 502, 503, 504):
        wait = int(resp.headers.get("Retry-After", "10"))
        print(f"  Graph API returned {resp.status_code}, retrying in {wait}s...")
        time.sleep(wait)
        resp = requests.request(method, url, headers=headers, json=json_body)

    return resp


def find_application_by_object_id(token, object_id):
    """Find an application by object ID."""
    if not object_id:
        return None
    resp = graph_request("GET", f"/applications/{object_id}", token, retry=False)
    if resp.status_code == 200:
        return resp.json()
    return None


def find_application_by_app_id(token, app_id):
    """Find an application by appId."""
    if not app_id:
        return None
    resp = graph_request(
        "GET",
        f"/applications?$filter=appId eq '{odata_escape(app_id)}'",
        token,
    )
    if resp.status_code != 200:
        return None

    data = resp.json()
    if data.get("value"):
        return data["value"][0]
    return None


def find_existing_blueprint(token):
    """Find an existing Agent Identity Blueprint for the current scope."""
    scope = get_scope()
    stored_obj_id = get_azd_env("ENTRA_BLUEPRINT_OBJECT_ID")
    if stored_obj_id:
        existing = find_application_by_object_id(token, stored_obj_id)
        if existing:
            return existing
        print(f"  [warn] Stored ENTRA_BLUEPRINT_OBJECT_ID not found: {stored_obj_id}")

    stored_app_id = get_azd_env("ENTRA_BLUEPRINT_APP_ID")
    if stored_app_id:
        existing = find_application_by_app_id(token, stored_app_id)
        if existing:
            return existing
        print(f"  [warn] Stored ENTRA_BLUEPRINT_APP_ID not found: {stored_app_id}")

    current_name = blueprint_display_name(scope)
    resp = graph_request(
        "GET",
        f"/applications?$filter=displayName eq '{odata_escape(current_name)}'",
        token,
    )
    if resp.status_code != 200:
        return None

    data = resp.json()
    for app in data.get("value", []):
        if app.get("displayName") == current_name:
            return app
    return None


def ensure_blueprint_principal(token, app_id):
    """Ensure the AgentIdentityBlueprintPrincipal (SP) exists for a blueprint.
    Agent Identities cannot be created without it."""
    # Check if SP already exists
    resp = graph_request(
        "GET",
        f"/servicePrincipals?$filter=appId eq '{app_id}'",
        token,
    )
    if resp.status_code == 200:
        sps = resp.json().get("value", [])
        if sps:
            print(f"  Blueprint SP already exists: {sps[0].get('id')}")
            return

    # Create it — retry with delay since the Blueprint app may not have propagated yet
    print("  Creating blueprint service principal...")
    sp_body = {
        "@odata.type": "Microsoft.Graph.AgentIdentityBlueprintPrincipal",
        "appId": app_id,
    }
    for attempt in range(4):
        sp_resp = graph_request("POST", "/servicePrincipals", token, json_body=sp_body)
        if sp_resp.status_code in (200, 201):
            sp_data = sp_resp.json()
            print(f"  Blueprint SP created: {sp_data.get('id', 'unknown')}")
            return
        if attempt < 3:
            wait = (attempt + 1) * 10
            print(f"  SP creation returned {sp_resp.status_code}, retrying in {wait}s (app may still be propagating)...")
            time.sleep(wait)
    print(f"  WARNING: Failed to create blueprint SP after retries: {sp_resp.status_code}")
    print(f"  Response: {sp_resp.text}")


def create_blueprint(token):
    """Create an Agent Identity Blueprint (application registration)."""
    scope = get_scope()
    blueprint_name = blueprint_display_name(scope)
    print("\n--- Creating Agent Identity Blueprint ---\n")

    # Check for existing blueprint first (idempotency)
    existing = find_existing_blueprint(token)
    if existing:
        app_id = existing["appId"]
        obj_id = existing["id"]
        print(f"  [skip] Blueprint already exists: {existing.get('displayName', blueprint_name)}")
        print(f"         App ID:    {app_id}")
        print(f"         Object ID: {obj_id}")
        set_azd_env("ENTRA_BLUEPRINT_APP_ID", app_id)
        set_azd_env("ENTRA_BLUEPRINT_OBJECT_ID", obj_id)
        # Ensure the BlueprintPrincipal (SP) exists — it may not if a previous
        # run created the blueprint but failed before creating the SP.
        ensure_blueprint_principal(token, app_id)
        return app_id, obj_id

    # Create the blueprint application
    body = {
        "@odata.type": "Microsoft.Graph.AgentIdentityBlueprint",
        "displayName": blueprint_name,
        "description": (
            "Agent Identity Blueprint for Identity Research for Agent Management Using SPIFFE Budget Backend PoC. "
            "Creates per-agent Entra identities for SPIFFE mTLS enforcement."
        ),
    }
    # Agent Identity Blueprints require at least one sponsor (user)
    sponsors_bind = build_sponsors_bind()
    if sponsors_bind:
        body["sponsors@odata.bind"] = sponsors_bind

    resp = graph_request("POST", "/applications", token, json_body=body)
    if resp.status_code not in (200, 201):
        # Check for the known Directory.AccessAsUser.All rejection
        resp_text = resp.text
        if "Directory.AccessAsUser.All" in resp_text:
            print(f"  ERROR: Agent APIs reject tokens with Directory.AccessAsUser.All")
            print(f"  This means the dedicated app registration token still has issues.")
            print(f"  Check that admin consent was granted for the app.")
            print(f"  Azure Portal → App registrations → {PROVISIONER_APP_DISPLAY_NAME}")
            print(f"  → API permissions → Grant admin consent for this tenant")
            sys.exit(1)
        print(f"  ERROR: Failed to create blueprint: {resp.status_code}")
        print(f"  Response: {resp_text}")
        sys.exit(1)

    data = resp.json()
    app_id = data["appId"]
    obj_id = data["id"]
    print(f"  [new] Blueprint created: {blueprint_name}")
    print(f"        App ID:    {app_id}")
    print(f"        Object ID: {obj_id}")

    set_azd_env("ENTRA_BLUEPRINT_APP_ID", app_id)
    set_azd_env("ENTRA_BLUEPRINT_OBJECT_ID", obj_id)

    # Create the service principal for the blueprint
    ensure_blueprint_principal(token, app_id)

    return app_id, obj_id


def find_service_principal_by_app_id(token, app_id):
    """Find a service principal by appId."""
    if not app_id:
        return None
    resp = graph_request(
        "GET",
        f"/servicePrincipals?$filter=appId eq '{odata_escape(app_id)}'",
        token,
    )
    if resp.status_code != 200:
        return None

    data = resp.json()
    if data.get("value"):
        return data["value"][0]
    return None


def find_existing_agent_identity(token, display_name, stored_app_id=None):
    """Find an existing Agent Identity by stored appId first, then display name."""
    existing = find_service_principal_by_app_id(token, stored_app_id)
    if existing:
        return existing

    resp = graph_request(
        "GET",
        f"/servicePrincipals?$filter=displayName eq '{odata_escape(display_name)}'",
        token,
    )
    if resp.status_code != 200:
        return None

    data = resp.json()
    for sp in data.get("value", []):
        if sp.get("displayName") == display_name:
            return sp
    return None


def create_agent_identities(token, blueprint_app_id):
    """Create an Agent Identity for each agent."""
    scope = get_scope()
    print("\n--- Creating Agent Identities ---\n")

    # Get the current user's object ID for sponsor assignment.
    # /me doesn't work with client_credentials — use az CLI instead.
    sponsor_id = get_signed_in_user_id()
    if sponsor_id:
        print(f"  Sponsor (current user): {sponsor_id}")
    else:
        print("  WARNING: Could not get current user for sponsorship")

    created = 0
    skipped = 0
    failed = 0

    for agent_def in AGENTS:
        name = agent_def["name"]
        env_key = agent_def["env_key"]
        display_name = agent_identity_display_name(name, scope)
        stored_app_id = get_azd_env(env_key)

        # Check for existing identity (idempotency)
        existing = find_existing_agent_identity(token, display_name, stored_app_id=stored_app_id)
        if existing:
            agent_id = existing.get("appId")
            if not agent_id:
                print(f"  [err]  {name}: existing Agent Identity is missing appId")
                failed += 1
                continue
            print(f"  [skip] {name}: already exists ({display_name}, appId={agent_id})")
            set_azd_env(env_key, agent_id)
            skipped += 1
            continue

        # Create the Agent Identity
        body = {
            "@odata.type": "Microsoft.Graph.AgentIdentity",
            "displayName": display_name,
            "agentIdentityBlueprintId": blueprint_app_id,
        }

        # Add sponsor if available
        if sponsor_id:
            body["sponsors@odata.bind"] = [
                f"https://graph.microsoft.com/beta/users/{sponsor_id}"
            ]

        for attempt in range(3):
            resp = graph_request(
                "POST",
                "/servicePrincipals",
                token,
                json_body=body,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                agent_id = data.get("appId")
                if not agent_id:
                    print(f"  [err]  {name}: Graph response did not include appId")
                    failed += 1
                    break
                print(f"  [new]  {name}: created ({display_name}, appId={agent_id})")
                set_azd_env(env_key, agent_id)
                print(f"         Stored {env_key}={agent_id}")
                created += 1
                break
            elif resp.status_code == 403:
                print(f"  [err]  {name}: permission denied — need Agent ID Developer role")
                print(f"         Response: {resp.text[:200]}")
                failed += 1
                break
            elif attempt < 2:
                wait = 10 * (attempt + 1)
                print(f"  [wait] {name}: {resp.status_code}, retrying in {wait}s...")
                time.sleep(wait)
            else:
                print(f"  [err]  {name}: failed after retries ({resp.status_code})")
                print(f"         Response: {resp.text[:200]}")
                failed += 1

    print(f"\n--- Done: {created} created, {skipped} skipped, {failed} failed ---")

    if failed > 0:
        print(f"\nWARNING: {failed} agent identity(ies) failed to create.")
        print("Entra Agent IDs are optional — SPIFFE mTLS enforcement works without them.")
        print("Fix errors above and re-run, or continue without Entra Agent IDs.")
        # Non-fatal: return 0 since Entra is optional metadata


# =============================================================================
# OAuth2 Token Flow Provisioning
# =============================================================================
# OAuth2 Token Flow Provisioning (Workload Identity Federation)
# =============================================================================
# Creates federated identity credentials on the Blueprint application,
# linking each agent's user-assigned managed identity to the Blueprint.
# This allows agents to use ManagedIdentityCredential → token exchange
# to acquire tokens that represent the Agent ID.
#
# Flow: Container App MI → token exchange → Entra Agent ID token
# BudgetBackend validates: issuer, audience (Blueprint appId), oid

# Agents that need FICs for token exchange (all callers — not budget-backend).
# EmployeeMenus needs a FIC too so it can acquire tokens; it gets blocked by
# tag mismatch (Layer 4b), not by token acquisition failure.
CALLING_AGENTS = [
    {"name": "budget-report",   "mi_name": "budget-report-identity"},
    {"name": "budget-approval", "mi_name": "budget-approval-identity"},
    {"name": "employee-menus",  "mi_name": "employee-menus-identity"},
]

CALLING_AGENT_MI_BY_NAME = {agent["name"]: agent["mi_name"] for agent in CALLING_AGENTS}


def get_managed_identity_principal_id(mi_name, resource_group):
    """Get the principal ID of a user-assigned managed identity."""
    rc, out, _ = run_az([
        "identity", "show",
        "--name", mi_name,
        "--resource-group", resource_group,
        "--query", "principalId",
        "-o", "tsv",
    ])
    if rc == 0 and out:
        return out
    return None


def get_managed_identity_client_id(mi_name, resource_group):
    """Get the client ID of a user-assigned managed identity."""
    rc, out, _ = run_az([
        "identity", "show",
        "--name", mi_name,
        "--resource-group", resource_group,
        "--query", "clientId",
        "-o", "tsv",
    ])
    if rc == 0 and out:
        return out
    return None


def create_federated_credentials(token):
    """Create federated identity credentials on the Blueprint.

    Links each calling agent's managed identity to the Blueprint app via
    workload identity federation. This allows agents to use their MI to
    acquire tokens scoped to the Blueprint (Agent ID audience).
    """
    print("\n--- Creating Federated Identity Credentials (OAuth2) ---\n")
    scope = get_scope()

    tenant_id = os.environ.get("AZURE_TENANT_ID") or get_azd_env("AZURE_TENANT_ID")
    resource_group = os.environ.get("AZURE_RESOURCE_GROUP") or get_azd_env("AZURE_RESOURCE_GROUP")
    blueprint_app_id = get_azd_env("ENTRA_BLUEPRINT_APP_ID")
    blueprint_obj_id = get_azd_env("ENTRA_BLUEPRINT_OBJECT_ID")

    if not blueprint_obj_id:
        print("  [err] No Blueprint object ID found")
        return
    if not tenant_id:
        print("  [err] No tenant ID found")
        return
    if not resource_group:
        print("  [err] No resource group found")
        return

    # Ensure the Blueprint has an Application ID URI (api://{appId}).
    # This is required for token scoping — callers request tokens for
    # "api://{blueprint-app-id}/.default" and this URI must be registered.
    print(f"  Setting Application ID URI on Blueprint...")
    uri_body = {
        "identifierUris": [f"api://{blueprint_app_id}"],
    }
    uri_resp = graph_request(
        "PATCH",
        f"/applications/{blueprint_obj_id}/microsoft.graph.agentIdentityBlueprint",
        token,
        json_body=uri_body,
    )
    if uri_resp.status_code in (200, 204):
        print(f"  Application ID URI: api://{blueprint_app_id}")
    elif "already" in uri_resp.text.lower() or uri_resp.status_code == 400:
        # May already be set, or the agentIdentityBlueprint path may not support PATCH
        # Try the regular applications path
        uri_resp2 = graph_request("PATCH", f"/applications/{blueprint_obj_id}", token, json_body=uri_body)
        if uri_resp2.status_code in (200, 204):
            print(f"  Application ID URI: api://{blueprint_app_id}")
        else:
            print(f"  [warn] Could not set ID URI: {uri_resp2.status_code} {uri_resp2.text[:200]}")
    else:
        print(f"  [warn] Could not set ID URI: {uri_resp.status_code} {uri_resp.text[:200]}")

    issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"

    # Fetch all existing FICs on the Blueprint so we can detect stale subjects.
    existing_fics_resp = graph_request(
        "GET",
        f"/applications/{blueprint_obj_id}/federatedIdentityCredentials",
        token,
    )
    existing_fics = {}  # name -> {id, subject}
    if existing_fics_resp.status_code == 200:
        for fic in existing_fics_resp.json().get("value", []):
            existing_fics[fic["name"]] = {
                "id": fic["id"],
                "subject": fic.get("subject", ""),
            }

    for agent in CALLING_AGENTS:
        name = agent["name"]
        mi_name = agent["mi_name"]
        env_upper = name.upper().replace("-", "_")
        fic_key = f"ENTRA_FIC_CREATED_{env_upper}"

        # Always refresh the current MI client ID from Azure. After azd down/up,
        # the user-assigned identity may be recreated with a new client ID even if
        # stale azd env markers still say the FIC was previously created.
        client_id = get_managed_identity_client_id(mi_name, resource_group)
        if client_id:
            set_azd_env(f"MI_CLIENT_ID_{env_upper}", client_id)

        # Get the MI's principal ID (used as the 'subject' in the FIC)
        principal_id = get_managed_identity_principal_id(mi_name, resource_group)
        if not principal_id:
            print(f"  [err]  {name}: could not find MI '{mi_name}' principal ID")
            continue

        # Get the MI's client ID (used by the caller to specify which MI to use)
        client_id = client_id or get_managed_identity_client_id(mi_name, resource_group)
        if not client_id:
            print(f"  [err]  {name}: could not find MI '{mi_name}' client ID")
            continue

        current_fic_name = scoped_fic_name(name, scope)

        # Check if an existing FIC has a stale subject (MI was recreated after
        # infra teardown). If so, delete it so we can recreate with the correct
        # principal ID. Without this, token exchange fails with AADSTS700213.
        if current_fic_name in existing_fics:
            existing = existing_fics[current_fic_name]
            if existing["subject"] == principal_id:
                print(
                    f"  [skip] {name}: federated credential up-to-date "
                    f"({current_fic_name}, subject={principal_id[:8]}...)"
                )
                set_azd_env(fic_key, "true")
                set_azd_env(f"MI_CLIENT_ID_{env_upper}", client_id)
                continue
            else:
                print(
                    f"  [fix]  {name}: {current_fic_name} subject stale "
                    f"({existing['subject'][:8]}... → {principal_id[:8]}...), deleting..."
                )
                del_resp = graph_request(
                    "DELETE",
                    f"/applications/{blueprint_obj_id}/federatedIdentityCredentials/{existing['id']}",
                    token,
                )
                if del_resp.status_code not in (204, 404):
                    print(f"         [warn] Delete returned {del_resp.status_code}, retrying in 5s...")
                    time.sleep(5)
                    graph_request(
                        "DELETE",
                        f"/applications/{blueprint_obj_id}/federatedIdentityCredentials/{existing['id']}",
                        token,
                    )
                time.sleep(2)  # Brief pause for Graph propagation
                # Clear the env marker so we proceed to create below
                set_azd_env(fic_key, "")

        # Create federated identity credential on the Blueprint application
        fic_body = {
            "name": current_fic_name,
            "issuer": issuer,
            "subject": principal_id,
            "audiences": ["api://AzureADTokenExchange"],
        }

        resp = graph_request(
            "POST",
            f"/applications/{blueprint_obj_id}/microsoft.graph.agentIdentityBlueprint/federatedIdentityCredentials",
            token,
            json_body=fic_body,
        )
        if resp.status_code in (200, 201):
            print(f"  [new]  {name}: federated credential created ({current_fic_name})")
            print(f"         MI: {mi_name} (principal: {principal_id})")
            set_azd_env(fic_key, "true")
            set_azd_env(f"MI_CLIENT_ID_{env_upper}", client_id)
            # Graph needs propagation time between consecutive FIC writes on the
            # same application object. Without this, the next creation can fail.
            time.sleep(5)
        elif (resp.status_code == 409
              or "already exists" in resp.text.lower()
              or "duplicate" in resp.text.lower()):
            print(f"  [skip] {name}: federated credential already exists")
            set_azd_env(fic_key, "true")
            set_azd_env(f"MI_CLIENT_ID_{env_upper}", client_id)
        else:
            print(f"  [err]  {name}: failed to create FIC: {resp.status_code}")
            print(f"         {resp.text[:300]}")

    # Store tenant ID and Blueprint app ID for token acquisition/validation
    if tenant_id:
        set_azd_env("AZURE_TENANT_ID", tenant_id)
    if blueprint_app_id:
        set_azd_env("ENTRA_OAUTH2_AUDIENCE", blueprint_app_id)
        print(f"\n  OAuth2 audience (Blueprint): {blueprint_app_id}")


# App roles to create on the Blueprint for OAuth2 token-based authorization.
# These appear in the JWT `roles` claim when assigned to a service principal.
APP_ROLES = [
    {
        "displayName": "Budget Read",
        "description": "Allows reading budget data",
        "value": "Budget.Read",
        "id": "b1e2c3d4-0001-4000-8000-000000000001",
        "isEnabled": True,
        "allowedMemberTypes": ["Application"],
    },
    {
        "displayName": "Budget Submit",
        "description": "Allows submitting budget entries",
        "value": "Budget.Submit",
        "id": "b1e2c3d4-0002-4000-8000-000000000002",
        "isEnabled": True,
        "allowedMemberTypes": ["Application"],
    },
]

# Which roles each agent's managed identity should be assigned.
# The MI service principal gets the app role assignment, which causes the
# `roles` claim to appear in tokens acquired by that MI.
AGENT_ROLE_ASSIGNMENTS = {
    "budget-report":   ["Budget.Read"],
    "budget-approval": ["Budget.Read", "Budget.Submit"],
    # employee-menus: no roles (blocked at mTLS anyway)
    # budget-backend: no roles (it's the resource, not a caller)
}


def provision_app_roles(token):
    """Create app roles on the Blueprint and assign them to Agent Identity SPs.

    App roles are the mechanism by which Entra JWT tokens carry authorization claims.
    Roles are assigned to the Agent Identity service principals (not Managed Identity
    SPs) because the two-hop token exchange produces tokens where oid = Agent Identity.
    The T2 token's `roles` array includes roles assigned to the Agent Identity SP.

    This is Layer 3 of the enforcement stack — the SPIFFE proxy validates these
    roles against `required_roles` in the RBAC policy.
    """
    print("\n--- Creating App Roles (OAuth2 Layer 3) ---\n")

    blueprint_app_id = get_azd_env("ENTRA_BLUEPRINT_APP_ID")
    blueprint_obj_id = get_azd_env("ENTRA_BLUEPRINT_OBJECT_ID")
    resource_group = os.environ.get("AZURE_RESOURCE_GROUP") or get_azd_env("AZURE_RESOURCE_GROUP")

    if not blueprint_obj_id:
        print("  [err] No Blueprint object ID found — cannot create app roles")
        return

    # Step 1: Create app roles on the Blueprint application.
    # PATCH /applications/{id} with appRoles array.
    # This is idempotent — if roles already exist with the same IDs, they're updated.
    print("  Setting Application ID URI on Blueprint...")
    resp = graph_request("GET", f"/applications/{blueprint_obj_id}", token)
    if resp.status_code != 200:
        print(f"  [err] Failed to read Blueprint app: {resp.status_code}")
        return

    existing_app = resp.json()
    existing_roles = existing_app.get("appRoles", [])
    existing_role_values = {r.get("value") for r in existing_roles}

    # Check if our roles already exist
    roles_to_add = [r for r in APP_ROLES if r["value"] not in existing_role_values]
    if not roles_to_add:
        print(f"  [skip] App roles already exist: {', '.join(existing_role_values & {'Budget.Read', 'Budget.Submit'})}")
    else:
        # Merge with any existing roles (don't overwrite)
        merged_roles = existing_roles + roles_to_add
        role_resp = graph_request(
            "PATCH",
            f"/applications/{blueprint_obj_id}",
            token,
            json_body={"appRoles": merged_roles},
        )
        if role_resp.status_code in (200, 204):
            print(f"  [new] App roles created: {', '.join(r['value'] for r in roles_to_add)}")
        else:
            print(f"  [err] Failed to create app roles: {role_resp.status_code}")
            print(f"        {role_resp.text[:300]}")
            return

    # Build a lookup of role value → role ID
    role_id_map = {}
    for r in APP_ROLES:
        role_id_map[r["value"]] = r["id"]

    # Wait for app role propagation before attempting assignments.
    # The PATCH above updates the application object, but the service principal's
    # appRoles list takes time to sync. Without this delay, role assignments fail
    # with "Permission being assigned was not found on application".
    if roles_to_add:
        print("  Waiting 15s for app role propagation...")
        time.sleep(15)

    # Step 2: Find the Blueprint service principal ID (resource SP for role assignments).
    bp_sp_resp = graph_request(
        "GET",
        f"/servicePrincipals?$filter=appId eq '{blueprint_app_id}'",
        token,
    )
    if bp_sp_resp.status_code != 200 or not bp_sp_resp.json().get("value"):
        print("  [err] Blueprint service principal not found — cannot assign roles")
        return
    blueprint_sp_id = bp_sp_resp.json()["value"][0]["id"]
    print(f"  Blueprint SP: {blueprint_sp_id}")

    # Step 3: Assign roles to Agent Identity service principals.
    # The two-hop token exchange (MI → Blueprint T1 → Agent Identity T2) produces
    # a T2 token where oid = Agent Identity SP. The `roles` claim in T2 comes from
    # roles assigned to the Agent Identity SP, NOT the MI SP.
    # POST /servicePrincipals/{blueprint_sp_id}/appRoleAssignments
    for agent_name, role_values in AGENT_ROLE_ASSIGNMENTS.items():
        env_upper = agent_name.upper().replace("-", "_")

        # Look up the Agent Identity's appId from azd env
        agent_identity_app_id = get_azd_env(f"ENTRA_AGENT_ID_{env_upper}")
        if not agent_identity_app_id:
            print(f"  [skip] {agent_name}: no ENTRA_AGENT_ID_{env_upper} (Agent Identity not created yet?)")
            continue

        # Also refresh MI client ID while we're here (needed for FIC and env plumbing)
        if resource_group:
            mi_name = CALLING_AGENT_MI_BY_NAME.get(agent_name, f"{agent_name}-identity")
            mi_client_id = get_managed_identity_client_id(mi_name, resource_group)
            if mi_client_id:
                set_azd_env(f"MI_CLIENT_ID_{env_upper}", mi_client_id)

        # Find the Agent Identity's service principal ID by its appId
        agent_sp_id = None
        for attempt in range(5):
            sp_resp = graph_request(
                "GET",
                f"/servicePrincipals?$filter=appId eq '{odata_escape(agent_identity_app_id)}'",
                token,
            )
            if sp_resp.status_code == 200 and sp_resp.json().get("value"):
                agent_sp_id = sp_resp.json()["value"][0]["id"]
                break
            if attempt < 4:
                print(f"  [wait] {agent_name}: Agent Identity SP not visible yet for {agent_identity_app_id}, retrying in 10s...")
                time.sleep(10)
        if not agent_sp_id:
            print(f"  [skip] {agent_name}: Agent Identity SP not found for appId {agent_identity_app_id}")
            continue

        # Check existing role assignments to avoid duplicates
        existing_assignments_resp = graph_request(
            "GET",
            f"/servicePrincipals/{agent_sp_id}/appRoleAssignments",
            token,
        )
        existing_assigned_roles = set()
        if existing_assignments_resp.status_code == 200:
            for assignment in existing_assignments_resp.json().get("value", []):
                existing_assigned_roles.add(assignment.get("appRoleId"))

        for role_value in role_values:
            role_id = role_id_map.get(role_value)
            if not role_id:
                print(f"  [err] {agent_name}: unknown role {role_value}")
                continue

            if role_id in existing_assigned_roles:
                print(f"  [skip] {agent_name}: {role_value} already assigned (Agent Identity SP)")
                continue

            assignment_body = {
                "principalId": agent_sp_id,
                "resourceId": blueprint_sp_id,
                "appRoleId": role_id,
            }
            # Retry up to 3 times with 10s waits — app role propagation to the
            # Blueprint SP can lag behind the application PATCH, causing 400
            # "Permission being assigned was not found on application".
            assigned = False
            for attempt in range(3):
                assign_resp = graph_request(
                    "POST",
                    f"/servicePrincipals/{blueprint_sp_id}/appRoleAssignments",
                    token,
                    json_body=assignment_body,
                )
                if assign_resp.status_code in (200, 201):
                    print(f"  [new] {agent_name}: {role_value} assigned to Agent Identity SP")
                    assigned = True
                    break
                elif assign_resp.status_code == 409 or "already exists" in assign_resp.text.lower():
                    print(f"  [skip] {agent_name}: {role_value} already assigned (Agent Identity SP)")
                    assigned = True
                    break
                elif assign_resp.status_code == 400 and attempt < 2:
                    print(f"  [wait] {agent_name}: {role_value} assignment returned 400, retrying in 10s (attempt {attempt + 1}/3)...")
                    time.sleep(10)
                else:
                    print(f"  [err] {agent_name}: failed to assign {role_value}: {assign_resp.status_code}")
                    print(f"        {assign_resp.text[:300]}")
                    break

    set_azd_env("ENTRA_OAUTH2_APP_ROLES_READY", "true")
    print("\n  App roles provisioned and assigned.")
    print("  Note: roles may take up to 60s to appear in newly acquired tokens.")


def main():
    load_azd_env()

    print("\n=== Entra Agent ID Provisioning ===")
    print("Creates Agent Identity Blueprint + per-agent identities via Graph beta API")
    print("")

    try:
        print_scope_preflight()
    except ScopeResolutionError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)

    # Get Graph API token
    print("Acquiring Graph API token...")
    try:
        token = get_graph_token()
        print("  Token acquired successfully")
    except Exception as e:
        print(f"ERROR: Failed to acquire Graph token: {e}")
        print("Ensure 'az login' has been run and you have Graph API permissions.")
        print("\nEntra Agent IDs are optional — skipping.")
        sys.exit(0)  # Non-fatal exit

    # Step 1: Create or find the blueprint
    blueprint_app_id, _ = create_blueprint(token)

    # Step 2: Create agent identities
    create_agent_identities(token, blueprint_app_id)

    # Step 3: Create federated identity credentials for OAuth2 token flow
    create_federated_credentials(token)

    # Step 4: Create app roles and assign to agent managed identities
    provision_app_roles(token)

    # Summary
    print("\nEntra Agent ID mapping:")
    for agent_def in AGENTS:
        entra_id = get_azd_env(agent_def["env_key"]) or "not-set"
        print(f"  {agent_def['name']:20s}  Entra: {entra_id}")


if __name__ == "__main__":
    main()
