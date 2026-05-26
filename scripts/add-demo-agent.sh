#!/bin/bash
# =============================================================================
# AIM Prototype Platform — Add a Demo Agent (Dynamic Onboarding)
# =============================================================================
# Deploys a new caller agent into the existing Azure environment, attests it
# with SPIRE, and updates the portal config. Re-runnable — each invocation
# picks the next available name from the curated list.
#
# Usage:
#   ./scripts/add-demo-agent.sh                  # auto-pick next name
#   ./scripts/add-demo-agent.sh --name my-agent  # specific name
#
# The agent starts blocked (not in mTLS allow list, no RBAC rules).
# Use the portal to gradually grant access.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=scripts/lib/deploy-config.sh
source "${SCRIPT_DIR}/lib/deploy-config.sh"
# shellcheck source=scripts/lib/azure-helpers.sh
source "${SCRIPT_DIR}/lib/azure-helpers.sh"
# shellcheck source=scripts/lib/entra-scope.sh
source "${SCRIPT_DIR}/lib/entra-scope.sh"

VM_RUN_COUNTER=0
VM_RUN_EPOCH=$(date +%s)

AGENT_IMAGE="demo-agent:v1"
PORTAL_PORT=8550
PYTHON=python3

# Curated name pool — script cycles through these
DEMO_NAMES=("audit-reviewer" "tax-reporter" "payroll-service" "expense-tracker" "compliance-bot")

AGENT_NAME=""
for arg in "$@"; do
    case $arg in
        --name) shift; AGENT_NAME="${1:-}"; shift || true ;;
        --name=*) AGENT_NAME="${arg#*=}" ;;
    esac
done

echo ""
echo "============================================="
echo "  AIM Prototype Platform — Add Demo Agent"
echo "============================================="
echo ""

# ─── Step 1: Discover Azure environment ──────────────────────────────────

echo "📍 Discovering Azure environment..."

# Read azd env — same variable names as deploy.sh
AZD_ENV=$(azd_env_load)
RG=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_RESOURCE_GROUP")
ACR_SERVER=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_CONTAINER_REGISTRY_ENDPOINT")
ACR_NAME=$(echo "$ACR_SERVER" | cut -d'.' -f1 || true)
SPIRE_SERVER_FQDN=$(azd_env_get_from_blob "$AZD_ENV" "SPIRE_SERVER_FQDN")

if [ -z "$RG" ]; then
    RG=$(az group list --query "[?starts_with(name,'aim-') || starts_with(name,'rg-aim')].name" -o tsv 2>/dev/null | head -1 || true)
fi
if [ -z "$ACR_NAME" ]; then
    ACR_NAME=$(az acr list --resource-group "$RG" --query "[0].name" -o tsv 2>/dev/null | head -1 || true)
    ACR_SERVER="${ACR_NAME}.azurecr.io"
fi

SPIFFE_IMAGE="${ACR_SERVER}/spiffe-proxy:${IMAGE_TAG}"

# Read Entra Agent Identity OIDs from azd env (for correct SPIFFE ID construction)
ENTRA_BP_OID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_OBJECT_ID")
ENTRA_AGENT_OID_BUDGET_BACKEND=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_AGENT_ID_BUDGET_BACKEND")

# Get Container Apps Environment ID from an existing app
ENV_ID=$(az containerapp show --name budget-report --resource-group "$RG" \
    --query "properties.managedEnvironmentId" -o tsv 2>/dev/null || true)

# Get SPIRE Server VM IP (fallback if not in azd env)
if [ -z "$SPIRE_SERVER_FQDN" ]; then
    SPIRE_SERVER_FQDN=$(az vm list-ip-addresses --resource-group "$RG" \
        --query "[0].virtualMachine.network.publicIpAddresses[0].ipAddress" -o tsv 2>/dev/null || true)
fi

# Get user-assigned identity from budget-report (reuse for ACR pull)
IDENTITY_ID=$(az containerapp show --name budget-report --resource-group "$RG" \
    --query "identity.userAssignedIdentities | keys(@) | [0]" -o tsv 2>/dev/null || true)

echo "  Resource Group:  ${RG}"
echo "  ACR:             ${ACR_SERVER}"
echo "  Environment:     ${ENV_ID##*/}"
echo "  SPIRE Server:    ${SPIRE_SERVER_FQDN}"
echo ""

# ─── Step 2: Pick agent name ─────────────────────────────────────────────

if [ -z "$AGENT_NAME" ]; then
    echo "🔍 Finding next available agent name..."
    for candidate in "${DEMO_NAMES[@]}"; do
        EXISTS=$(az containerapp show --name "$candidate" --resource-group "$RG" \
            --query "name" -o tsv 2>/dev/null || true)
        if [ -z "$EXISTS" ]; then
            AGENT_NAME="$candidate"
            break
        fi
        echo "   ${candidate} — already exists, skipping"
    done
fi

if [ -z "$AGENT_NAME" ]; then
    echo "❌ All demo names are taken. Use --name <custom-name> to specify one."
    exit 1
fi

# Generate display name: audit-reviewer → AuditReviewer
DISPLAY_NAME=$(echo "$AGENT_NAME" | sed 's/-/ /g' | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) substr($i,2)}1' | tr -d ' ')

echo "  Agent Name:      ${AGENT_NAME}"
echo "  Display Name:    ${DISPLAY_NAME}"
if ! validate_entra_scope; then
    exit 1
fi
echo "  Scope Mode:      $(resolve_scope_mode)"
echo "  Scope Key:       $(resolve_scope_key)"
echo "  Agent Identity:  $(agent_identity_display_name "${AGENT_NAME}")"
echo "  Federated Cred:  $(fic_name "${AGENT_NAME}")"
echo ""

# ─── Step 2.5: Provision Entra Agent Identity + FIC ───────────────────
#
# Creates an Agent Identity SP under the Blueprint and a Federated Identity
# Credential linking the demo agent's Managed Identity to the Blueprint.
# This enables the two-hop token exchange: MI → Blueprint (T1) → Agent ID (T2).

echo "🆔 Provisioning Entra Agent Identity for ${AGENT_NAME}..."

# Create a dedicated user-assigned MI for this demo agent (needed for unique FIC subject)
MI_NAME="${AGENT_NAME}-identity"
MI_EXISTS=$(az identity show --name "$MI_NAME" --resource-group "$RG" --query "name" -o tsv 2>/dev/null || true)
if [ -z "$MI_EXISTS" ]; then
    echo "   Creating managed identity: ${MI_NAME}..."
    az identity create --name "$MI_NAME" --resource-group "$RG" -o none 2>&1
    echo "   Waiting 15s for MI propagation..."
    sleep 15
else
    echo "   ✓ Managed identity ${MI_NAME} already exists"
fi

DEMO_MI_RESOURCE_ID=$(az identity show --name "$MI_NAME" --resource-group "$RG" --query "id" -o tsv 2>/dev/null || true)
DEMO_MI_CLIENT_ID=$(az identity show --name "$MI_NAME" --resource-group "$RG" --query "clientId" -o tsv 2>/dev/null || true)
DEMO_MI_PRINCIPAL_ID=$(az identity show --name "$MI_NAME" --resource-group "$RG" --query "principalId" -o tsv 2>/dev/null || true)

# Grant AcrPull to the new MI so it can pull container images
ACR_ID=$(az acr show --name "$ACR_NAME" --query "id" -o tsv 2>/dev/null || true)
az role assignment create --assignee-object-id "$DEMO_MI_PRINCIPAL_ID" \
    --assignee-principal-type ServicePrincipal \
    --role AcrPull --scope "$ACR_ID" -o none 2>/dev/null || true

# Use the provisioner app to create Agent Identity + FIC via Graph API
export REPO_ROOT AGENT_NAME DEMO_MI_PRINCIPAL_ID DEMO_MI_CLIENT_ID
ENTRA_AGENT_OID=$($PYTHON << 'PROVISION_AGENT_ID'
import os
import sys
import time

sys.path.insert(0, os.path.join(os.environ["REPO_ROOT"], "scripts"))

from entra_provisioning import (
    build_required_permission_values, get_azd_env, set_azd_env,
    get_graph_token as get_provisioner_graph_token, get_signed_in_user_id,
)
from entra_scope import agent_identity_display_name, fic_name, resolve_scope
import requests

GRAPH_BASE = "https://graph.microsoft.com/beta"
agent_name = os.environ["AGENT_NAME"]
mi_principal_id = os.environ["DEMO_MI_PRINCIPAL_ID"]
mi_client_id = os.environ["DEMO_MI_CLIENT_ID"]
scope = resolve_scope(env_get=get_azd_env, env_set=set_azd_env)

def graph_request(method, path, token, json_body=None):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    return requests.request(method, f"{GRAPH_BASE}{path}", headers=headers, json=json_body)

# Get provisioner token
token = get_provisioner_graph_token(build_required_permission_values(include_ca=True))

blueprint_app_id = get_azd_env("ENTRA_BLUEPRINT_APP_ID")
blueprint_obj_id = get_azd_env("ENTRA_BLUEPRINT_OBJECT_ID")
tenant_id = get_azd_env("AZURE_TENANT_ID")
display_name = agent_identity_display_name(agent_name, scope)
stored_app_id = get_azd_env(f"ENTRA_AGENT_ID_{agent_name.upper().replace('-', '_')}")

if not blueprint_app_id:
    print("ERROR: No Blueprint app ID found", file=sys.stderr)
    sys.exit(1)

# --- Create Agent Identity SP ---
existing = None
if stored_app_id:
    resp = graph_request("GET", f"/servicePrincipals?$filter=appId eq '{stored_app_id}'", token)
    if resp.status_code == 200 and resp.json().get("value"):
        existing = resp.json()["value"][0]
if existing is None:
    resp = graph_request("GET", f"/servicePrincipals?$filter=displayName eq '{display_name}'", token)
    if resp.status_code == 200:
        for sp in resp.json().get("value", []):
            if sp.get("displayName") == display_name:
                existing = sp
                break

if existing:
    agent_id = existing.get("appId")
    if not agent_id:
        print(f"  ERROR: Existing Agent Identity is missing appId ({display_name})", file=sys.stderr)
        sys.exit(1)
    print(f"  [skip] {agent_name}: Agent Identity already exists ({display_name}, appId={agent_id})", file=sys.stderr)
else:
    sponsor_id = get_signed_in_user_id()
    body = {
        "@odata.type": "Microsoft.Graph.AgentIdentity",
        "displayName": display_name,
        "agentIdentityBlueprintId": blueprint_app_id,
    }
    if sponsor_id:
        body["sponsors@odata.bind"] = [f"https://graph.microsoft.com/beta/users/{sponsor_id}"]

    for attempt in range(3):
        resp = graph_request("POST", "/servicePrincipals", token, json_body=body)
        if resp.status_code in (200, 201):
            agent_id = resp.json().get("appId")
            if not agent_id:
                print(f"  ERROR: Graph response missing appId for {display_name}", file=sys.stderr)
                sys.exit(1)
            print(f"  [new] {agent_name}: Agent Identity created ({display_name}, appId={agent_id})", file=sys.stderr)
            break
        elif attempt < 2:
            time.sleep(10 * (attempt + 1))
        else:
            print(f"  ERROR: Failed to create Agent Identity: {resp.status_code} {resp.text[:300]}", file=sys.stderr)
            sys.exit(1)

set_azd_env(f"ENTRA_AGENT_ID_{agent_name.upper().replace('-', '_')}", agent_id)

# --- Create or update FIC ---
issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
fic_display_name = fic_name(agent_name, scope)

# Check existing FICs
fics_resp = graph_request("GET", f"/applications/{blueprint_obj_id}/federatedIdentityCredentials", token)
existing_fic = None
if fics_resp.status_code == 200:
    for fic in fics_resp.json().get("value", []):
        if fic["name"] == fic_display_name:
            existing_fic = fic
            break

if existing_fic and existing_fic.get("subject") == mi_principal_id:
    print(f"  [skip] {agent_name}: {fic_display_name} up-to-date (subject={mi_principal_id[:8]}...)", file=sys.stderr)
elif existing_fic:
    # Stale — delete and recreate
    print(f"  [fix] {agent_name}: {fic_display_name} subject stale, recreating...", file=sys.stderr)
    graph_request("DELETE", f"/applications/{blueprint_obj_id}/federatedIdentityCredentials/{existing_fic['id']}", token)
    time.sleep(3)
    existing_fic = None

if not existing_fic or existing_fic.get("subject") != mi_principal_id:
    fic_body = {
        "name": fic_display_name,
        "issuer": issuer,
        "subject": mi_principal_id,
        "audiences": ["api://AzureADTokenExchange"],
    }
    fic_resp = graph_request(
        "POST",
        f"/applications/{blueprint_obj_id}/microsoft.graph.agentIdentityBlueprint/federatedIdentityCredentials",
        token, json_body=fic_body,
    )
    if fic_resp.status_code in (200, 201):
        print(f"  [new] {agent_name}: {fic_display_name} created (MI principal: {mi_principal_id[:8]}...)", file=sys.stderr)
    elif "already exists" in fic_resp.text.lower() or "duplicate" in fic_resp.text.lower():
        print(f"  [skip] {agent_name}: {fic_display_name} already exists", file=sys.stderr)
    else:
        print(f"  ERROR: FIC creation failed: {fic_resp.status_code} {fic_resp.text[:300]}", file=sys.stderr)
        sys.exit(1)

set_azd_env(f"MI_CLIENT_ID_{agent_name.upper().replace('-', '_')}", mi_client_id)

# Output the agent ID on stdout for the bash script to capture
print(agent_id)
PROVISION_AGENT_ID
)

if [ -z "$ENTRA_AGENT_OID" ]; then
    echo "   ❌ Failed to provision Entra Agent Identity"
    exit 1
fi

echo "   ✓ Entra Agent ID: ${ENTRA_AGENT_OID}"
echo "   SPIFFE ID: spiffe://${TRUST_DOMAIN}/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID}"
echo ""

# ─── Step 3: Build agent image (if needed) ───────────────────────────────

echo "🔨 Checking if demo-agent image exists in ACR..."
IMG_EXISTS=$(az acr repository show-tags --name "$ACR_NAME" --repository demo-agent \
    --query "[?@=='v1']" -o tsv 2>/dev/null || true)

if [ -z "$IMG_EXISTS" ]; then
    echo "   Building demo-agent:v1 in ACR..."
    az acr build --registry "$ACR_NAME" --image "$AGENT_IMAGE" \
        "${REPO_ROOT}/src/demo-agent/" 2>&1 | tail -5
    echo "   ✓ Image built"
else
    echo "   ✓ Image already exists, skipping build"
fi
echo ""

# ─── Step 4: Create Container App ────────────────────────────────────────

echo "🚀 Creating Container App: ${AGENT_NAME}..."

# Read A2A-related env vars from azd env for the demo agent
MGMT_API_KEY=$(azd_env_get_from_blob "$AZD_ENV" "MGMT_API_KEY")
AZURE_TENANT_ID=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_TENANT_ID")
ENTRA_OAUTH2_AUDIENCE=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_OAUTH2_AUDIENCE")

# Discover existing agent FQDNs for A2A target URLs
A2A_REPORT_URL=$(az containerapp show --name budget-report --resource-group "$RG" \
    --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)
A2A_APPROVAL_URL=$(az containerapp show --name budget-approval --resource-group "$RG" \
    --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)
A2A_MENUS_URL=$(az containerapp show --name employee-menus --resource-group "$RG" \
    --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)
ADMIN_CP_URL=$(az containerapp show --name admin-control-plane --resource-group "$RG" \
    --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)

az containerapp create \
    --name "$AGENT_NAME" \
    --resource-group "$RG" \
    --environment "$ENV_ID" \
    --image "${ACR_SERVER}/${AGENT_IMAGE}" \
    --target-port 8000 \
    --ingress external \
    --min-replicas 1 \
    --max-replicas 1 \
    --cpu 0.25 \
    --memory 0.5Gi \
    --env-vars \
        "AGENT_NAME=${AGENT_NAME}" \
        "BACKEND_ENDPOINT=http://localhost:8080" \
        "MGMT_API_KEY=${MGMT_API_KEY}" \
        "AZURE_TENANT_ID=${AZURE_TENANT_ID}" \
        "ENTRA_OAUTH2_AUDIENCE=${ENTRA_OAUTH2_AUDIENCE}" \
        "ENTRA_AGENT_ID=${ENTRA_AGENT_OID}" \
        "ADMIN_CONTROL_PLANE_ENDPOINT=https://${ADMIN_CP_URL}" \
        "A2A_TARGET_URL_BUDGET_REPORT=https://${A2A_REPORT_URL}" \
        "A2A_TARGET_URL_BUDGET_APPROVAL=https://${A2A_APPROVAL_URL}" \
        "A2A_TARGET_URL_EMPLOYEE_MENUS=https://${A2A_MENUS_URL}" \
        "AGENT_TAG=" \
        "MI_CLIENT_ID=${DEMO_MI_CLIENT_ID}" \
    --user-assigned "$DEMO_MI_RESOURCE_ID" "$IDENTITY_ID" \
    --registry-server "$ACR_SERVER" \
    --registry-identity "$IDENTITY_ID" \
    2>&1 | tail -3

echo "   ✓ Container App created"
echo ""

# ─── Step 5: Add SPIFFE sidecar with join token ─────────────────────────

echo "🧹 Cleaning up stale SPIRE entries for ${AGENT_NAME}..."
SPIRE_CLEANUP="
for EID in \$(docker exec spire-server /opt/spire/bin/spire-server entry show -spiffeID spiffe://${TRUST_DOMAIN}/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID} 2>/dev/null | grep 'Entry ID' | awk '{print \$NF}'); do
    docker exec spire-server /opt/spire/bin/spire-server entry delete -entryID \$EID 2>/dev/null || true
done
for EID in \$(docker exec spire-server /opt/spire/bin/spire-server entry show -spiffeID spiffe://${TRUST_DOMAIN}/agent/${AGENT_NAME} 2>/dev/null | grep 'Entry ID' | awk '{print \$NF}'); do
    docker exec spire-server /opt/spire/bin/spire-server entry delete -entryID \$EID 2>/dev/null || true
done
docker exec spire-server /opt/spire/bin/spire-server agent evict -spiffeID spiffe://${TRUST_DOMAIN}/agent/${AGENT_NAME} 2>/dev/null || true
echo SPIRE_CLEANUP_DONE
"
azure_vm_run "$RG" "$SPIRE_SERVER_VM_NAME" "demo-cleanup-${AGENT_NAME}" "${SPIRE_CLEANUP}" 120 | grep -E 'CLEANUP_DONE|Evicted|Deleted' || true
echo "   ✓ Stale entries cleaned"
echo ""

echo "🔐 Extracting SPIRE trust bundle for secure bootstrap..."
BUNDLE_OUTPUT=$(azure_vm_run "$RG" "$SPIRE_SERVER_VM_NAME" "demo-trust-bundle-${AGENT_NAME}" \
    "docker exec spire-server /opt/spire/bin/spire-server bundle show -format pem" 120 2>&1) || true

SPIRE_TRUST_BUNDLE=$(echo "$BUNDLE_OUTPUT" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)
if [ -z "$SPIRE_TRUST_BUNDLE" ]; then
    echo "   ❌ Failed to extract trust bundle from SPIRE server"
    echo "   Output: ${BUNDLE_OUTPUT}"
    exit 1
fi
echo "   ✓ Trust bundle extracted"
echo ""

echo "🔑 Generating join token..."

AGENT_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT_NAME}"
TOKEN_OUTPUT=$(azure_vm_run "$RG" "$SPIRE_SERVER_VM_NAME" "demo-token-${AGENT_NAME}" \
    "docker exec spire-server /opt/spire/bin/spire-server token generate \
        -spiffeID '${AGENT_SPIFFE_ID}' \
        -ttl 600" 120 2>&1) || true

JOIN_TOKEN=$(echo "$TOKEN_OUTPUT" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)

if [ -z "$JOIN_TOKEN" ]; then
    echo "   ❌ Failed to generate token"
    echo "   Output: ${TOKEN_OUTPUT}"
    exit 1
fi

echo "   Token: ${JOIN_TOKEN:0:8}..."
echo ""
echo "📦 Injecting SPIFFE sidecar..."

pip3 install pyyaml --quiet 2>/dev/null || true

YAML_FILE="/tmp/${AGENT_NAME}-update.yaml"
az containerapp show --name "$AGENT_NAME" --resource-group "$RG" -o yaml | grep -v 'revisionSuffix' > "$YAML_FILE"

(
export YAML_FILE="$YAML_FILE"
export AGENT_NAME="$AGENT_NAME"
export SPIFFE_IMAGE="$SPIFFE_IMAGE"
export SPIRE_SERVER_FQDN="$SPIRE_SERVER_FQDN"
export JOIN_TOKEN="$JOIN_TOKEN"
export ENTRA_BP_OID="$ENTRA_BP_OID"
export ENTRA_AGENT_OID_BUDGET_BACKEND="$ENTRA_AGENT_OID_BUDGET_BACKEND"
export SPIRE_TRUST_BUNDLE="$SPIRE_TRUST_BUNDLE"
"$PYTHON" << 'PYTHON_SCRIPT'
import os
import yaml

yaml_file = os.environ["YAML_FILE"]
agent_name = os.environ["AGENT_NAME"]
spiffe_image = os.environ["SPIFFE_IMAGE"]
spire_server_fqdn = os.environ["SPIRE_SERVER_FQDN"]
join_token = os.environ["JOIN_TOKEN"]
entra_bp_oid = os.environ.get("ENTRA_BP_OID", "") or "placeholder-bp-oid"
entra_agent_oid_backend = os.environ.get("ENTRA_AGENT_OID_BUDGET_BACKEND", "") or "placeholder-backend-oid"
spire_trust_bundle = os.environ.get("SPIRE_TRUST_BUNDLE", "")

with open(yaml_file) as f:
    app = yaml.safe_load(f)

containers = app['properties']['template']['containers']

# Construct budget-backend's SPIFFE ID (must match exactly for TLS handshake)
backend_spiffe = f"spiffe://aim.microsoft.com/ests/bp/{entra_bp_oid}/aid/{entra_agent_oid_backend}"

# Add sidecar container
sidecar = {
    'name': f'{agent_name}-spiffe-proxy',
    'image': spiffe_image,
    'resources': {'cpu': 0.25, 'memory': '0.5Gi'},
    'env': [
        {'name': 'CONTAINER_MODE', 'value': 'agent-proxy'},
        {'name': 'PROXY_MODE', 'value': 'egress'},
        {'name': 'SPIRE_SERVER_ADDR', 'value': spire_server_fqdn},
        {'name': 'JOIN_TOKEN', 'value': join_token},
        {'name': 'SPIRE_TRUST_BUNDLE', 'value': spire_trust_bundle},
        {'name': 'HTTP_LISTEN_ADDR', 'value': ':8080'},
        {'name': 'REMOTE_PROXY_ADDR', 'value': 'budget-backend:8443'},
        {'name': 'ALLOWED_REMOTE_SPIFFE_ID', 'value': backend_spiffe},
    ],
}

# Replace existing sidecar or append
sidecar_name = f'{agent_name}-spiffe-proxy'
replaced = False
for i, c in enumerate(containers):
    if c['name'] == sidecar_name:
        containers[i] = sidecar
        replaced = True
        break
if not replaced:
    containers.append(sidecar)

with open(yaml_file, 'w') as f:
    yaml.dump(app, f, default_flow_style=False)
PYTHON_SCRIPT
)

az containerapp update --name "$AGENT_NAME" --resource-group "$RG" --yaml "$YAML_FILE" 2>&1 | tail -3
rm -f "$YAML_FILE"
echo "   ✓ Sidecar injected"
echo ""

# ─── Step 6: Wait for attestation + register workload ───────────────────

echo "⏳ Waiting 45s for SPIRE attestation..."
sleep 45

echo "📝 Registering workload entry..."
PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT_NAME}"
WORKLOAD_ID="spiffe://${TRUST_DOMAIN}/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID}"

azure_vm_run "$RG" "$SPIRE_SERVER_VM_NAME" "demo-entry-${AGENT_NAME}" \
    "docker exec spire-server /opt/spire/bin/spire-server entry create \
        -parentID '${PARENT_ID}' \
        -spiffeID '${WORKLOAD_ID}' \
        -selector unix:uid:0 \
        -ttl 3600" 120 2>&1 | grep -E 'Entry ID|already exists|stdout' || true

echo "   ✓ Workload registered"
echo ""

# ─── Step 7: Get FQDN + update portal config ────────────────────────────

echo "🌐 Discovering agent FQDN..."
AGENT_FQDN=$(az containerapp show --name "$AGENT_NAME" --resource-group "$RG" \
    --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)
AGENT_URL="https://${AGENT_FQDN}"
echo "   URL: ${AGENT_URL}"
echo ""

CONFIG_FILE="${REPO_ROOT}/portal/portal-config.json"
if [ -f "$CONFIG_FILE" ]; then
    echo "📋 Updating portal-config.json..."
    export CONFIG_FILE AGENT_NAME DISPLAY_NAME AGENT_URL TRUST_DOMAIN ENTRA_BP_OID ENTRA_AGENT_OID
    python3 << 'PYEOF'
import json
import os

config_file = os.environ["CONFIG_FILE"]
agent_name = os.environ["AGENT_NAME"]
display_name = os.environ["DISPLAY_NAME"]
agent_url = os.environ["AGENT_URL"]
trust_domain = os.environ["TRUST_DOMAIN"]
entra_bp_oid = os.environ.get("ENTRA_BP_OID", "")
entra_agent_oid = os.environ.get("ENTRA_AGENT_OID", "")

with open(config_file) as f:
    config = json.load(f)

config["agents"][agent_name] = {
    "name": display_name,
    "app_name": agent_name,
    "url": agent_url,
    "spiffe_id": f"spiffe://{trust_domain}/ests/bp/{entra_bp_oid}/aid/{entra_agent_oid}",
    "entra_agent_id": entra_agent_oid,
    "role": "Dynamic Caller",
    "entra_role": "\u2014"
}

with open(config_file, "w") as f:
    json.dump(config, f, indent=2)

print(f"   Added {len(config['agents'])} agents to config")
PYEOF

    # Notify portal to reload
    curl -s -X POST "http://localhost:${PORTAL_PORT}/api/reload-config" > /dev/null 2>&1 && \
        echo "   ✓ Portal notified" || \
        echo "   ⚠ Portal not running (start it to see the new agent)"
fi

echo ""
echo "============================================="
echo "✅ AGENT DEPLOYED: ${DISPLAY_NAME}"
echo "============================================="
echo ""
echo "  Name:      ${AGENT_NAME}"
echo "  SPIFFE ID: ${WORKLOAD_ID}"
echo "  URL:       ${AGENT_URL}"
echo "  Status:    🚫 BLOCKED (not in mTLS allow list)"
echo ""
echo "Next steps in the portal (localhost:${PORTAL_PORT}):"
echo "  1. Refresh the page — ${DISPLAY_NAME} appears in the flow diagram (blocked)"
echo "  2. Go to mTLS tab → add the agent's SPIFFE ID to allow list"
echo "  3. Go to Policy tab → add RBAC rules for ${AGENT_NAME}"
echo "  4. Execute tab → test ${DISPLAY_NAME} → GET /budget/read"
echo ""
echo "Cleanup: ./scripts/remove-demo-agent.sh ${AGENT_NAME}"
echo ""
