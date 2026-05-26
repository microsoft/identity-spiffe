#!/bin/bash
# =============================================================================
# AIM Prototype Platform — Remove Demo Agent(s)
# =============================================================================
# Usage:
#   ./scripts/remove-demo-agent.sh audit-reviewer   # remove one agent
#   ./scripts/remove-demo-agent.sh --all             # remove all demo agents
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

PORTAL_PORT=8550
DEMO_NAMES=("audit-reviewer" "tax-reporter" "payroll-service" "expense-tracker" "compliance-bot")
export REPO_ROOT

CONFIG_FILE="${REPO_ROOT}/portal/portal-config.json"

REMOVE_ALL=false
TARGETS=()

for arg in "$@"; do
    case $arg in
        --all) REMOVE_ALL=true ;;
        *) TARGETS+=("$arg") ;;
    esac
done

# Discover environment
AZD_ENV=$(azd_env_load)
RG=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_RESOURCE_GROUP")
ENTRA_BP_OID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_OBJECT_ID")
if [ -z "$RG" ]; then
    RG=$(az group list --query "[?starts_with(name,'aim-') || starts_with(name,'rg-aim')].name" -o tsv 2>/dev/null | head -1 || true)
fi

if [ -z "$RG" ]; then
    echo "❌ Could not discover resource group."
    exit 1
fi

if ! validate_entra_scope; then
    exit 1
fi
echo "Scope Mode: $(resolve_scope_mode)"
echo "Scope Key:  $(resolve_scope_key)"

# Build target list
if [ "$REMOVE_ALL" = true ]; then
    for name in "${DEMO_NAMES[@]}"; do
        EXISTS=$(az containerapp show --name "$name" --resource-group "$RG" --query "name" -o tsv 2>/dev/null || true)
        if [ -n "$EXISTS" ]; then
            TARGETS+=("$name")
        fi
    done
fi

if [ ${#TARGETS[@]} -eq 0 ]; then
    echo "Nothing to remove. Usage:"
    echo "  ./scripts/remove-demo-agent.sh <agent-name>"
    echo "  ./scripts/remove-demo-agent.sh --all"
    exit 0
fi

echo ""
echo "============================================="
echo "  Removing ${#TARGETS[@]} demo agent(s)"
echo "============================================="
echo ""

for AGENT_NAME in "${TARGETS[@]}"; do
    echo "🗑  Removing ${AGENT_NAME}..."
    echo "   Agent Identity: $(agent_identity_display_name "${AGENT_NAME}")"
    echo "   Federated Cred: $(fic_name "${AGENT_NAME}")"

    # Delete Container App
    az containerapp delete --name "$AGENT_NAME" --resource-group "$RG" --yes 2>&1 | tail -1 || true
    echo "   ✓ Container App deleted"

    # Delete the demo agent's dedicated Managed Identity
    MI_NAME="${AGENT_NAME}-identity"
    az identity delete --name "$MI_NAME" --resource-group "$RG" 2>/dev/null || true
    echo "   ✓ Managed Identity deleted (${MI_NAME})"

    # Delete Entra Agent Identity SP and FIC via Graph API
    export AGENT_NAME
    python3 << 'REMOVE_ENTRA_PYEOF'
import os, sys
sys.path.insert(0, os.path.join(os.environ["REPO_ROOT"], "scripts"))
from entra_provisioning import (
    build_required_permission_values, get_azd_env, set_azd_env,
    get_graph_token as get_provisioner_graph_token,
)
from entra_scope import agent_identity_display_name, fic_name, resolve_scope
import requests

GRAPH_BASE = "https://graph.microsoft.com/beta"
agent_name = os.environ["AGENT_NAME"]
scope = resolve_scope(env_get=get_azd_env, env_set=set_azd_env)
display_name = agent_identity_display_name(agent_name, scope)

def graph_request(method, path, token, json_body=None):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    return requests.request(method, f"{GRAPH_BASE}{path}", headers=headers, json=json_body)

try:
    token = get_provisioner_graph_token(build_required_permission_values(include_ca=True))
except Exception as e:
    print(f"   ⚠ Could not get Graph token for Entra cleanup: {e}")
    sys.exit(0)  # Non-fatal — Container App is already deleted

blueprint_obj_id = get_azd_env("ENTRA_BLUEPRINT_OBJECT_ID")

# Delete FIC
if blueprint_obj_id:
    fic_display_name = fic_name(agent_name, scope)
    fics_resp = graph_request("GET", f"/applications/{blueprint_obj_id}/federatedIdentityCredentials", token)
    if fics_resp.status_code == 200:
        for fic in fics_resp.json().get("value", []):
            if fic["name"] == fic_display_name:
                graph_request("DELETE", f"/applications/{blueprint_obj_id}/federatedIdentityCredentials/{fic['id']}", token)
                print(f"   ✓ FIC deleted ({fic_display_name})")
                break

# Delete Agent Identity SP
resp = graph_request("GET", f"/servicePrincipals?\$filter=displayName eq '{display_name}'", token)
if resp.status_code == 200:
    for sp in resp.json().get("value", []):
        if sp.get("displayName") == display_name:
            sp_id = sp["id"]
            del_resp = graph_request("DELETE", f"/servicePrincipals/{sp_id}", token)
            if del_resp.status_code == 204:
                print(f"   ✓ Agent Identity deleted ({display_name})")
            break

# Clear azd env vars
env_upper = agent_name.upper().replace("-", "_")
set_azd_env(f"ENTRA_AGENT_ID_{env_upper}", "")
set_azd_env(f"MI_CLIENT_ID_{env_upper}", "")
set_azd_env(f"ENTRA_FIC_CREATED_{env_upper}", "")
REMOVE_ENTRA_PYEOF

    # Remove from portal config
    if [ -f "$CONFIG_FILE" ]; then
        export CONFIG_FILE AGENT_NAME
        python3 -c '
import json, os
config_file = os.environ["CONFIG_FILE"]
agent_name = os.environ["AGENT_NAME"]
with open(config_file) as f:
    config = json.load(f)
config["agents"].pop(agent_name, None)
with open(config_file, "w") as f:
    json.dump(config, f, indent=2)
print("   \u2713 Removed from portal config")
'
    fi
    echo ""
done

# ─── Clean up SPIRE entries (batched into one VM command) ────────────────

echo "🧹 Cleaning up SPIRE entries..."
SPIRE_CLEANUP=""
for AGENT_NAME in "${TARGETS[@]}"; do
    # Look up the Entra Agent OID from azd env (may be empty if already cleared)
    _ENV_UPPER=$(echo "$AGENT_NAME" | tr '[:lower:]-' '[:upper:]_')
    _ENTRA_OID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_AGENT_ID_${_ENV_UPPER}")
    # Build SPIFFE ID — use Entra OID if available, fall back to agent name
    _AID="${_ENTRA_OID:-$AGENT_NAME}"
    SPIRE_CLEANUP+="
for EID in \$(docker exec spire-server /opt/spire/bin/spire-server entry show -spiffeID spiffe://${TRUST_DOMAIN}/ests/bp/${ENTRA_BP_OID:-placeholder-bp-oid}/aid/${_AID} 2>/dev/null | grep 'Entry ID' | awk '{print \$NF}'); do
    docker exec spire-server /opt/spire/bin/spire-server entry delete -entryID \$EID 2>/dev/null || true
done
for EID in \$(docker exec spire-server /opt/spire/bin/spire-server entry show -spiffeID spiffe://${TRUST_DOMAIN}/agent/${AGENT_NAME} 2>/dev/null | grep 'Entry ID' | awk '{print \$NF}'); do
    docker exec spire-server /opt/spire/bin/spire-server entry delete -entryID \$EID 2>/dev/null || true
done
docker exec spire-server /opt/spire/bin/spire-server agent evict -spiffeID spiffe://${TRUST_DOMAIN}/agent/${AGENT_NAME} 2>/dev/null || true
"
done
SPIRE_CLEANUP+="echo SPIRE_CLEANUP_DONE"

azure_vm_run "$RG" "$SPIRE_SERVER_VM_NAME" "demo-remove-cleanup" "${SPIRE_CLEANUP}" 120 | grep -E 'CLEANUP_DONE|Evicted|Deleted' || true
echo "✓ SPIRE entries cleaned up"
echo ""

# Notify portal
curl -s -X POST "http://localhost:${PORTAL_PORT}/api/reload-config" > /dev/null 2>&1 && \
    echo "✓ Portal notified" || \
    echo "⚠ Portal not running"

echo ""
echo "✅ Done. Removed: ${TARGETS[*]}"
echo ""
