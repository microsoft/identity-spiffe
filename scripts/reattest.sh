#!/bin/bash
# =============================================================================
# Re-attest SPIRE agents with fresh join tokens
# =============================================================================
# Generates new join tokens and updates sidecar containers WITHOUT rebuilding
# images, reprovisioning infrastructure, or touching Entra Agent IDs.
#
# Use when: a Container App revision reset wiped a sidecar's join token,
# or an agent is stuck in a "join token does not exist" crash loop.
#
# Usage:
#   ./scripts/reattest.sh                     # re-attest all agents
#   ./scripts/reattest.sh admin-control-plane  # re-attest one agent
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/lib/deploy-config.sh"
source "${SCRIPT_DIR}/lib/azure-helpers.sh"

AZD_VALUES=$(azd_env_load)
RG=$(azd_env_get_from_blob "$AZD_VALUES" "AZURE_RESOURCE_GROUP")
SPIRE_SERVER_FQDN=$(azd_env_get_from_blob "$AZD_VALUES" "SPIRE_SERVER_FQDN")

if [ -z "$RG" ] || [ -z "$SPIRE_SERVER_FQDN" ]; then
    echo "ERROR: Missing azd env values (AZURE_RESOURCE_GROUP, SPIRE_SERVER_FQDN)." >&2
    echo "Run deploy.sh first to set up the environment." >&2
    exit 1
fi

# Which agents to re-attest
if [ $# -gt 0 ]; then
    TARGET_AGENTS=("$@")
else
    TARGET_AGENTS=("${AGENTS[@]}")
fi

vm_run() {
    local cmd_name="$1"
    local script="$2"
    local timeout_secs="${3:-120}"
    echo "   [vm-run] ${cmd_name}..."
    azure_vm_run "$RG" "$SPIRE_SERVER_VM_NAME" "$cmd_name" "$script" "$timeout_secs"
}

echo ""
echo "============================================="
echo "  Re-attest SPIRE Agents (fresh join tokens)"
echo "============================================="
echo "  Resource Group: ${RG}"
echo "  SPIRE Server:   ${SPIRE_SERVER_FQDN}"
echo "  Agents:         ${TARGET_AGENTS[*]}"
echo ""

pip3 install pyyaml --quiet 2>/dev/null || true

for AGENT in "${TARGET_AGENTS[@]}"; do
    echo "🔑 [$AGENT] Generating fresh join token..."

    AGENT_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT}"

    TOKEN_OUTPUT=$(vm_run "token-${AGENT}" "sudo docker exec spire-server /opt/spire/bin/spire-server token generate \
            -spiffeID '${AGENT_SPIFFE_ID}' \
            -ttl 600" 120 2>&1)

    JOIN_TOKEN=$(echo "$TOKEN_OUTPUT" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)

    if [ -z "$JOIN_TOKEN" ]; then
        echo "   ERROR: Failed to generate token for ${AGENT}"
        echo "   Output: ${TOKEN_OUTPUT}"
        exit 1
    fi

    echo "   Token: ${JOIN_TOKEN:0:8}..."

    # Export current YAML, update ONLY the JOIN_TOKEN env var, apply
    echo "   Updating sidecar JOIN_TOKEN..."
    YAML_FILE="/tmp/${AGENT}-reattest.yaml"
    az containerapp show --name "$AGENT" --resource-group "$RG" -o yaml | grep -v 'revisionSuffix' > "$YAML_FILE"

    YAML_FILE="$YAML_FILE" AGENT="$AGENT" JOIN_TOKEN="$JOIN_TOKEN" python3 << 'PYEOF'
import os
import yaml

yaml_file = os.environ["YAML_FILE"]
agent_name = os.environ["AGENT"]
new_token = os.environ["JOIN_TOKEN"]

with open(yaml_file) as f:
    app = yaml.safe_load(f)

sidecar_name = f"{agent_name}-spiffe-proxy"
updated = False

for container in app['properties']['template']['containers']:
    if container['name'] == sidecar_name:
        for env in container.get('env', []):
            if env['name'] == 'JOIN_TOKEN':
                env['value'] = new_token
                updated = True
                break
        break

if not updated:
    print(f"   WARN: Could not find JOIN_TOKEN in {sidecar_name} — skipping")
else:
    with open(yaml_file, 'w') as f:
        yaml.dump(app, f, default_flow_style=False)
    print(f"   JOIN_TOKEN updated in YAML")
PYEOF

    az containerapp update --name "$AGENT" --resource-group "$RG" --yaml "$YAML_FILE" 2>&1 | tail -3
    rm -f "$YAML_FILE"
    echo "   ✓ ${AGENT} re-attesting with fresh token"
    echo ""
done

echo "⏳ Waiting 30s for agents to attest..."
sleep 30

# Verify attestation
echo "🔍 Checking attested agents..."
AGENT_LIST=$(vm_run "agent-list" "sudo docker exec spire-server /opt/spire/bin/spire-server agent list" 120 2>&1)
ATTESTED_COUNT=$(echo "$AGENT_LIST" | grep -oE 'SPIFFE ID' | wc -l | tr -d ' ')
echo "   Attested agents: ${ATTESTED_COUNT}"
echo "$AGENT_LIST" | grep -E 'SPIFFE ID|Attestation' || true

echo ""
echo "============================================="
echo "✅ Re-attestation complete"
echo "============================================="
echo ""
echo "If the portal Overview is blank, restart it:"
echo "  az containerapp update -n isp-portal -g ${RG} --set-env-vars CACHE_BUST=\$(date +%s)"
