#!/bin/bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Shared Federation Provisioning Helpers
# =============================================================================
# Shared functions for provisioning cross-cloud agents (Google, GitHub, etc.)
# Extracts common logic: Azure env discovery, Graph token, Agent Identity
# creation, app role assignment, mTLS allow list, portal registration.
#
# Usage: source this file from platform-specific provisioning scripts.
#   source "${SCRIPT_DIR}/lib/federation-helpers.sh"
# =============================================================================

GRAPH_BASE="https://graph.microsoft.com/beta"
FIC_AUDIENCE="api://AzureADTokenExchange"

# ---------------------------------------------------------------------------
# discover_azure_env — Load Azure environment from azd
# Sets: TENANT_ID, BP_CLIENT_ID, BP_OBJECT_ID, BP_OID, MGMT_KEY (if not set)
# ---------------------------------------------------------------------------
discover_azure_env() {
    echo "📍 Discovering Azure environment..."

    AZD_ENV=$(azd_env_load)
    TENANT_ID=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_TENANT_ID")
    if [[ -z "$TENANT_ID" ]]; then
        TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null || true)
    fi
    if [[ -z "$TENANT_ID" ]]; then
        echo "ERROR: Could not determine AZURE_TENANT_ID." >&2
        return 1
    fi

    BP_CLIENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_CLIENT_ID")
    if [[ -z "$BP_CLIENT_ID" ]]; then
        BP_CLIENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_APP_ID")
    fi
    if [[ -z "$BP_CLIENT_ID" ]]; then
        BP_CLIENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_OAUTH2_AUDIENCE")
    fi
    BP_OBJECT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_OBJECT_ID")
    BP_OID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_OID")

    if [[ -z "${MGMT_KEY:-}" ]]; then
        MGMT_KEY=$(azd_env_get_from_blob "$AZD_ENV" "MGMT_API_KEY")
    fi

    if [[ -z "$BP_CLIENT_ID" || -z "$BP_OBJECT_ID" ]]; then
        echo "ERROR: Blueprint IDs not found in azd env." >&2
        echo "       Run create-entra-agent-ids.py first." >&2
        return 1
    fi

    echo "  Tenant ID:        ${TENANT_ID}"
    echo "  Blueprint client: ${BP_CLIENT_ID}"
    echo "  Blueprint object: ${BP_OBJECT_ID}"
}

# ---------------------------------------------------------------------------
# acquire_graph_token — Get a Microsoft Graph API token
# Sets: GRAPH_TOKEN
# ---------------------------------------------------------------------------
acquire_graph_token() {
    GRAPH_TOKEN=$(az account get-access-token \
        --resource "https://graph.microsoft.com" \
        --query accessToken -o tsv 2>/dev/null || true)

    if [[ -z "$GRAPH_TOKEN" ]]; then
        echo "ERROR: Could not get a Graph API token. Run 'az login' first." >&2
        return 1
    fi

    # Try provisioner app if available
    local provisioner_client_id
    provisioner_client_id=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_AGENTID_CLIENT_ID" || true)
    if [[ -n "$provisioner_client_id" ]]; then
        local provisioner_secret
        provisioner_secret=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_AGENTID_CLIENT_SECRET" || true)
        if [[ -n "$provisioner_secret" ]]; then
            local prov_token
            prov_token=$(printf 'client_id=%s&client_secret=%s&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default&grant_type=client_credentials' \
                "$provisioner_client_id" "$provisioner_secret" | \
                curl -s -X POST \
                "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
                --data @- | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))")
            if [[ -n "$prov_token" ]]; then
                GRAPH_TOKEN="$prov_token"
            fi
        fi
    fi
}

# ---------------------------------------------------------------------------
# create_agent_identity — Create Entra Agent Identity under Blueprint
# Args: $1 = agent_display_name, $2 = stored_env_key (for idempotency)
# Sets: AGENT_OID, AGENT_CLIENT_ID
# ---------------------------------------------------------------------------
create_agent_identity() {
    local agent_display_name="$1"
    local stored_env_key="${2:-}"

    echo ""
    echo "🤖 Creating Entra Agent Identity: ${agent_display_name}..."

    local sponsor_id
    sponsor_id=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)

    # Idempotency: check stored ID first
    if [[ -n "$stored_env_key" ]]; then
        local stored_id
        stored_id=$(azd_env_get_from_blob "$AZD_ENV" "$stored_env_key" || true)
        if [[ -n "$stored_id" ]]; then
            local verify_code
            verify_code=$(curl -s -o /dev/null -w "%{http_code}" \
                "${GRAPH_BASE}/servicePrincipals/${stored_id}" \
                -H "Authorization: Bearer ${GRAPH_TOKEN}" 2>/dev/null || true)
            if [[ "$verify_code" == "200" ]]; then
                echo "  ✅ Agent Identity already exists: ${stored_id}"
                AGENT_OID="$stored_id"
                AGENT_CLIENT_ID="$stored_id"
                return 0
            fi
        fi
    fi

    # Search by display name
    local existing_response existing_id
    existing_response=$(curl -s \
        "${GRAPH_BASE}/servicePrincipals?\$count=true" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        -H "ConsistencyLevel: eventual")

    existing_id=$(echo "$existing_response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    bp = '${BP_CLIENT_ID}'
    name = '${agent_display_name}'
    for v in data.get('value', []):
        if v.get('displayName') == name and v.get('agentIdentityBlueprintId') == bp:
            print(v.get('id', ''))
            break
except Exception:
    pass
" 2>/dev/null || true)

    if [[ -n "$existing_id" ]]; then
        echo "  ✅ Agent Identity already exists — reusing: ${existing_id}"
        AGENT_OID="$existing_id"
        AGENT_CLIENT_ID=$(echo "$existing_response" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for v in data.get('value', []):
    if v.get('id') == '${existing_id}':
        print(v.get('appId', ''))
        break
" 2>/dev/null || true)
        return 0
    fi

    # Create new Agent Identity
    local agent_body
    agent_body=$(python3 -c "
import json
body = {
    '@odata.type': 'Microsoft.Graph.AgentIdentity',
    'displayName': '${agent_display_name}',
    'agentIdentityBlueprintId': '${BP_CLIENT_ID}',
}
sponsor_id = '${sponsor_id}'
if sponsor_id:
    body['sponsors@odata.bind'] = [
        f'https://graph.microsoft.com/beta/users/{sponsor_id}'
    ]
print(json.dumps(body))
")

    local response body status
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "${GRAPH_BASE}/servicePrincipals" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$agent_body")

    body=$(echo "$response" | sed '$d')
    status=$(echo "$response" | tail -n 1)

    if [[ "$status" != "201" && "$status" != "200" ]]; then
        echo "ERROR: Agent Identity creation failed (HTTP ${status}):" >&2
        echo "$body" | python3 -m json.tool >&2 || echo "$body" >&2
        return 1
    fi

    AGENT_OID=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))")
    AGENT_CLIENT_ID=$(echo "$body" | python3 -c "import sys,json; print(json.load(sys.stdin).get('appId',''))")

    if [[ -z "$AGENT_OID" ]]; then
        echo "ERROR: Agent Identity response missing 'id' field." >&2
        return 1
    fi

    echo "  ✅ Agent Identity created"
    echo "  Agent Identity OID:       ${AGENT_OID}"
    echo "  Agent Identity client ID: ${AGENT_CLIENT_ID}"

    # Persist to azd env so subsequent deploy.sh steps (and later runs) can read it back.
    # Without this, the parent deploy sees an empty value and propagates PLACEHOLDER
    # into /etc/identity-spiffe-github-runner.env on the runner VM.
    if [[ -n "$stored_env_key" ]] && command -v azd >/dev/null 2>&1; then
        if azd env set "$stored_env_key" "$AGENT_OID" >/dev/null 2>&1; then
            echo "  ✅ Persisted OID to azd env as ${stored_env_key}"
        else
            echo "  ⚠️  Could not persist OID to azd env (not fatal, but next deploy can't reuse)"
        fi
    fi
}

# ---------------------------------------------------------------------------
# assign_app_role — Assign an app role to the Agent Identity
# Args: $1 = role_value (e.g. "Budget.Read")
# Requires: BP_CLIENT_ID, AGENT_OID, GRAPH_TOKEN
# ---------------------------------------------------------------------------
assign_app_role() {
    local role_value="$1"

    echo ""
    echo "🎫 Assigning ${role_value} app role to Agent Identity..."

    local bp_sp_id
    bp_sp_id=$(curl -s \
        "https://graph.microsoft.com/v1.0/servicePrincipals?\$filter=appId%20eq%20'${BP_CLIENT_ID}'" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        -H "ConsistencyLevel: eventual" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('value',[{}])[0].get('id',''))" 2>/dev/null || true)

    if [[ -z "$bp_sp_id" ]]; then
        echo "WARNING: Could not find Blueprint service principal — skipping role assignment." >&2
        return 0
    fi

    local role_id
    role_id=$(curl -s \
        "https://graph.microsoft.com/v1.0/applications?\$filter=appId%20eq%20'${BP_CLIENT_ID}'" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        -H "ConsistencyLevel: eventual" \
        | python3 -c "
import sys, json
roles = json.load(sys.stdin).get('value', [{}])[0].get('appRoles', [])
for r in roles:
    if r.get('value') == '${role_value}':
        print(r['id'])
        break
" 2>/dev/null || true)

    if [[ -z "$role_id" ]]; then
        echo "WARNING: ${role_value} role not found on Blueprint." >&2
        return 0
    fi

    # Idempotency check
    local existing_role
    existing_role=$(curl -s \
        "${GRAPH_BASE}/servicePrincipals/${AGENT_OID}/appRoleAssignments" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        | python3 -c "
import sys, json
for a in json.load(sys.stdin).get('value', []):
    if a.get('appRoleId') == '${role_id}':
        print('assigned')
        break
" 2>/dev/null || true)

    if [[ "$existing_role" == "assigned" ]]; then
        echo "  ✅ ${role_value} already assigned — skipping."
        return 0
    fi

    local assign_response assign_body assign_status
    assign_response=$(curl -s -w "\n%{http_code}" -X POST \
        "${GRAPH_BASE}/servicePrincipals/${bp_sp_id}/appRoleAssignments" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"principalId\": \"${AGENT_OID}\",
            \"resourceId\": \"${bp_sp_id}\",
            \"appRoleId\": \"${role_id}\"
        }")

    assign_body=$(echo "$assign_response" | sed '$d')
    assign_status=$(echo "$assign_response" | tail -n 1)

    if [[ "$assign_status" == "201" || "$assign_status" == "200" ]]; then
        echo "  ✅ ${role_value} role assigned."
    else
        echo "WARNING: Role assignment failed (HTTP ${assign_status}):" >&2
        echo "$assign_body" | python3 -m json.tool >&2 || echo "$assign_body" >&2
    fi
}

# ---------------------------------------------------------------------------
# update_mtls_allow_list — Add a SPIFFE ID to the mTLS allow list
# Args: $1 = spiffe_id
# Requires: MGMT_KEY, PORTAL_URL
# ---------------------------------------------------------------------------
update_mtls_allow_list() {
    local spiffe_id="$1"

    echo ""
    echo "🔒 Adding SPIFFE ID to mTLS allow list..."
    echo "  SPIFFE ID: ${spiffe_id}"

    if [[ -z "${MGMT_KEY:-}" ]]; then
        echo "WARNING: MGMT_API_KEY not available — skipping mTLS update." >&2
        return 0
    fi

    local mtls_status
    mtls_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Spiffe-Admin-Key: ${MGMT_KEY}" \
        "${PORTAL_URL}/api/mtls-policy" || true)

    if [[ "$mtls_status" != "200" ]]; then
        echo "WARNING: Could not reach portal (HTTP ${mtls_status})." >&2
        return 0
    fi

    local current_ids new_ids_json put_status
    current_ids=$(curl -s \
        -H "X-Spiffe-Admin-Key: ${MGMT_KEY}" \
        "${PORTAL_URL}/api/mtls-policy" | \
        python3 -c "import sys,json; ids=json.load(sys.stdin).get('allowed_ids',[]); print('\n'.join(ids))")

    new_ids_json=$(echo "$current_ids" | python3 -c "
import sys, json
ids = [l.strip() for l in sys.stdin if l.strip()]
if '${spiffe_id}' not in ids:
    ids.append('${spiffe_id}')
print(json.dumps({'allowed_ids': ids}))
")

    put_status=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        -H "X-Spiffe-Admin-Key: ${MGMT_KEY}" \
        -H "Content-Type: application/json" \
        -d "$new_ids_json" \
        "${PORTAL_URL}/api/mtls-policy")

    if [[ "$put_status" == "200" ]]; then
        echo "  ✅ mTLS allow list updated."
    else
        echo "WARNING: mTLS update returned HTTP ${put_status}." >&2
    fi
}

# ---------------------------------------------------------------------------
# register_external_agent — Register agent in portal external-agent store
# Args: $1=name, $2=invoke_url, $3=display_name, $4=hosting_platform
# Requires: MGMT_KEY, PORTAL_URL
# ---------------------------------------------------------------------------
register_external_agent() {
    local name="$1" invoke_url="$2" display_name="$3" hosting_platform="$4"

    echo ""
    echo "📋 Registering agent in portal external-agent store..."

    if [[ -z "${MGMT_KEY:-}" ]]; then
        echo "WARNING: MGMT_API_KEY not available — skipping portal registration." >&2
        return 0
    fi

    local agent_json reg_status
    agent_json=$(python3 -c "
import json
print(json.dumps({
    'name': '${name}',
    'invoke_url': '${invoke_url}',
    'display_name': '${display_name}',
    'transport': 'spiffe',
    'hosting_platform': '${hosting_platform}'
}))
")

    reg_status=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        -H "X-Spiffe-Admin-Key: ${MGMT_KEY}" \
        -H "Content-Type: application/json" \
        -d "$agent_json" \
        "${PORTAL_URL}/api/external-agents/${name}")

    if [[ "$reg_status" == "200" ]]; then
        echo "  ✅ External agent registered."
    else
        echo "WARNING: Portal registration returned HTTP ${reg_status}." >&2
    fi
}
