#!/usr/bin/env bash
# =============================================================================
# assign-role.sh — Assign or remove an app role on an agent's managed identity
# =============================================================================
# Manages Budget.Read and Budget.Submit role assignments via Graph API.
# Use during demos to grant/revoke roles and show OAuth enforcement changes.
#
# Usage:
#   ./scripts/assign-role.sh budget-report Budget.Submit        # assign
#   ./scripts/assign-role.sh budget-report Budget.Submit remove  # remove
#   ./scripts/assign-role.sh --list                              # show all
# =============================================================================
set -euo pipefail

AZD_VALUES=$(azd env get-values 2>/dev/null || true)
get_val() { echo "$AZD_VALUES" | grep -E "^$1=" | cut -d= -f2 | tr -d '"'; }

TENANT_ID=$(get_val AZURE_TENANT_ID)
CLIENT_ID=$(get_val ENTRA_AGENTID_CLIENT_ID)
CLIENT_SECRET=$(get_val ENTRA_AGENTID_CLIENT_SECRET)
AUDIENCE=$(get_val ENTRA_OAUTH2_AUDIENCE)

if [ -z "$TENANT_ID" ] || [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
    echo "ERROR: Missing azd env vars (AZURE_TENANT_ID, ENTRA_AGENTID_CLIENT_ID, ENTRA_AGENTID_CLIENT_SECRET)"
    exit 1
fi

# Get Graph token
TOKEN=$(curl -s -X POST "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
    -d "client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&scope=https://graph.microsoft.com/.default&grant_type=client_credentials" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Role ID mapping
role_id() {
    case "$1" in
        Budget.Read)   echo "b1e2c3d4-0001-4000-8000-000000000001" ;;
        Budget.Submit) echo "b1e2c3d4-0002-4000-8000-000000000002" ;;
        *) echo ""; return 1 ;;
    esac
}

# Find Blueprint SP ID
BP_SP_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/beta/servicePrincipals?\$filter=appId%20eq%20'${AUDIENCE}'" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['value'][0]['id'])")

# List mode
if [ "${1:-}" = "--list" ]; then
    echo ""
    echo "App role assignments on Blueprint:"
    echo ""
    curl -s -H "Authorization: Bearer $TOKEN" \
        "https://graph.microsoft.com/beta/servicePrincipals/${BP_SP_ID}/appRoleAssignedTo" \
        | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data.get('value', []):
    role = 'Budget.Read' if '0001' in a['appRoleId'] else 'Budget.Submit' if '0002' in a['appRoleId'] else a['appRoleId']
    print(f'  {a[\"principalDisplayName\"]:30s} -> {role}')
"
    echo ""
    exit 0
fi

# Parse args
AGENT="${1:?Usage: assign-role.sh <agent-name> <role> [remove]}"
ROLE="${2:?Usage: assign-role.sh <agent-name> <role> [remove]}"
ACTION="${3:-assign}"

ROLE_ID=$(role_id "$ROLE") || { echo "Unknown role: $ROLE (valid: Budget.Read, Budget.Submit)"; exit 1; }

# Get agent MI client ID
ENV_UPPER=$(echo "$AGENT" | tr '[:lower:]-' '[:upper:]_')
MI_CLIENT=$(get_val "MI_CLIENT_ID_${ENV_UPPER}")
if [ -z "$MI_CLIENT" ]; then
    echo "ERROR: No MI_CLIENT_ID_${ENV_UPPER} in azd env"
    exit 1
fi

# Find MI SP ID
MI_SP_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/beta/servicePrincipals?\$filter=appId%20eq%20'${MI_CLIENT}'" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['value'][0]['id'])")

echo ""

if [ "$ACTION" = "remove" ]; then
    # Find the assignment ID to delete
    ASSIGNMENT_ID=$(curl -s -H "Authorization: Bearer $TOKEN" \
        "https://graph.microsoft.com/beta/servicePrincipals/${MI_SP_ID}/appRoleAssignments" \
        | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data.get('value', []):
    if a['appRoleId'] == '${ROLE_ID}':
        print(a['id'])
        break
")
    if [ -z "$ASSIGNMENT_ID" ]; then
        echo "  $AGENT doesn't have $ROLE — nothing to remove"
    else
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
            -H "Authorization: Bearer $TOKEN" \
            "https://graph.microsoft.com/beta/servicePrincipals/${MI_SP_ID}/appRoleAssignments/${ASSIGNMENT_ID}")
        if [ "$STATUS" = "204" ]; then
            echo "  Removed $ROLE from $AGENT"
        else
            echo "  ERROR: Failed to remove (HTTP $STATUS)"
        fi
    fi
else
    # Assign
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d "{\"principalId\":\"${MI_SP_ID}\",\"resourceId\":\"${BP_SP_ID}\",\"appRoleId\":\"${ROLE_ID}\"}" \
        "https://graph.microsoft.com/beta/servicePrincipals/${BP_SP_ID}/appRoleAssignments")
    if [ "$STATUS" = "201" ] || [ "$STATUS" = "200" ]; then
        echo "  Assigned $ROLE to $AGENT"
    elif [ "$STATUS" = "409" ]; then
        echo "  $AGENT already has $ROLE"
    else
        echo "  ERROR: Failed to assign (HTTP $STATUS)"
    fi
fi

echo ""
echo "Next: ./scripts/flush-tokens.sh $AGENT"
echo ""
