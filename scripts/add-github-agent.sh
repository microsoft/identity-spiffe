#!/bin/bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Provision a GitHub Actions Cross-Cloud Agent
# =============================================================================
# Creates an Entra Agent Identity for a GitHub Actions-hosted agent, wires a
# Flexible Federated Identity Credential to trust the GitHub org's OIDC tokens,
# adds the agent's SPIFFE ID to the mTLS allow list, and registers invoke
# metadata in the portal.
#
# KEY DIFFERENTIATOR: Uses a single Flexible FIC with claimsMatchingExpression
# to trust ALL repos in the GitHub org. Per-repo authorization is handled by
# Identity Research for Agent Management Using SPIFFE's RBAC engine, not by per-repo FICs. This solves the 20-FIC-per-app
# scaling limit.
#
# Prerequisites:
#   - az login  (DefaultAzureCredential for Graph API)
#   - azd env select <env>  (correct environment)
#   - The Blueprint already exists (run create-entra-agent-ids.py first)
#
# Required arguments / env vars:
#   --github-org  GITHUB_ORG  — GitHub organization name (e.g. "microsoft")
#
# Optional arguments / env vars:
#   --name        AGENT_NAME    — RBAC policy name (default: github-budget-reader)
#   --invoke-url  INVOKE_URL    — URL of the runner's agent endpoint
#   --portal-url  PORTAL_URL    — Portal base URL (default: http://localhost:8550)
#   --mgmt-key    MGMT_API_KEY  — Admin API key
#   --runner-spiffe-id RUNNER_SPIFFE_ID — SPIFFE ID of the self-hosted runner
#
# Usage:
#   ./scripts/add-github-agent.sh --github-org microsoft
#   ./scripts/add-github-agent.sh \
#       --github-org microsoft \
#       --name github-budget-reader \
#       --runner-spiffe-id spiffe://aim.microsoft.com/agent/github-runner
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=scripts/lib/deploy-config.sh
source "${SCRIPT_DIR}/lib/deploy-config.sh"
# shellcheck source=scripts/lib/azure-helpers.sh
source "${SCRIPT_DIR}/lib/azure-helpers.sh"
# shellcheck source=scripts/lib/entra-scope.sh
source "${SCRIPT_DIR}/lib/entra-scope.sh"
# shellcheck source=scripts/lib/federation-helpers.sh
source "${SCRIPT_DIR}/lib/federation-helpers.sh"

GITHUB_OIDC_ISSUER="https://token.actions.githubusercontent.com"

# ─── Argument parsing ────────────────────────────────────────────────────────

GITHUB_ORG=""
AGENT_NAME="github-budget-reader"
INVOKE_URL=""
PORTAL_URL="${PORTAL_URL:-http://localhost:8550}"
MGMT_KEY="${MGMT_API_KEY:-}"
RUNNER_SPIFFE_ID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --github-org)       GITHUB_ORG="$2"; shift 2 ;;
        --github-org=*)     GITHUB_ORG="${1#*=}"; shift ;;
        --name)             AGENT_NAME="$2"; shift 2 ;;
        --name=*)           AGENT_NAME="${1#*=}"; shift ;;
        --invoke-url)       INVOKE_URL="$2"; shift 2 ;;
        --invoke-url=*)     INVOKE_URL="${1#*=}"; shift ;;
        --portal-url)       PORTAL_URL="$2"; shift 2 ;;
        --portal-url=*)     PORTAL_URL="${1#*=}"; shift ;;
        --mgmt-key)         MGMT_KEY="$2"; shift 2 ;;
        --mgmt-key=*)       MGMT_KEY="${1#*=}"; shift ;;
        --runner-spiffe-id) RUNNER_SPIFFE_ID="$2"; shift 2 ;;
        --runner-spiffe-id=*) RUNNER_SPIFFE_ID="${1#*=}"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$GITHUB_ORG" ]]; then
    echo "ERROR: --github-org <org-name> is required." >&2
    exit 1
fi

echo ""
echo "============================================================"
echo "  Identity Research for Agent Management Using SPIFFE — Provision GitHub Actions Agent: ${AGENT_NAME}"
echo "============================================================"
echo ""

# ─── Step 1/7: Discover Azure environment ─────────────────────────────────

echo "📍 Step 1/7 — Discovering Azure environment..."
discover_azure_env || exit 1

# ─── Step 2/7: Validate GitHub org ────────────────────────────────────────

echo ""
echo "🔍 Step 2/7 — Validating GitHub organization: ${GITHUB_ORG}..."

# Basic validation — the org name appears in expected OIDC subject format
if [[ ! "$GITHUB_ORG" =~ ^[a-zA-Z0-9_.-]+$ ]]; then
    echo "ERROR: Invalid GitHub org name: ${GITHUB_ORG}" >&2
    echo "       Must contain only alphanumeric characters, hyphens, dots, underscores." >&2
    exit 1
fi
echo "  GitHub org: ${GITHUB_ORG}"
echo "  FIC subject pattern: repo:${GITHUB_ORG}/*"

# ─── Step 3/7: Create Agent Identity ─────────────────────────────────────

echo ""
echo "🤖 Step 3/7 — Creating Entra Agent Identity..."
acquire_graph_token || exit 1
create_agent_identity "${AGENT_NAME}" "ENTRA_AGENT_ID_GITHUB_BUDGET_READER" || exit 1

echo "  Agent Identity OID:       ${AGENT_OID}"
echo "  Agent Identity client ID: ${AGENT_CLIENT_ID}"

# ─── Step 4/7: Create Flexible FIC on Blueprint for GitHub OIDC ──────────

echo ""
echo "🔗 Step 4/7 — Creating Flexible FIC for GitHub Actions OIDC..."
echo "  Issuer:  ${GITHUB_OIDC_ISSUER}"
echo "  Pattern: repo:${GITHUB_ORG}/*"

FIC_NAME="github-${AGENT_NAME}"

# Check if Flexible FIC is supported (claimsMatchingExpression)
# Try to list existing FICs first — if the endpoint works, we're good
EXISTING_FICS=$(curl -s \
    "${GRAPH_BASE}/applications/${BP_OBJECT_ID}/federatedIdentityCredentials" \
    -H "Authorization: Bearer ${GRAPH_TOKEN}" 2>/dev/null || true)

# Idempotency: check if our FIC already exists
EXISTING_FIC_MATCH=$(echo "$EXISTING_FICS" | python3 -c "
import sys, json
try:
    fics = json.load(sys.stdin).get('value', [])
    match = [f for f in fics if f.get('name') == '${FIC_NAME}']
    if match:
        print(match[0].get('id', 'exists'))
    else:
        print('')
except: print('')
" 2>/dev/null || true)

if [[ -n "$EXISTING_FIC_MATCH" ]]; then
    echo "  ✅ FIC already exists — skipping."
    FIC_ID="$EXISTING_FIC_MATCH"
else
    # Create Flexible FIC with claimsMatchingExpression
    FIC_BODY=$(python3 -c "
import json
print(json.dumps({
    'name': '${FIC_NAME}',
    'issuer': '${GITHUB_OIDC_ISSUER}',
    'claimsMatchingExpression': {
        'value': \"claims['sub'] matches 'repo:${GITHUB_ORG}/*'\",
        'languageVersion': 1
    },
    'audiences': ['${FIC_AUDIENCE}']
}))
")

    FIC_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "${GRAPH_BASE}/applications/${BP_OBJECT_ID}/federatedIdentityCredentials" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$FIC_BODY")

    FIC_RESP_BODY=$(echo "$FIC_RESPONSE" | sed '$d')
    FIC_STATUS=$(echo "$FIC_RESPONSE" | tail -n 1)

    if [[ "$FIC_STATUS" == "409" ]] || { [[ "$FIC_STATUS" == "400" ]] && echo "$FIC_RESP_BODY" | grep -q "already exist"; }; then
        echo "  ✅ FIC already exists — skipping."
    elif [[ "$FIC_STATUS" == "400" ]] && echo "$FIC_RESP_BODY" | grep -qi "claimsMatchingExpression\|not supported\|unknown property"; then
        echo "ERROR: Flexible FIC (claimsMatchingExpression) is not available in this tenant." >&2
        echo "       This feature requires the Azure Flexible FIC preview." >&2
        echo "       Workaround: Create a standard FIC with exact subject for one repo:" >&2
        echo "         subject: repo:${GITHUB_ORG}/<repo-name>:ref:refs/heads/main" >&2
        echo "       Then re-run with: --exact-subject (not yet implemented)" >&2
        exit 1
    elif [[ "$FIC_STATUS" != "201" && "$FIC_STATUS" != "200" ]]; then
        echo "ERROR: FIC creation failed (HTTP ${FIC_STATUS}):" >&2
        echo "$FIC_RESP_BODY" | python3 -m json.tool >&2 || echo "$FIC_RESP_BODY" >&2
        exit 1
    else
        echo "  ✅ Flexible FIC created: ${FIC_NAME}"
    fi

    FIC_ID=$(echo "$FIC_RESP_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || true)
fi

echo "  FIC ID: ${FIC_ID:-existing}"

# ─── Step 5/7: Assign Budget.Read app role ───────────────────────────────

echo ""
echo "🎫 Step 5/7 — Assigning app role..."
assign_app_role "Budget.Read"

# ─── Step 6/7: Add runner SPIFFE ID to mTLS allow list ───────────────────

if [[ -z "$RUNNER_SPIFFE_ID" ]]; then
    # Default SPIFFE ID for the GitHub runner
    RUNNER_SPIFFE_ID="spiffe://aim.microsoft.com/agent/${AGENT_NAME}"
fi

echo ""
echo "🔒 Step 6/7 — Updating mTLS allow list..."
update_mtls_allow_list "$RUNNER_SPIFFE_ID"

# ─── Step 7/7: Register in portal external-agent store ───────────────────

echo ""
echo "📋 Step 7/7 — Registering agent in portal..."
register_external_agent \
    "$AGENT_NAME" \
    "${INVOKE_URL:-http://localhost:8080}" \
    "GitHub Budget Reader (Actions)" \
    "github"

# ─── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  ✅  GitHub Actions Agent Provisioned"
echo "============================================================"
echo ""
echo "  Agent name:        ${AGENT_NAME}"
echo "  SPIFFE ID:         ${RUNNER_SPIFFE_ID}"
echo "  Entra Agent OID:   ${AGENT_OID}"
echo "  GitHub org:        ${GITHUB_ORG}"
echo "  FIC pattern:       repo:${GITHUB_ORG}/*"
echo ""
echo "Next: Add the following stanza to your RBAC policy YAML and deploy."
echo ""
echo "  federated_policies:"
echo "    - spiffe_id: \"${RUNNER_SPIFFE_ID}\""
echo "      trust_domain: \"aim.microsoft.com\""
echo "      name: \"${AGENT_NAME}\""
echo "      description: \"GitHub Actions agent (org: ${GITHUB_ORG})\""
echo "      ca:"
echo "        agent_state: enabled"
echo "        agent_tag: finance"
echo "      rules:"
echo "        - path: \"/budget/read\""
echo "          methods: [\"GET\", \"POST\"]"
echo "          action: allow"
echo "          require_jwt: true"
echo "          required_roles: [\"Budget.Read\"]"
echo "        - path: \"/budget/submit\""
echo "          methods: [\"*\"]"
echo "          action: deny"
echo ""
echo "Then set the following env vars on the self-hosted runner:"
echo ""
echo "  TOKEN_SOURCE=github_oidc"
echo "  ENTRA_OAUTH2_AUDIENCE=${BP_CLIENT_ID}"
echo "  ENTRA_AGENT_ID=${AGENT_CLIENT_ID}"
echo "  AZURE_TENANT_ID=${TENANT_ID}"
echo ""
