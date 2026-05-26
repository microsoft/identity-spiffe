#!/bin/bash
# =============================================================================
# AIM Prototype Platform — Provision a Google-Hosted Cross-Cloud Agent
# =============================================================================
# Creates an Entra Agent Identity for a GCP-hosted agent, wires a Federated
# Identity Credential to the GCP service account, adds the agent's SPIFFE ID
# to the mTLS allow list, and registers invoke metadata in the portal.
#
# Prerequisites:
#   - az login  (DefaultAzureCredential for Graph API)
#   - gcloud auth login  (to look up GCP SA numeric unique ID)
#   - azd env select <env>  (correct environment)
#   - The Blueprint already exists (run create-entra-agent-ids.py first)
#   - The portal + admin-CP are running (for mTLS + external-agent registration)
#
# Required arguments / env vars:
#   --gcp-sa  GCP_SA_EMAIL        — GCP service account email
#
# Optional arguments / env vars:
#   --name    AGENT_NAME          — RBAC policy name (default: google-budget-reader)
#   --invoke-url  INVOKE_URL      — VPN-routable (private) URL of the GCE VM agent endpoint
#   --portal-url  PORTAL_URL      — Portal base URL (default: http://localhost:8550)
#   --mgmt-key    MGMT_API_KEY    — Admin API key (falls back to env / azd env)
#
# Usage examples:
#   ./scripts/add-google-agent.sh --gcp-sa my-sa@my-project.iam.gserviceaccount.com
#   ./scripts/add-google-agent.sh \
#       --gcp-sa my-sa@my-project.iam.gserviceaccount.com \
#       --invoke-url https://34.82.1.100:8443 \
#       --name google-budget-reader
#
# CRITICAL: The FIC subject MUST be the GCP SA numeric unique ID — NOT the email.
# Using the email causes AADSTS70021 at token exchange time.
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

FEDERATED_TRUST_DOMAIN="gcp.aim.microsoft.com"
GCP_OIDC_ISSUER="https://accounts.google.com"

# ─── Argument parsing ────────────────────────────────────────────────────────

GCP_SA_EMAIL=""
AGENT_NAME="google-budget-reader"
INVOKE_URL=""
PORTAL_URL="${PORTAL_URL:-http://localhost:8550}"
MGMT_KEY="${MGMT_API_KEY:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gcp-sa)       GCP_SA_EMAIL="$2"; shift 2 ;;
        --gcp-sa=*)     GCP_SA_EMAIL="${1#*=}"; shift ;;
        --name)         AGENT_NAME="$2"; shift 2 ;;
        --name=*)       AGENT_NAME="${1#*=}"; shift ;;
        --invoke-url)   INVOKE_URL="$2"; shift 2 ;;
        --invoke-url=*) INVOKE_URL="${1#*=}"; shift ;;
        --portal-url)   PORTAL_URL="$2"; shift 2 ;;
        --portal-url=*) PORTAL_URL="${1#*=}"; shift ;;
        --mgmt-key)     MGMT_KEY="$2"; shift 2 ;;
        --mgmt-key=*)   MGMT_KEY="${1#*=}"; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$GCP_SA_EMAIL" ]]; then
    echo "ERROR: --gcp-sa <service-account-email> is required." >&2
    exit 1
fi

echo ""
echo "============================================================"
echo "  AIM — Provision Google Cross-Cloud Agent: ${AGENT_NAME}"
echo "============================================================"
echo ""

# ─── Step 1: Discover Azure environment ──────────────────────────────────────

echo "📍 Step 1/7 — Discovering Azure environment..."
discover_azure_env || exit 1

# ─── Step 2: Get GCP SA numeric unique ID ────────────────────────────────────

echo ""
echo "🔍 Step 2/7 — Resolving GCP service account numeric unique ID..."
echo "  SA email: ${GCP_SA_EMAIL}"

if ! command -v gcloud >/dev/null 2>&1; then
    echo "ERROR: gcloud not found — cannot resolve GCP SA numeric unique ID." >&2
    echo "       Install Google Cloud SDK or set GCP_SA_UNIQUE_ID manually." >&2
    exit 1
fi

GCP_SA_UNIQUE_ID=$(gcloud iam service-accounts describe "$GCP_SA_EMAIL" \
    --format "value(uniqueId)" 2>/dev/null || true)

if [[ -z "$GCP_SA_UNIQUE_ID" ]]; then
    echo "ERROR: Could not resolve numeric unique ID for ${GCP_SA_EMAIL}." >&2
    echo "       Check that gcloud is authenticated and the SA exists." >&2
    exit 1
fi

echo "  GCP SA unique ID (FIC subject): ${GCP_SA_UNIQUE_ID}"

# ─── Step 3: Create Entra Agent Identity under Blueprint ─────────────────────

echo ""
echo "🤖 Step 3/7 — Creating Entra Agent Identity under Blueprint..."
acquire_graph_token || exit 1
create_agent_identity "${AGENT_NAME}" "ENTRA_AGENT_ID_GOOGLE_BUDGET_READER" || exit 1

echo "  Agent Identity OID:       ${AGENT_OID}"
echo "  Agent Identity client ID: ${AGENT_CLIENT_ID}"

# ─── Step 4: Create FIC on Blueprint for GCP OIDC ────────────────────────────

echo ""
echo "🔗 Step 4/7 — Creating Blueprint FIC for GCP OIDC..."
echo "  Issuer:   ${GCP_OIDC_ISSUER}"
echo "  Subject:  ${GCP_SA_UNIQUE_ID}  (numeric unique ID — NOT email)"
echo "  Audience: ${FIC_AUDIENCE}"

FIC_NAME="gcp-${AGENT_NAME}"

# Idempotency: check if FIC already exists before trying to create
EXISTING_FICS=$(curl -s \
    "${GRAPH_BASE}/applications/${BP_OBJECT_ID}/federatedIdentityCredentials" \
    -H "Authorization: Bearer ${GRAPH_TOKEN}" 2>/dev/null || true)
EXISTING_FIC_MATCH=$(echo "$EXISTING_FICS" | python3 -c "
import sys, json
try:
    fics = json.load(sys.stdin).get('value', [])
    match = [f for f in fics if f.get('subject') == '${GCP_SA_UNIQUE_ID}' or f.get('name') == '${FIC_NAME}']
    if match:
        print(match[0].get('id', 'exists'))
    else:
        print('')
except: print('')
" 2>/dev/null || true)

if [[ -n "$EXISTING_FIC_MATCH" ]]; then
    echo "  ✅ FIC already exists for this GCP service account — skipping."
    FIC_ID="$EXISTING_FIC_MATCH"
else
    FIC_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "${GRAPH_BASE}/applications/${BP_OBJECT_ID}/federatedIdentityCredentials" \
        -H "Authorization: Bearer ${GRAPH_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"${FIC_NAME}\",
            \"issuer\": \"${GCP_OIDC_ISSUER}\",
            \"subject\": \"${GCP_SA_UNIQUE_ID}\",
            \"audiences\": [\"${FIC_AUDIENCE}\"]
        }")

    FIC_BODY=$(echo "$FIC_RESPONSE" | sed '$d')
    FIC_STATUS=$(echo "$FIC_RESPONSE" | tail -n 1)

    if [[ "$FIC_STATUS" == "409" ]] || { [[ "$FIC_STATUS" == "400" ]] && echo "$FIC_BODY" | grep -q "already exist"; }; then
        echo "  ✅ FIC already exists — skipping."
    elif [[ "$FIC_STATUS" != "201" && "$FIC_STATUS" != "200" ]]; then
        echo "ERROR: FIC creation failed (HTTP ${FIC_STATUS}):" >&2
        echo "$FIC_BODY" | python3 -m json.tool >&2 || echo "$FIC_BODY" >&2
        exit 1
    else
        echo "  ✅ FIC created: ${FIC_NAME}"
    fi

    FIC_ID=$(echo "$FIC_BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || true)
fi
echo "  FIC ID: ${FIC_ID:-existing}"

# ─── Step 5: Assign Budget.Read app role to Agent Identity ───────────────────

echo ""
echo "🎫 Step 5/7 — Assigning app role..."
assign_app_role "Budget.Read"

# ─── Step 6: Add Google SPIFFE ID to mTLS allow list ─────────────────────────

SPIFFE_ID="spiffe://${FEDERATED_TRUST_DOMAIN}/ests/bp/${BP_OID:-$BP_CLIENT_ID}/aid/${AGENT_OID}"

echo ""
echo "🔒 Step 6/7 — Adding Google SPIFFE ID to mTLS allow list..."
echo "  SPIFFE ID: ${SPIFFE_ID}"
update_mtls_allow_list "$SPIFFE_ID"

# ─── Step 7: Register invoke metadata in portal external-agent store ─────────

echo ""
echo "📋 Step 7/7 — Registering agent in portal external-agent store..."
register_external_agent \
    "$AGENT_NAME" \
    "$INVOKE_URL" \
    "Google Budget Reader (GCP)" \
    "gcp"

# ─── Summary ─────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  ✅  Google Cross-Cloud Agent Provisioned"
echo "============================================================"
echo ""
echo "  Agent name:       ${AGENT_NAME}"
echo "  SPIFFE ID:        ${SPIFFE_ID}"
echo "  Entra Agent OID:  ${AGENT_OID}"
echo "  GCP SA:           ${GCP_SA_EMAIL}"
echo "  GCP SA unique ID: ${GCP_SA_UNIQUE_ID}  (FIC subject)"
echo ""
echo "Next: Add the following stanza to your RBAC policy YAML and deploy."
echo ""
echo "  federated_policies:"
echo "    - spiffe_id: \"${SPIFFE_ID}\""
echo "      trust_domain: \"${FEDERATED_TRUST_DOMAIN}\""
echo "      name: \"${AGENT_NAME}\""
echo "      description: \"Google-hosted cross-cloud agent (${GCP_SA_EMAIL})\""
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
echo "Then set the following env var in the GCE VM agent container:"
echo ""
echo "  TOKEN_SOURCE=google_oidc"
echo "  ENTRA_OAUTH2_AUDIENCE=${BP_CLIENT_ID}"
echo "  ENTRA_AGENT_ID=${AGENT_CLIENT_ID}"
echo "  AZURE_TENANT_ID=${TENANT_ID}"
echo ""
echo "Also register the SPIRE entry on the SPIRE server:"
echo "  -federatesWith ${FEDERATED_TRUST_DOMAIN#gcp.}"
echo "  -id ${SPIFFE_ID}"
echo ""
