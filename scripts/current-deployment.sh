#!/bin/bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Current Deployment Status
# =============================================================================
# Displays a comprehensive overview of the deployed Identity Research for Agent Management Using SPIFFE environment:
#   - Azure subscription + resource group + credit/spending
#   - Container Apps (agents) status + endpoints
#   - SPIRE Server VM status
#   - GitHub Runner VM status (if deployed)
#   - Entra identity configuration (Blueprint, Agent Identities)
#   - Federated Identity Credentials
#   - RBAC policy summary
#   - Portal + mTLS allow list
#   - Cross-cloud agents (Google, GitHub)
#
# Usage:
#   ./scripts/current-deployment.sh
#   ./scripts/current-deployment.sh --json   # JSON output (future)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# shellcheck source=scripts/lib/azure-helpers.sh
source "${SCRIPT_DIR}/lib/azure-helpers.sh"
# shellcheck source=scripts/lib/deploy-config.sh
source "${SCRIPT_DIR}/lib/deploy-config.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

ok() { printf "${GREEN}✅${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}⚠️${NC}  %s\n" "$*"; }
fail() { printf "${RED}❌${NC} %s\n" "$*"; }
info() { printf "${CYAN}ℹ${NC}  %s\n" "$*"; }
header() {
    echo ""
    printf "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
    printf "${BOLD}  %s${NC}\n" "$*"
    printf "${BOLD}${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
}
subheader() {
    echo ""
    printf "${BOLD}  ─── %s ───${NC}\n" "$*"
}

# ─── Load environment ────────────────────────────────────────────────────────

AZD_ENV=$(azd_env_load)

if [[ -z "$AZD_ENV" ]]; then
    fail "No azd environment found. Run: azd env select <env>"
    exit 1
fi

ENV_NAME=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_ENV_NAME")
SUBSCRIPTION_ID=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_SUBSCRIPTION_ID")
TENANT_ID=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_TENANT_ID")
if [[ -z "$TENANT_ID" ]]; then
    TENANT_ID=$(az account show --query tenantId -o tsv 2>/dev/null || true)
fi

# Discover resource group — try multiple strategies
# 1. Check azd env for explicit AZURE_RESOURCE_GROUP
RG_NAME=$(azd_env_get_from_blob "$AZD_ENV" "AZURE_RESOURCE_GROUP")
# 2. Search by project tag (works across env renames)
if [[ -z "$RG_NAME" ]]; then
    RG_NAME=$(az group list --query "[?tags.project=='aim-prototype-platform'] | [0].name" -o tsv 2>/dev/null || true)
fi
# 3. Search by azd-env-name tag matching current env
if [[ -z "$RG_NAME" ]]; then
    RG_NAME=$(az group list --query "[?tags.\"azd-env-name\"=='${ENV_NAME}'] | [0].name" -o tsv 2>/dev/null || true)
fi
# 4. Search for any RG with Identity Research for Agent Management Using SPIFFE container apps
if [[ -z "$RG_NAME" ]]; then
    RG_NAME=$(az group list --query "[?contains(name,'aim')] | [0].name" -o tsv 2>/dev/null || true)
fi
# 5. Last resort: convention
if [[ -z "$RG_NAME" ]]; then
    RG_NAME="rg-${ENV_NAME}"
fi
LOCATION=$(az group show -n "$RG_NAME" --query location -o tsv 2>/dev/null || echo "unknown")

# =============================================================================
header "Identity Research for Agent Management Using SPIFFE Deployment Status: ${ENV_NAME}"
# =============================================================================

echo ""
printf "  ${DIM}Timestamp:${NC}      $(date '+%Y-%m-%d %H:%M:%S %Z')\n"
printf "  ${DIM}Environment:${NC}    ${ENV_NAME}\n"
printf "  ${DIM}Resource Group:${NC} ${RG_NAME}\n"
printf "  ${DIM}Location:${NC}       ${LOCATION}\n"
printf "  ${DIM}Subscription:${NC}   ${SUBSCRIPTION_ID}\n"
printf "  ${DIM}Tenant:${NC}         ${TENANT_ID}\n"

# ─── Subscription & Spending ─────────────────────────────────────────────────

subheader "Subscription & Spending"

SUB_NAME=$(az account show --query name -o tsv 2>/dev/null || echo "unknown")
SUB_STATE=$(az account show --query state -o tsv 2>/dev/null || echo "unknown")
printf "  Subscription:  ${SUB_NAME}\n"

if [[ "$SUB_STATE" == "Enabled" ]]; then
    ok "Subscription state: ${SUB_STATE}"
else
    fail "Subscription state: ${SUB_STATE}"
fi

# Try to get current month spending
MONTH_START=$(date -u '+%Y-%m-01')
MONTH_END=$(date -u '+%Y-%m-%dT23:59:59Z' 2>/dev/null || date -u '+%Y-%m-%d')
COST=$(az consumption usage list \
    --start-date "$MONTH_START" --end-date "$MONTH_END" \
    --query "[?contains(instanceId, '${RG_NAME}')].pretaxCost | sum(@)" \
    -o tsv 2>/dev/null || true)

if [[ -n "$COST" && "$COST" != "null" && "$COST" != "0" ]]; then
    printf "  Current month spend (this RG): ${YELLOW}\$%.2f${NC}\n" "$COST"
else
    # Fallback: try Cost Management API
    COST_MGMT=$(az costmanagement query \
        --type ActualCost \
        --scope "/subscriptions/${SUBSCRIPTION_ID}" \
        --timeframe MonthToDate \
        --query "properties.rows[?[2]=='${RG_NAME}'] | [0][0]" \
        -o tsv 2>/dev/null || true)
    if [[ -n "$COST_MGMT" && "$COST_MGMT" != "null" ]]; then
        printf "  Current month spend (this RG): ${YELLOW}\$%.2f${NC}\n" "$COST_MGMT"
    else
        info "Spending data not available (may need Cost Management Reader role)"
    fi
fi

# Credit balance (for sponsored/MSDN subscriptions)
CREDIT=$(az consumption budget list --query "[0].amount" -o tsv 2>/dev/null || true)
if [[ -n "$CREDIT" && "$CREDIT" != "null" ]]; then
    printf "  Budget limit: \$${CREDIT}\n"
fi

# ─── Container Apps ──────────────────────────────────────────────────────────

subheader "Container Apps (Agents)"

CA_ENV_NAME=$(az containerapp env list -g "$RG_NAME" --query "[0].name" -o tsv 2>/dev/null || true)

if [[ -z "$CA_ENV_NAME" ]]; then
    fail "No Container Apps environment found in ${RG_NAME}"
else
    printf "  ${DIM}Environment:${NC} ${CA_ENV_NAME}\n"
    echo ""

    # Get each app's status via revision query (the correct API path)
    for app_name in $(az containerapp list -g "$RG_NAME" --query "[].name" -o tsv 2>/dev/null || true); do
        APP_INFO=$(az containerapp show -g "$RG_NAME" -n "$app_name" \
            --query "{fqdn:properties.configuration.ingress.fqdn, prov:properties.provisioningState, latest:properties.latestRevisionName}" \
            -o json 2>/dev/null || echo "{}")
        FQDN=$(echo "$APP_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('fqdn',''))" 2>/dev/null || true)
        PROV_STATE=$(echo "$APP_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('prov','?'))" 2>/dev/null || true)

        REV_INFO=$(az containerapp revision list -g "$RG_NAME" -n "$app_name" \
            --query "[?properties.active].{name:name, replicas:properties.replicas, state:properties.runningState}" \
            -o json 2>/dev/null || echo "[]")
        REPLICA_COUNT=$(echo "$REV_INFO" | python3 -c "import sys,json; r=json.load(sys.stdin); print(sum(x.get('replicas',0) for x in r))" 2>/dev/null || echo "0")
        RUNNING_STATE=$(echo "$REV_INFO" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r[0].get('state','?') if r else '?')" 2>/dev/null || echo "?")

        if [[ "$RUNNING_STATE" == *"Running"* && "$REPLICA_COUNT" -gt 0 ]]; then
            ok "${app_name}: ${RUNNING_STATE} (${REPLICA_COUNT} replica(s))"
        elif [[ "$REPLICA_COUNT" == "0" ]]; then
            warn "${app_name}: scaled to zero (${PROV_STATE})"
        else
            warn "${app_name}: ${RUNNING_STATE} (${REPLICA_COUNT} replica(s), ${PROV_STATE})"
        fi
        if [[ -n "$FQDN" ]]; then
            printf "    ${DIM}https://${FQDN}${NC}\n"
        fi
    done
fi

# ─── Virtual Machines ────────────────────────────────────────────────────────

subheader "Virtual Machines"

VMS=$(az vm list -g "$RG_NAME" --query "[].{name:name, size:hardwareProfile.vmSize}" -o json 2>/dev/null || echo "[]")

if [[ "$VMS" == "[]" ]]; then
    info "No VMs found"
else
    for vm_name in $(echo "$VMS" | python3 -c "import sys,json; [print(v['name']) for v in json.load(sys.stdin)]" 2>/dev/null); do
        VM_STATUS=$(az vm get-instance-view -g "$RG_NAME" -n "$vm_name" \
            --query "instanceView.statuses[?starts_with(code,'PowerState/')].displayStatus | [0]" \
            -o tsv 2>/dev/null || echo "unknown")
        VM_SIZE=$(echo "$VMS" | python3 -c "import sys,json; [print(v['size']) for v in json.load(sys.stdin) if v['name']=='${vm_name}']" 2>/dev/null || echo "?")
        VM_IP=$(az vm show -g "$RG_NAME" -n "$vm_name" -d --query publicIps -o tsv 2>/dev/null || echo "none")
        VM_PRIVATE=$(az vm show -g "$RG_NAME" -n "$vm_name" -d --query privateIps -o tsv 2>/dev/null || echo "none")

        if [[ "$VM_STATUS" == *"running"* ]]; then
            ok "${vm_name}: ${VM_STATUS} (${VM_SIZE})"
        elif [[ "$VM_STATUS" == *"deallocated"* ]]; then
            warn "${vm_name}: ${VM_STATUS} (${VM_SIZE})"
        else
            fail "${vm_name}: ${VM_STATUS} (${VM_SIZE})"
        fi
        printf "    Public IP:  ${VM_IP}\n"
        printf "    Private IP: ${VM_PRIVATE}\n"
    done
fi

# ─── Entra Identity ──────────────────────────────────────────────────────────

subheader "Entra Identity (Agent Identities)"

BP_CLIENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_CLIENT_ID")
if [[ -z "$BP_CLIENT_ID" ]]; then
    BP_CLIENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_APP_ID")
fi
if [[ -z "$BP_CLIENT_ID" ]]; then
    BP_CLIENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_OAUTH2_AUDIENCE")
fi
BP_OBJECT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_BLUEPRINT_OBJECT_ID")

if [[ -n "$BP_CLIENT_ID" ]]; then
    ok "Blueprint App ID: ${BP_CLIENT_ID}"
    printf "    Object ID:  ${BP_OBJECT_ID:-unknown}\n"
else
    fail "Blueprint not found in azd env"
fi

# List Agent Identities — paginate through all service principals
GRAPH_TOKEN=$(az account get-access-token --resource "https://graph.microsoft.com" --query accessToken -o tsv 2>/dev/null || true)

if [[ -n "$GRAPH_TOKEN" && -n "$BP_CLIENT_ID" ]]; then
    # Fetch all SPs by following @odata.nextLink pagination
    AGENTS_RESPONSE=$(python3 -c "
import json, sys
try:
    import urllib.request
    token = '${GRAPH_TOKEN}'
    bp = '${BP_CLIENT_ID}'
    agents = []
    url = 'https://graph.microsoft.com/beta/servicePrincipals?\$count=true'
    while url:
        req = urllib.request.Request(url, headers={
            'Authorization': f'Bearer {token}',
            'ConsistencyLevel': 'eventual',
        })
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        for v in data.get('value', []):
            if v.get('agentIdentityBlueprintId') == bp:
                agents.append(v)
        url = data.get('@odata.nextLink', '')
    print(json.dumps(agents))
except Exception as e:
    print(json.dumps([]))
    print(str(e), file=sys.stderr)
" 2>/dev/null || echo "[]")

    echo "$AGENTS_RESPONSE" | python3 -c "
import sys, json
try:
    agents = json.load(sys.stdin)
    if agents:
        for a in agents:
            name = a.get('displayName', '?')
            oid = a.get('id', '?')
            app_id = a.get('appId', '?')
            print(f'  ✅ {name}')
            print(f'      OID: {oid}')
            print(f'      App ID: {app_id}')
    else:
        print('  (no Agent Identities found under Blueprint)')
except Exception as e:
    print(f'  ⚠️  Could not query Graph API: {e}')
" 2>/dev/null || warn "Could not parse Graph response"

    # List FICs on Blueprint
    subheader "Federated Identity Credentials (FICs)"

    if [[ -n "$BP_OBJECT_ID" ]]; then
        FICS=$(curl -s \
            "https://graph.microsoft.com/beta/applications/${BP_OBJECT_ID}/federatedIdentityCredentials" \
            -H "Authorization: Bearer ${GRAPH_TOKEN}" 2>/dev/null || true)

        echo "$FICS" | python3 -c "
import sys, json
try:
    fics = json.load(sys.stdin).get('value', [])
    if fics:
        for f in fics:
            name = f.get('name', '?')
            issuer = f.get('issuer', '?')
            subject = f.get('subject', '')
            expr = f.get('claimsMatchingExpression', {})
            print(f'  ✅ {name}')
            print(f'      Issuer: {issuer}')
            if subject:
                print(f'      Subject: {subject}')
            if expr:
                print(f'      Expression: {expr.get(\"value\", \"?\")}')
            audiences = f.get('audiences', [])
            if audiences:
                print(f'      Audiences: {audiences}')
    else:
        print('  (no FICs found)')
except Exception as e:
    print(f'  ⚠️  Could not parse FIC response: {e}')
" 2>/dev/null || warn "Could not query FICs"
    fi
else
    warn "No Graph token available — skipping Entra queries (run 'az login')"
fi

# ─── RBAC Policy ─────────────────────────────────────────────────────────────

subheader "RBAC Policy (spiffe-rbac-policy.yaml)"

POLICY_FILE="${REPO_ROOT}/src/spiffe-proxy/config/spiffe-rbac-policy.yaml"
if [[ -f "$POLICY_FILE" ]]; then
    python3 -c "
import yaml, sys
with open('${POLICY_FILE}') as f:
    policy = yaml.safe_load(f)

version = policy.get('version', '?')
trust_domain = policy.get('trust_domain', '?')
default_action = policy.get('default_action', '?')
domestic = policy.get('policies', [])
federated = policy.get('federated_policies', [])
admin_gov = policy.get('admin_governance', {})

print(f'  Version: {version}')
print(f'  Trust domain: {trust_domain}')
print(f'  Default action: {default_action}')
print(f'  Admin governance: {\"enabled\" if admin_gov.get(\"enabled\") else \"disabled\"}')
print(f'  Domestic policies: {len(domestic)}')
for p in domestic:
    name = p.get('name', p.get('spiffe_id', '?'))
    rules = len(p.get('rules', []))
    print(f'    • {name} ({rules} rules)')
print(f'  Federated policies: {len(federated)}')
for p in federated:
    name = p.get('name', '?')
    td = p.get('trust_domain', '?')
    rules = len(p.get('rules', []))
    has_tags = any(r.get('required_tags') for r in p.get('rules', []))
    tag_note = ' [has required_tags]' if has_tags else ''
    print(f'    • {name} (domain: {td}, {rules} rules{tag_note})')
" 2>/dev/null || warn "Could not parse RBAC policy"
else
    fail "RBAC policy file not found: ${POLICY_FILE}"
fi

# ─── Portal & mTLS ──────────────────────────────────────────────────────────

subheader "Portal & mTLS"

PORTAL_URL=$(azd_env_get_from_blob "$AZD_ENV" "SERVICE_PORTAL_ENDPOINT_URL")
MGMT_KEY=$(azd_env_get_from_blob "$AZD_ENV" "MGMT_API_KEY")

if [[ -n "$PORTAL_URL" ]]; then
    printf "  Portal URL: ${PORTAL_URL}\n"

    # Check portal health
    PORTAL_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${PORTAL_URL}/health" 2>/dev/null || echo "unreachable")
    if [[ "$PORTAL_STATUS" == "200" ]]; then
        ok "Portal health: OK"
    else
        warn "Portal health: ${PORTAL_STATUS}"
    fi
else
    info "Portal URL not in azd env"
fi

# mTLS allow list
if [[ -n "$MGMT_KEY" && -n "$PORTAL_URL" ]]; then
    MTLS_RESPONSE=$(curl -s --max-time 5 \
        -H "X-Spiffe-Admin-Key: ${MGMT_KEY}" \
        "${PORTAL_URL}/api/mtls-policy" 2>/dev/null || true)

    if [[ -n "$MTLS_RESPONSE" ]]; then
        echo "$MTLS_RESPONSE" | python3 -c "
import sys, json
try:
    ids = json.load(sys.stdin).get('allowed_ids', [])
    print(f'  mTLS allow list: {len(ids)} SPIFFE IDs')
    for sid in ids:
        print(f'    • {sid}')
except:
    print('  ⚠️  Could not parse mTLS response')
" 2>/dev/null || true
    fi

    # External agents
    EXT_AGENTS=$(curl -s --max-time 5 \
        -H "X-Spiffe-Admin-Key: ${MGMT_KEY}" \
        "${PORTAL_URL}/api/external-agents" 2>/dev/null || true)

    if [[ -n "$EXT_AGENTS" && "$EXT_AGENTS" != "[]" ]]; then
        subheader "External Agents (Portal Store)"
        echo "$EXT_AGENTS" | python3 -c "
import sys, json
try:
    agents = json.load(sys.stdin)
    if isinstance(agents, list):
        for a in agents:
            name = a.get('name', '?')
            platform = a.get('hosting_platform', '?')
            transport = a.get('transport', '?')
            url = a.get('invoke_url', '?')
            print(f'  • {name} (platform: {platform}, transport: {transport})')
            print(f'    URL: {url}')
except:
    pass
" 2>/dev/null || true
    fi
fi

# ─── Cross-Cloud Status ─────────────────────────────────────────────────────

subheader "Cross-Cloud Federation"

# Detect cross-cloud agents from multiple sources:
# 1. Agent Identities in Graph (already queried above)
# 2. FICs on Blueprint (Google issuer = google.com, GitHub issuer = github)
# 3. azd env vars (may be empty even when deployed)
# 4. RBAC policy federated entries

# Google — check FIC issuer for accounts.google.com
_google_fic="false"
if [[ -n "${FICS:-}" ]]; then
    _google_fic=$(echo "$FICS" | python3 -c "
import sys, json
try:
    fics = json.load(sys.stdin).get('value', [])
    print('true' if any('accounts.google.com' in f.get('issuer','') for f in fics) else 'false')
except: print('false')
" 2>/dev/null || echo "false")
fi

GOOGLE_AGENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_AGENT_ID_GOOGLE_BUDGET_READER")
if [[ "$_google_fic" == "true" ]]; then
    ok "Google (google-budget-reader): deployed"
    if [[ -n "$GOOGLE_AGENT_ID" ]]; then
        printf "    Agent OID: ${GOOGLE_AGENT_ID}\n"
    else
        printf "    ${DIM}(FIC exists but agent OID not in azd env)${NC}\n"
    fi
else
    info "Google: not provisioned (use --google flag)"
fi

# GitHub — check FIC issuer for token.actions.githubusercontent.com
_github_fic="false"
if [[ -n "${FICS:-}" ]]; then
    _github_fic=$(echo "$FICS" | python3 -c "
import sys, json
try:
    fics = json.load(sys.stdin).get('value', [])
    print('true' if any('token.actions.githubusercontent.com' in f.get('issuer','') for f in fics) else 'false')
except: print('false')
" 2>/dev/null || echo "false")
fi

GITHUB_AGENT_ID=$(azd_env_get_from_blob "$AZD_ENV" "ENTRA_AGENT_ID_GITHUB_BUDGET_READER")
if [[ "$_github_fic" == "true" ]]; then
    ok "GitHub (github-budget-reader): deployed"
    if [[ -n "$GITHUB_AGENT_ID" ]]; then
        printf "    Agent OID: ${GITHUB_AGENT_ID}\n"
    else
        printf "    ${DIM}(FIC exists but agent OID not in azd env)${NC}\n"
    fi
else
    info "GitHub: not provisioned (use --github flag)"
fi

# GitHub runner VM
GITHUB_RUNNER_IP=$(az vm show -g "$RG_NAME" -n "github-runner" -d --query publicIps -o tsv 2>/dev/null || true)
if [[ -n "$GITHUB_RUNNER_IP" ]]; then
    RUNNER_STATUS=$(az vm get-instance-view -g "$RG_NAME" -n "github-runner" \
        --query "instanceView.statuses[?starts_with(code,'PowerState/')].displayStatus | [0]" \
        -o tsv 2>/dev/null || echo "unknown")
    if [[ "$RUNNER_STATUS" == *"running"* ]]; then
        ok "GitHub Runner VM: ${RUNNER_STATUS} (${GITHUB_RUNNER_IP})"
    else
        warn "GitHub Runner VM: ${RUNNER_STATUS} (${GITHUB_RUNNER_IP})"
    fi
fi

# ─── Networking ──────────────────────────────────────────────────────────────

subheader "Networking"

VNETS=$(az network vnet list -g "$RG_NAME" --query "[].{name:name, addressSpace:addressSpace.addressPrefixes[0], subnets:subnets[].name}" -o json 2>/dev/null || echo "[]")

echo "$VNETS" | python3 -c "
import sys, json
try:
    vnets = json.load(sys.stdin)
    for v in vnets:
        name = v.get('name', '?')
        cidr = v.get('addressSpace', '?')
        subnets = v.get('subnets', [])
        print(f'  VNet: {name} ({cidr})')
        for s in subnets:
            print(f'    Subnet: {s}')
except:
    print('  (no VNets found)')
" 2>/dev/null || true

# VPN Gateway
VPN_GW=$(az network vnet-gateway list -g "$RG_NAME" --query "[0].name" -o tsv 2>/dev/null || true)
if [[ -n "$VPN_GW" ]]; then
    VPN_STATUS=$(az network vnet-gateway show -g "$RG_NAME" -n "$VPN_GW" --query "provisioningState" -o tsv 2>/dev/null || echo "unknown")
    ok "VPN Gateway: ${VPN_GW} (${VPN_STATUS})"
else
    info "VPN Gateway: none (no cross-cloud VPN)"
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

header "Summary"

echo ""
TOTAL_CAS=$(az containerapp list -g "$RG_NAME" --query "length(@)" -o tsv 2>/dev/null || echo "0")
TOTAL_VMS=$(echo "$VMS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")

printf "  Container Apps:  ${TOTAL_CAS}\n"
printf "  Virtual Machines: ${TOTAL_VMS}\n"
printf "  Environment:     ${ENV_NAME}\n"
printf "  Region:          ${LOCATION}\n"

GOOGLE_STATUS="not deployed"
[[ "$_google_fic" == "true" ]] && GOOGLE_STATUS="deployed"
GITHUB_STATUS="not deployed"
[[ "$_github_fic" == "true" ]] && GITHUB_STATUS="deployed"

printf "  Google agent:    ${GOOGLE_STATUS}\n"
printf "  GitHub agent:    ${GITHUB_STATUS}\n"
echo ""
