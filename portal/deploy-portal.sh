#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# AIM Prototype Platform — Control Panel Launcher
#
# This script:
#   1. Discovers deployed Container App FQDNs from your Azure environment
#   2. Queries SPIRE Server VM for health/registration info
#   3. Writes a portal-config.json with real endpoints
#   4. Launches the local control panel (Python FastAPI on :8550)
#
# Prerequisites:
#   - az CLI logged in (az login)
#   - azd environment provisioned (azd up has been run)
#   - Python 3.10+ with pip
#
# Usage:
#   ./portal/deploy-portal.sh                # auto-discover from azd env
#   ./portal/deploy-portal.sh --rg my-rg     # override resource group
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/portal-config.json"
PORTAL_PORT="${PORTAL_PORT:-8550}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

header() { echo -e "\n${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}${BOLD}  $1${NC}"; echo -e "${CYAN}${BOLD}═══════════════════════════════════════════════════════${NC}"; }
info()   { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err()    { echo -e "${RED}[ERR]${NC}   $1"; }
step()   { echo -e "${BOLD}  → $1${NC}"; }

# --- Parse args ---
RESOURCE_GROUP=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --rg)         RESOURCE_GROUP="$2"; shift 2 ;;
    --port)       PORTAL_PORT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--rg RESOURCE_GROUP] [--port PORT]"
      echo ""
      echo "  --rg RG   Override the Azure resource group"
      echo "  --port N  Override portal port (default: 8550)"
      exit 0 ;;
    *) err "Unknown option: $1"; exit 1 ;;
  esac
done

header "AIM Prototype Platform — Control Panel"
echo -e "  Agentic IAM for an Agentic Age"
echo -e "  Budget Backend PoC — SPIFFE/SPIRE mTLS Enforcement\n"

# Container App names (must match what azd/Bicep actually deploys)
APP_BUDGET_REPORT="budget-report"
APP_BUDGET_BACKEND="budget-backend"
APP_EMPLOYEE_MENUS="employee-menus"
APP_BUDGET_APPROVAL="budget-approval"
APP_ADMIN_CONTROL_PLANE="admin-control-plane"

###############################################################################
# Step 1: Discover Azure environment
###############################################################################

FQDN_BUDGET_REPORT=""
FQDN_BUDGET_BACKEND=""
FQDN_EMPLOYEE_MENUS=""
FQDN_BUDGET_APPROVAL=""
FQDN_ADMIN_CONTROL_PLANE=""
SPIRE_VM_IP=""
AZURE_LOCATION=""
AZURE_SUBSCRIPTION_ID=""

discover_endpoints() {
  header "Step 1: Discovering Azure Environment"

  # Try azd env first (run from repo root where .azure/ lives)
  if command -v azd &>/dev/null; then
    info "Found azd CLI — reading environment values..."
    AZD_ENV=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null || true)

    if [[ -z "$RESOURCE_GROUP" ]]; then
      RESOURCE_GROUP=$(echo "$AZD_ENV" | grep -E '^AZURE_RESOURCE_GROUP=' | cut -d= -f2 | tr -d '"' || true)
    fi
    AZURE_LOCATION=$(echo "$AZD_ENV" | grep -E '^AZURE_LOCATION=' | cut -d= -f2 | tr -d '"' || true)
    AZURE_SUBSCRIPTION_ID=$(echo "$AZD_ENV" | grep -E '^AZURE_SUBSCRIPTION_ID=' | cut -d= -f2 | tr -d '"' || true)
  fi

  # Fallback: try az CLI directly
  if [[ -z "$RESOURCE_GROUP" ]]; then
    info "No azd env found. Trying az CLI resource group discovery..."
    RESOURCE_GROUP=$(az group list --query "[?starts_with(name,'aim-') || starts_with(name,'rg-aim')].name" -o tsv 2>/dev/null | head -1 || true)
  fi

  if [[ -z "$RESOURCE_GROUP" ]]; then
    err "Could not discover resource group."
    err "Use --rg <name> to specify, or run 'azd up' first."
    exit 1
  fi

  info "Resource Group: ${BOLD}${RESOURCE_GROUP}${NC}"
  [[ -n "${AZURE_LOCATION}" ]] && info "Location: ${BOLD}${AZURE_LOCATION}${NC}"
  [[ -n "${AZURE_SUBSCRIPTION_ID}" ]] && info "Subscription: ${BOLD}${AZURE_SUBSCRIPTION_ID}${NC}"

  # Discover Container App FQDNs — prefer azd env URLs (set by azd deploy)
  header "Step 2: Discovering Container App Endpoints"

  # azd env already has SERVICE_*_ENDPOINT_URL for each agent — use those first
  FQDN_BUDGET_REPORT=$(echo "$AZD_ENV" | grep -E '^SERVICE_BUDGET_REPORT_ENDPOINT_URL=' | cut -d= -f2 | tr -d '"' || true)
  FQDN_BUDGET_BACKEND=$(echo "$AZD_ENV" | grep -E '^SERVICE_BUDGET_BACKEND_ENDPOINT_URL=' | cut -d= -f2 | tr -d '"' || true)
  FQDN_EMPLOYEE_MENUS=$(echo "$AZD_ENV" | grep -E '^SERVICE_EMPLOYEE_MENUS_ENDPOINT_URL=' | cut -d= -f2 | tr -d '"' || true)
  FQDN_BUDGET_APPROVAL=$(echo "$AZD_ENV" | grep -E '^SERVICE_BUDGET_APPROVAL_ENDPOINT_URL=' | cut -d= -f2 | tr -d '"' || true)
  FQDN_ADMIN_CONTROL_PLANE=$(echo "$AZD_ENV" | grep -E '^SERVICE_ADMIN_CONTROL_PLANE_ENDPOINT_URL=' | cut -d= -f2 | tr -d '"' || true)

  # If azd env URLs are present, use them directly
  if [[ -n "$FQDN_BUDGET_REPORT" ]]; then
    info "  budget-report:   ${GREEN}${FQDN_BUDGET_REPORT}${NC}"
    info "  budget-backend:  ${GREEN}${FQDN_BUDGET_BACKEND}${NC}"
    info "  employee-menus:  ${GREEN}${FQDN_EMPLOYEE_MENUS}${NC}"
    info "  budget-approval: ${GREEN}${FQDN_BUDGET_APPROVAL}${NC}"
    info "  admin-control-plane: ${GREEN}${FQDN_ADMIN_CONTROL_PLANE}${NC}"
  else
    # Fallback: query az containerapp show
    info "azd env URLs not found, querying Container Apps directly..."

    get_fqdn() {
      local app_name="$1"
      az containerapp show \
        --name "$app_name" \
        --resource-group "$RESOURCE_GROUP" \
        --query "properties.configuration.ingress.fqdn" \
        -o tsv 2>/dev/null || true
    }

    for pair in \
      "${APP_BUDGET_REPORT}:budget-report" \
      "${APP_BUDGET_BACKEND}:budget-backend" \
      "${APP_EMPLOYEE_MENUS}:employee-menus" \
      "${APP_BUDGET_APPROVAL}:budget-approval" \
      "${APP_ADMIN_CONTROL_PLANE}:admin-control-plane"; do

      app_name="${pair%%:*}"
      key="${pair##*:}"
      step "Querying ${app_name}..."

      fqdn=$(get_fqdn "$app_name")

      if [[ -n "$fqdn" && "$fqdn" != "None" ]]; then
        url="https://${fqdn}"
        info "  ${key}: ${GREEN}${url}${NC}"
        case "$key" in
          budget-report)   FQDN_BUDGET_REPORT="$url" ;;
          budget-backend)  FQDN_BUDGET_BACKEND="$url" ;;
          employee-menus)  FQDN_EMPLOYEE_MENUS="$url" ;;
          budget-approval) FQDN_BUDGET_APPROVAL="$url" ;;
          admin-control-plane) FQDN_ADMIN_CONTROL_PLANE="$url" ;;
        esac
      else
        warn "  ${key}: NOT FOUND (app may not be deployed)"
      fi
    done
  fi

  # Discover SPIRE Server VM
  header "Step 3: Discovering SPIRE Server VM"
  SPIRE_VM_IP=$(az vm list-ip-addresses \
    --resource-group "$RESOURCE_GROUP" \
    --query "[?starts_with(virtualMachine.name,'aim-spire') || starts_with(virtualMachine.name,'spire')].virtualMachine.network.publicIpAddresses[0].ipAddress" \
    -o tsv 2>/dev/null | head -1 || true)

  if [[ -n "$SPIRE_VM_IP" ]]; then
    info "SPIRE Server VM: ${GREEN}${SPIRE_VM_IP}${NC}"
  else
    warn "SPIRE Server VM not found. Some health details may be unavailable."
  fi
}

###############################################################################
# Step 2: Write config
###############################################################################

write_config() {
  header "Writing Portal Configuration"

  # Read Entra Agent Identity OIDs from azd env (if available)
  local ENTRA_BP_OID="" ENTRA_AGENT_OID_BR="" ENTRA_AGENT_OID_BB="" ENTRA_AGENT_OID_EM="" ENTRA_AGENT_OID_BA=""
  local ENTRA_AGENT_OID_ACP="" ENTRA_ID_BR="" ENTRA_ID_BB="" ENTRA_ID_EM="" ENTRA_ID_BA="" ENTRA_ID_ACP=""
  local MGMT_API_KEY=""
  local GRAPH_CID="" GRAPH_CSEC="" AZD_TENANT_ID=""
  if command -v azd &>/dev/null; then
    local AZD_VALS
    AZD_VALS=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null || true)
    ENTRA_BP_OID=$(echo "$AZD_VALS" | grep -E '^ENTRA_BLUEPRINT_OBJECT_ID=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_AGENT_OID_BR=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_BUDGET_REPORT=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_AGENT_OID_BB=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_BUDGET_BACKEND=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_AGENT_OID_EM=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_EMPLOYEE_MENUS=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_AGENT_OID_BA=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_BUDGET_APPROVAL=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_AGENT_OID_ACP=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_ID_BR=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_BUDGET_REPORT=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_ID_BB=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_BUDGET_BACKEND=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_ID_EM=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_EMPLOYEE_MENUS=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_ID_BA=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_BUDGET_APPROVAL=' | cut -d= -f2 | tr -d '"' || true)
    ENTRA_ID_ACP=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE=' | cut -d= -f2 | tr -d '"' || true)
    [[ -n "$ENTRA_ID_BR" ]] && info "Entra Agent IDs found — bridging into config"
    MGMT_API_KEY=$(echo "$AZD_VALS" | grep -E '^MGMT_API_KEY=' | cut -d= -f2 | tr -d '"' || true)
    GRAPH_CID=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENTID_CLIENT_ID=' | cut -d= -f2 | tr -d '"' || true)
    GRAPH_CSEC=$(echo "$AZD_VALS" | grep -E '^ENTRA_AGENTID_CLIENT_SECRET=' | cut -d= -f2 | tr -d '"' || true)
    AZD_TENANT_ID=$(echo "$AZD_VALS" | grep -E '^AZURE_TENANT_ID=' | cut -d= -f2 | tr -d '"' || true)
    [[ -n "$GRAPH_CID" ]] && info "Graph API credentials found — CA + risk operations enabled"
  fi

  # Build SPIFFE IDs — Entra Agent Identity Blueprint format
  local BP="${ENTRA_BP_OID:-placeholder-bp-oid}"
  local SPIFFE_BR="spiffe://aim.microsoft.com/ests/bp/${BP}/aid/${ENTRA_AGENT_OID_BR:-placeholder-report-oid}"
  local SPIFFE_BB="spiffe://aim.microsoft.com/ests/bp/${BP}/aid/${ENTRA_AGENT_OID_BB:-placeholder-backend-oid}"
  local SPIFFE_EM="spiffe://aim.microsoft.com/ests/bp/${BP}/aid/${ENTRA_AGENT_OID_EM:-placeholder-menus-oid}"
  local SPIFFE_BA="spiffe://aim.microsoft.com/ests/bp/${BP}/aid/${ENTRA_AGENT_OID_BA:-placeholder-approval-oid}"
  local SPIFFE_ACP="spiffe://aim.microsoft.com/ests/bp/${BP}/aid/${ENTRA_AGENT_OID_ACP:-placeholder-admin-oid}"

  cat > "$CONFIG_FILE" <<-EOF
{
  "mode": "live",
  "trust_domain": "aim.microsoft.com",
  "resource_group": "${RESOURCE_GROUP}",
  "location": "${AZURE_LOCATION:-northcentralus}",
  "portal_port": ${PORTAL_PORT},
  "agents": {
    "budget-report": {
      "name": "BudgetReport",
      "app_name": "${APP_BUDGET_REPORT}",
      "url": "${FQDN_BUDGET_REPORT}",
      "spiffe_id": "${SPIFFE_BR}",

      "entra_agent_id": "${ENTRA_ID_BR}",
      "role": "Read-only Caller",
      "entra_role": "BudgetFrontEnds"
    },
    "budget-backend": {
      "name": "BudgetBackend",
      "app_name": "${APP_BUDGET_BACKEND}",
      "url": "${FQDN_BUDGET_BACKEND}",
      "spiffe_id": "${SPIFFE_BB}",

      "entra_agent_id": "${ENTRA_ID_BB}",
      "role": "Protected Resource (MCP Server)",
      "entra_role": "—"
    },
    "employee-menus": {
      "name": "EmployeeMenus",
      "app_name": "${APP_EMPLOYEE_MENUS}",
      "url": "${FQDN_EMPLOYEE_MENUS}",
      "spiffe_id": "${SPIFFE_EM}",

      "entra_agent_id": "${ENTRA_ID_EM}",
      "role": "Blocked Caller",
      "entra_role": "Menus"
    },
    "budget-approval": {
      "name": "BudgetApproval",
      "app_name": "${APP_BUDGET_APPROVAL}",
      "url": "${FQDN_BUDGET_APPROVAL}",
      "spiffe_id": "${SPIFFE_BA}",

      "entra_agent_id": "${ENTRA_ID_BA}",
      "role": "Full-access Caller",
      "entra_role": "BudgetFrontEnds"
    }
  },
  "control_plane": {
    "name": "AdminControlPlane",
    "app_name": "${APP_ADMIN_CONTROL_PLANE}",
    "url": "${FQDN_ADMIN_CONTROL_PLANE}",
    "spiffe_id": "${SPIFFE_ACP}",
    "entra_agent_id": "${ENTRA_ID_ACP}",
    "role": "Dedicated Management Service"
  },
  "spire_server_ip": "${SPIRE_VM_IP}",
  "management_api_port": 9443,
  "mgmt_api_key": "${MGMT_API_KEY}"
}
EOF

  info "Config written to: ${CONFIG_FILE}"
}

###############################################################################
# Step 3: Install Python deps + launch portal
###############################################################################

install_and_launch() {
  header "Launching Control Panel"

  # Check Python
  if ! command -v python3 &>/dev/null; then
    err "Python 3 is required but not found. Install it first."
    exit 1
  fi

  PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  info "Python: ${PYTHON_VERSION}"

  # Install deps — try repo .venv first, then user install, then break-system-packages
  step "Installing dependencies..."
  if [[ -d "${REPO_ROOT}/.venv" ]]; then
    info "Using repo virtualenv at .venv"
    source "${REPO_ROOT}/.venv/bin/activate"
    pip install --quiet -r "${SCRIPT_DIR}/requirements.txt" 2>/dev/null
  elif pip3 install --quiet -r "${SCRIPT_DIR}/requirements.txt" 2>/dev/null; then
    true
  else
    pip3 install --quiet --break-system-packages -r "${SCRIPT_DIR}/requirements.txt" 2>/dev/null
  fi

  info "Dependencies installed."

  # Launch
  echo ""
  echo -e "${GREEN}${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
  echo -e "${GREEN}${BOLD}  │                                                 │${NC}"
  echo -e "${GREEN}${BOLD}  │   🛡️  AIM Prototype Platform Control Panel                 │${NC}"
  echo -e "${GREEN}${BOLD}  │                                                 │${NC}"
  echo -e "${GREEN}${BOLD}  │   http://localhost:${PORTAL_PORT}                        │${NC}"
  echo -e "${GREEN}${BOLD}  │                                                 │${NC}"
  echo -e "${GREEN}${BOLD}  │   Mode: ${CYAN}LIVE (Azure)${GREEN}${BOLD}                          │${NC}"
  echo -e "${GREEN}${BOLD}  │   Press Ctrl+C to stop                         │${NC}"
  echo -e "${GREEN}${BOLD}  │                                                 │${NC}"
  echo -e "${GREEN}${BOLD}  └─────────────────────────────────────────────────┘${NC}"
  echo ""

  # Open browser (macOS)
  if command -v open &>/dev/null; then
    ( sleep 2 && open "http://localhost:${PORTAL_PORT}" ) &
  fi

  # Start the server with Graph credentials (if available)
  export GRAPH_CLIENT_ID="${GRAPH_CID}"
  export GRAPH_CLIENT_SECRET="${GRAPH_CSEC}"
  export AZURE_TENANT_ID="${AZD_TENANT_ID:-${AZURE_TENANT_ID:-}}"
  exec python3 "${SCRIPT_DIR}/server.py" --port "$PORTAL_PORT" --config "$CONFIG_FILE"
}

###############################################################################
# Main
###############################################################################

discover_endpoints
write_config
install_and_launch
