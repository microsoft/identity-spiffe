#!/bin/bash
# =============================================================================
# AIM Prototype Platform — Full Teardown
# =============================================================================
# Tears down all Azure resources AND cleans up artifacts that azd down misses:
#   1. Deletes VPN Gateway resources (expensive, ~$140/mo, may not be in azd)
#   2. Runs azd down --force --purge
#   3. Clears stale azd env variables
#   4. Optionally tears down GCP resources (--google)
#
# Usage:
#   ./scripts/teardown.sh              # full teardown
#   ./scripts/teardown.sh --google     # also tear down GCP cross-cloud resources
#   ./scripts/teardown.sh --skip-azd   # clean up env only (azd down already run)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKIP_AZD=false
GOOGLE=false

for arg in "$@"; do
    case $arg in
        --skip-azd) SKIP_AZD=true ;;
        --google)   GOOGLE=true ;;
        --help|-h)
            echo "Usage: ./scripts/teardown.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-azd   Skip azd down (clean up env only)"
            echo "  --google     Also tear down GCP cross-cloud resources"
            echo "  --help       Show this help"
            exit 0
            ;;
    esac
done

echo ""
echo "============================================="
echo "  AIM Prototype Platform — Full Teardown"
echo "============================================="
echo ""

# ─── Load azd env ─────────────────────────────────────────────────────────

AZURE_ENV_NAME=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null | grep "^AZURE_ENV_NAME=" | cut -d'=' -f2 | tr -d '"' || true)
RG_NAME="rg-${AZURE_ENV_NAME}"

# ─── Step 1: Delete VPN Gateway resources ─────────────────────────────────
# VPN Gateways cost ~$140/mo and may have been deployed via
# deploy-azure-vpn.sh (az deployment sub create), so azd down may not
# remove them. Delete explicitly in dependency order.

echo "🔌 Step 1: Cleaning up Azure VPN Gateway resources..."

if [ -n "$AZURE_ENV_NAME" ] && az group exists -n "$RG_NAME" 2>/dev/null | grep -q true; then
    # Discover VPN resources by type within the resource group
    VPN_CONN=$(az network vpn-connection list -g "$RG_NAME" --query "[].name" -o tsv 2>/dev/null || true)
    VPN_GW=$(az network vnet-gateway list -g "$RG_NAME" --query "[].name" -o tsv 2>/dev/null || true)
    LOCAL_GW=$(az network local-gateway list -g "$RG_NAME" --query "[].name" -o tsv 2>/dev/null || true)

    if [ -n "$VPN_CONN" ] || [ -n "$VPN_GW" ] || [ -n "$LOCAL_GW" ]; then
        # Delete in dependency order: connection → VPN gateway → local gateway → PIP
        for conn in $VPN_CONN; do
            echo "   Deleting VPN connection: $conn ..."
            az network vpn-connection delete -g "$RG_NAME" -n "$conn" --no-wait 2>/dev/null || true
        done

        for gw in $VPN_GW; do
            echo "   Deleting VPN gateway: $gw (this takes a few minutes)..."
            az network vnet-gateway delete -g "$RG_NAME" -n "$gw" --no-wait 2>/dev/null || true
        done

        for lgw in $LOCAL_GW; do
            echo "   Deleting local network gateway: $lgw ..."
            az network local-gateway delete -g "$RG_NAME" -n "$lgw" --no-wait 2>/dev/null || true
        done

        # Delete VPN-associated public IPs (named *-pip by vpn-gateway.bicep)
        VPN_PIPS=$(az network public-ip list -g "$RG_NAME" \
            --query "[?contains(name,'vpn')].name" -o tsv 2>/dev/null || true)
        for pip in $VPN_PIPS; do
            echo "   Deleting public IP: $pip ..."
            az network public-ip delete -g "$RG_NAME" -n "$pip" --no-wait 2>/dev/null || true
        done

        echo "   ✅ VPN cleanup initiated (deletions running async)"
    else
        echo "   ⏭  No VPN resources found in $RG_NAME"
    fi
else
    echo "   ⏭  Resource group $RG_NAME not found or env not set — skipping"
fi
echo ""

# ─── Step 2: azd down --force --purge ─────────────────────────────────────

if [ "$SKIP_AZD" = false ]; then
    echo "🗑  Step 2: Running azd down --force --purge..."
    cd "$REPO_ROOT" && azd down --force --purge 2>&1
    echo ""
else
    echo "⏭  Step 2: Skipped (--skip-azd)"
    echo ""
fi

# ─── Step 3: Clear stale azd env variables ────────────────────────────────

AZD_ENV=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null || true)
echo "🧽 Step 3: Clearing stale azd env variables..."

STALE_VARS=(
    "FOUNDRY_AGENT_ID_BUDGET_REPORT"
    "FOUNDRY_AGENT_ID_BUDGET_BACKEND"
    "FOUNDRY_AGENT_ID_EMPLOYEE_MENUS"
    "FOUNDRY_AGENT_ID_BUDGET_APPROVAL"
    "AIFOUNDRY_PROJECT_ENDPOINT"
    "GCP_PROJECT"
    "GCP_BILLING_ID"
    "GCP_REGION"
    "GCP_VPN_PUBLIC_IP"
    "VPN_SHARED_KEY"
    "VPN_GATEWAY_PUBLIC_IP"
    "ENTRA_AGENT_ID_GOOGLE_BUDGET_READER"
)

for var in "${STALE_VARS[@]}"; do
    CURRENT=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null | grep "^${var}=" | cut -d'=' -f2 | tr -d '"' || true)
    if [ -n "$CURRENT" ]; then
        cd "$REPO_ROOT" && azd env set "$var" "" 2>/dev/null
        echo "   Cleared: ${var}"
    fi
done
echo ""

# ─── Step 4: Google teardown (optional) ───────────────────────────────────

if [ "$GOOGLE" = true ]; then
    echo "☁️  Step 4: Tearing down GCP cross-cloud resources..."
    if [ -f "$SCRIPT_DIR/teardown-google.sh" ]; then
        bash "$SCRIPT_DIR/teardown-google.sh"
    else
        echo "   ❌ scripts/teardown-google.sh not found"
        exit 1
    fi
    echo ""
else
    echo "⏭  Step 4: Google teardown skipped (use --google to include)"
    echo ""
fi

# ─── Step 5: Wait for soft-delete propagation ─────────────────────────────

echo "⏳ Step 5: Waiting 30s for resource soft-delete propagation..."
echo "   (Prevents IfMatchPreconditionFailed on next deploy)"
sleep 30
echo "   Done."
echo ""

echo "============================================="
echo "✅ TEARDOWN COMPLETE"
echo "============================================="
echo ""
echo "Next steps:"
echo "  ./deploy.sh              # Full fresh deploy"
echo "  azd env set AZURE_LOCATION westus  # Change region (if needed)"
echo ""
