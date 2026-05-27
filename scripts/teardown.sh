#!/bin/bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Full Teardown
# =============================================================================
# Tears down all Azure resources AND cleans up artifacts that azd down misses:
#   1. Deletes VPN Gateway resources (expensive, ~$140/mo, may not be in azd)
#   2. Runs azd down --force --purge
#   3. Clears stale azd env variables
#   4. Optionally tears down GCP resources (--google)
#   5. Optionally purges Entra directory objects (--purge-entra)
#
# Usage:
#   ./scripts/teardown.sh                  # full Azure teardown, Entra preserved
#   ./scripts/teardown.sh --google         # also tear down GCP cross-cloud resources
#   ./scripts/teardown.sh --skip-azd       # clean up env only (azd down already run)
#   ./scripts/teardown.sh --purge-entra    # also delete Entra apps + portal groups
#                                          # (Blueprint, Provisioner, Portal,
#                                          #  Security Portal Mock, Admin/Viewer
#                                          #  groups). Required for a true
#                                          #  clean-room first-run test.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SKIP_AZD=false
GOOGLE=false
PURGE_ENTRA=false

for arg in "$@"; do
    case $arg in
        --skip-azd)     SKIP_AZD=true ;;
        --google)       GOOGLE=true ;;
        --purge-entra)  PURGE_ENTRA=true ;;
        --help|-h)
            echo "Usage: ./scripts/teardown.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-azd       Skip azd down (clean up env only)"
            echo "  --google         Also tear down GCP cross-cloud resources"
            echo "  --purge-entra    Also delete Entra directory objects:"
            echo "                   Blueprint app (+ child Agent Identities + FICs),"
            echo "                   Provisioner app, Portal app, Security Portal Mock app,"
            echo "                   and the Administrators/Viewers groups."
            echo "                   Required for a true clean-room first-run test."
            echo "  --help           Show this help"
            exit 0
            ;;
    esac
done

echo ""
echo "============================================="
echo "  Identity Research for Agent Management Using SPIFFE — Full Teardown"
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

# ─── Step 5: Optional Entra directory purge ───────────────────────────────

if [ "$PURGE_ENTRA" = true ]; then
    echo "🧨 Step 5: Purging Entra directory objects..."
    echo "   This deletes Blueprint, Provisioner, Portal, Security Portal Mock"
    echo "   apps and the Administrators/Viewers groups. Cannot be undone."
    echo ""

    AZD_VALUES_NOW=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null || true)

    _val() {
        printf '%s\n' "$AZD_VALUES_NOW" | grep "^${1}=" | head -1 | cut -d'=' -f2- | tr -d '"'
    }

    delete_app() {
        # Args: friendly_label, app_id_or_empty
        local label="$1"
        local app_id="$2"
        if [ -z "$app_id" ]; then
            echo "   ⏭  ${label}: no app id in azd env, skipping"
            return 0
        fi
        local name
        name=$(az ad app show --id "$app_id" --query "displayName" -o tsv 2>/dev/null || true)
        if [ -z "$name" ]; then
            echo "   ⏭  ${label} (${app_id}): already deleted"
            return 0
        fi
        if az ad app delete --id "$app_id" 2>/dev/null; then
            echo "   ✅ Deleted ${label}: ${name} (${app_id})"
        else
            echo "   ⚠  ${label} (${app_id}): delete failed — you may need Application.ReadWrite.All" >&2
        fi
    }

    delete_group() {
        local label="$1"
        local group_id="$2"
        if [ -z "$group_id" ]; then
            echo "   ⏭  ${label}: no group id in azd env, skipping"
            return 0
        fi
        local name
        name=$(az ad group show --group "$group_id" --query "displayName" -o tsv 2>/dev/null || true)
        if [ -z "$name" ]; then
            echo "   ⏭  ${label} (${group_id}): already deleted"
            return 0
        fi
        if az ad group delete --group "$group_id" 2>/dev/null; then
            echo "   ✅ Deleted ${label}: ${name} (${group_id})"
        else
            echo "   ⚠  ${label} (${group_id}): delete failed — you may need Group.ReadWrite.All" >&2
        fi
    }

    # Apps. Deleting the Blueprint app cascades to its child Agent Identities
    # and federated credentials. The Provisioner / Portal / Security Portal Mock
    # apps are siblings and must be deleted explicitly.
    delete_app "Blueprint app"            "$(_val ENTRA_BLUEPRINT_APP_ID)"
    delete_app "Provisioner app"          "$(_val ENTRA_AGENTID_CLIENT_ID)"
    delete_app "Portal management app"    "$(_val PORTAL_AUTH_CLIENT_ID)"
    delete_app "Security Portal Mock app" "$(_val SECURITYPORTAL_AUTH_CLIENT_ID)"

    # Portal groups
    delete_group "Administrators group" "$(_val ISP_ADMIN_GROUP_ID)"
    delete_group "Viewers group"        "$(_val ISP_VIEWER_GROUP_ID)"

    # Clear the related env vars so the next deploy creates fresh objects
    # rather than trying to look up tombstoned IDs.
    ENTRA_VARS=(
        ENTRA_BLUEPRINT_APP_ID
        ENTRA_BLUEPRINT_OBJECT_ID
        ENTRA_AGENTID_CLIENT_ID
        ENTRA_AGENTID_CLIENT_SECRET
        ENTRA_AGENT_ID_BUDGET_REPORT
        ENTRA_AGENT_ID_BUDGET_BACKEND
        ENTRA_AGENT_ID_EMPLOYEE_MENUS
        ENTRA_AGENT_ID_BUDGET_APPROVAL
        ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE
        ENTRA_FIC_CREATED_BUDGET_REPORT
        ENTRA_FIC_CREATED_BUDGET_APPROVAL
        ENTRA_FIC_CREATED_EMPLOYEE_MENUS
        ENTRA_OAUTH2_APP_ROLES_READY
        ENTRA_OAUTH2_AUDIENCE
        PORTAL_AUTH_CLIENT_ID
        SECURITYPORTAL_AUTH_CLIENT_ID
        ISP_ADMIN_GROUP_ID
        ISP_VIEWER_GROUP_ID
    )
    for var in "${ENTRA_VARS[@]}"; do
        CURRENT=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null | grep "^${var}=" | cut -d'=' -f2 | tr -d '"' || true)
        if [ -n "$CURRENT" ]; then
            cd "$REPO_ROOT" && azd env set "$var" "" 2>/dev/null
            echo "   Cleared azd env: ${var}"
        fi
    done
    echo ""
else
    echo "⏭  Step 5: Entra directory preserved (use --purge-entra to delete)"
    echo "   Blueprint, Provisioner, Portal apps, and admin groups stay so the"
    echo "   next ./deploy.sh reuses them. Run with --purge-entra for a true"
    echo "   clean-room test."
    echo ""
fi

# ─── Step 6: Wait for soft-delete propagation ─────────────────────────────

echo "⏳ Step 6: Waiting 30s for resource soft-delete propagation..."
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
