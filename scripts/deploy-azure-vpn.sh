#!/usr/bin/env bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Deploy Azure VPN Gateway for Cross-Cloud Connectivity
# =============================================================================
# Deploys the Azure VPN Gateway + Local Network Gateway + IPsec connection
# by running az deployment sub create directly (azd provision's change detection
# doesn't reliably handle conditional VPN modules added after initial deploy).
#
# Prerequisites:
#   - azd env selected with the target environment
#   - GCE VM provisioned (need GCP_VPN_PUBLIC_IP)
#   - VPN_SHARED_KEY set (or will be generated)
#
# Usage:
#   ./scripts/deploy-azure-vpn.sh
#
# This takes ~30 minutes (Azure VPN Gateway provisioning).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

# Load azd env — export all vars so readEnvironmentVariable() in Bicep can see them
eval "$(azd env get-values 2>/dev/null)"
export AZURE_ENV_NAME AZURE_TENANT_ID GCP_VPN_PUBLIC_IP VPN_SHARED_KEY GCP_VPC_CIDR

GCP_VPN_PUBLIC_IP="${GCP_VPN_PUBLIC_IP:-}"
VPN_SHARED_KEY="${VPN_SHARED_KEY:-}"
GCP_VPC_CIDR="${GCP_VPC_CIDR:-10.128.0.0/20}"

if [ -z "$GCP_VPN_PUBLIC_IP" ]; then
    echo "ERROR: GCP_VPN_PUBLIC_IP not set in azd env."
    echo ""
    echo "Set it with the GCE VM's external IP:"
    echo "  azd env set GCP_VPN_PUBLIC_IP <ip>"
    exit 1
fi

if [ -z "$VPN_SHARED_KEY" ]; then
    VPN_SHARED_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    azd env set VPN_SHARED_KEY "$VPN_SHARED_KEY"
    echo "Generated and saved VPN_SHARED_KEY to azd env"
fi

echo "============================================="
echo "  Azure VPN Gateway Deployment"
echo "============================================="
echo ""
echo "  GCP VPN Public IP:  $GCP_VPN_PUBLIC_IP"
echo "  GCP VPC CIDR:       $GCP_VPC_CIDR"
echo "  Shared Key:         ${VPN_SHARED_KEY:0:8}..."
echo ""
echo "  ⚠️  This takes ~30 minutes. VPN Gateway provisioning is slow."
echo ""

az deployment sub create \
    --location "${AZURE_LOCATION:-westus}" \
    --template-file infra/main.bicep \
    --parameters infra/main.parameters.bicepparam \
    --parameters gcpVpnPublicIp="$GCP_VPN_PUBLIC_IP" \
                 vpnSharedKey="$VPN_SHARED_KEY" \
                 gcpVpcCidr="$GCP_VPC_CIDR" \
    --name "aim-vpn-$(date +%s)" \
    2>&1

echo ""

# Get the VPN Gateway public IP
VPN_GW_IP=$(az network public-ip list -g "rg-${AZURE_ENV_NAME}" \
    --query "[?contains(name, 'vpn')].ipAddress" -o tsv 2>/dev/null || true)

if [ -n "$VPN_GW_IP" ]; then
    azd env set VPN_GATEWAY_PUBLIC_IP "$VPN_GW_IP"
    echo "✅ VPN Gateway deployed"
    echo ""
    echo "  Azure VPN Gateway IP: $VPN_GW_IP"
    echo ""
    echo "  Next step — provision the GCP side:"
    echo "    AZURE_VPN_GATEWAY_IP=$VPN_GW_IP \\"
    echo "      VPN_SHARED_KEY=\"\$(azd env get-values 2>/dev/null | grep VPN_SHARED_KEY | cut -d= -f2 | tr -d '\"')\" \\"
    echo "      GCP_PROJECT=\$GCP_PROJECT \\"
    echo "      ./scripts/provision-gcp-vpn.sh"
else
    echo "⚠️  Could not find VPN Gateway public IP. Check deployment status:"
    echo "    az network vnet-gateway list -g rg-${AZURE_ENV_NAME} -o table"
fi
