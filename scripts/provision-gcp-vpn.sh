#!/usr/bin/env bash
# =============================================================================
# AIM Prototype Platform — Provision GCP Classic Cloud VPN to Azure
# =============================================================================
# Creates GCP-side infrastructure for a site-to-site VPN tunnel to Azure:
#   1. Static external IP for VPN gateway
#   2. Classic VPN gateway (target-vpn-gateway)
#   3. Forwarding rules (ESP, UDP 500, UDP 4500)
#   4. IPsec VPN tunnel (IKEv2) to Azure VPN Gateway
#   5. Route to Azure VNet via the tunnel
#
# The Azure side is the VPN Gateway created by vpn-gateway.bicep. Both sides
# must use the same shared key (VPN_SHARED_KEY) and correct peer IPs.
#
# Classic VPN (not HA VPN) is used — simpler and cheaper for this PoC.
# Classic VPN requires manual forwarding rules for ESP, UDP 500, and UDP 4500.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - A GCP project with Compute Engine API enabled
#   - Azure VPN Gateway public IP (from vpn-gateway.bicep output)
#   - IPsec pre-shared key (must match Azure VPN Gateway config)
#
# Idempotent: checks if each resource exists before creating it.
#
# Usage:
#   GCP_PROJECT=my-project \
#   AZURE_VPN_GATEWAY_IP=20.xx.xx.xx \
#   VPN_SHARED_KEY=mySecretKey123 \
#   ./scripts/provision-gcp-vpn.sh
#
# Configuration (env vars with defaults):
#   GCP_PROJECT          — required, no default
#   GCP_REGION           — default: us-west1
#   GCP_VPC_NAME         — default: aim-crosscloud
#   AZURE_VPN_GATEWAY_IP — required, no default (Azure VPN Gateway public IP)
#   VPN_SHARED_KEY       — required, no default (IPsec pre-shared key)
#   AZURE_VNET_CIDR      — default: 10.200.0.0/16
# Teardown (reverse order):
#   gcloud compute routes delete aim-route-to-azure --project=$GCP_PROJECT --quiet
#   gcloud compute vpn-tunnels delete aim-vpn-tunnel-azure --region=$GCP_REGION --project=$GCP_PROJECT --quiet
#   gcloud compute forwarding-rules delete aim-vpn-udp4500 aim-vpn-udp500 aim-vpn-esp --region=$GCP_REGION --project=$GCP_PROJECT --quiet
#   gcloud compute target-vpn-gateways delete aim-vpn-gateway --region=$GCP_REGION --project=$GCP_PROJECT --quiet
#   gcloud compute addresses delete aim-vpn-ip --region=$GCP_REGION --project=$GCP_PROJECT --quiet
# =============================================================================
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

MISSING_VARS=()

if [[ -z "${GCP_PROJECT:-}" ]]; then
    MISSING_VARS+=("GCP_PROJECT")
fi
if [[ -z "${AZURE_VPN_GATEWAY_IP:-}" ]]; then
    MISSING_VARS+=("AZURE_VPN_GATEWAY_IP")
fi
if [[ -z "${VPN_SHARED_KEY:-}" ]]; then
    MISSING_VARS+=("VPN_SHARED_KEY")
fi

if [[ ${#MISSING_VARS[@]} -gt 0 ]]; then
    echo "❌ ERROR: Required environment variables not set: ${MISSING_VARS[*]}" >&2
    echo "" >&2
    echo "   Usage:" >&2
    echo "     GCP_PROJECT=my-project \\" >&2
    echo "     AZURE_VPN_GATEWAY_IP=20.xx.xx.xx \\" >&2
    echo "     VPN_SHARED_KEY=mySecretKey123 \\" >&2
    echo "     ./scripts/provision-gcp-vpn.sh" >&2
    exit 1
fi

PROJECT="${GCP_PROJECT}"
REGION="${GCP_REGION:-us-west1}"
VPC_NAME="${GCP_VPC_NAME:-aim-crosscloud}"
AZURE_PEER_IP="${AZURE_VPN_GATEWAY_IP}"
SHARED_KEY="${VPN_SHARED_KEY}"
AZURE_CIDR="${AZURE_VNET_CIDR:-10.200.0.0/16}"

# Resource names
VPN_IP_NAME="aim-vpn-ip"
VPN_GW_NAME="aim-vpn-gateway"
FWD_ESP_NAME="aim-vpn-esp"
FWD_UDP500_NAME="aim-vpn-udp500"
FWD_UDP4500_NAME="aim-vpn-udp4500"
TUNNEL_NAME="aim-vpn-tunnel-azure"
ROUTE_NAME="aim-route-to-azure"

# ─── Helper functions ────────────────────────────────────────────────────────

info() {
    echo "✅ $*"
}

error() {
    echo "❌ $*" >&2
}

skip() {
    echo "⏭  $*"
}

warn() {
    echo "⚠️  $*"
}

# ─── Pre-flight checks ──────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  AIM — Provision GCP Classic Cloud VPN to Azure"
echo "============================================================"
echo ""
echo "  Project:          ${PROJECT}"
echo "  Region:           ${REGION}"
echo "  VPC:              ${VPC_NAME}"
echo "  Azure peer IP:    ${AZURE_PEER_IP}"
echo "  Azure VNet CIDR:  ${AZURE_CIDR}"
echo ""

echo "🔍 Pre-flight: checking gcloud CLI..."

if ! command -v gcloud &>/dev/null; then
    error "gcloud CLI not found. Install it from https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Verify authentication
if ! gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1 | grep -q '.'; then
    error "No active gcloud account. Run: gcloud auth login"
    exit 1
fi

# Verify project exists and is accessible
if ! gcloud projects describe "$PROJECT" &>/dev/null; then
    error "Cannot access GCP project '${PROJECT}'. Check the project ID and your permissions."
    exit 1
fi

ACTIVE_ACCOUNT=$(gcloud auth list --filter="status:ACTIVE" --format="value(account)" 2>/dev/null | head -1)
info "Authenticated as ${ACTIVE_ACCOUNT}"
info "Project ${PROJECT} is accessible"

echo "🔍 Checking Compute Engine API..."
if ! gcloud services list --project="$PROJECT" --enabled --filter="name:compute.googleapis.com" --format="value(name)" 2>/dev/null | grep -q 'compute'; then
    error "Compute Engine API not enabled. Run: gcloud services enable compute.googleapis.com --project=${PROJECT}"
    exit 1
fi
info "Compute Engine API is enabled"

echo "🔍 Checking VPC network ${VPC_NAME}..."
if ! gcloud compute networks describe "$VPC_NAME" --project="$PROJECT" &>/dev/null; then
    error "VPC '${VPC_NAME}' does not exist. Run provision-gce-vm.sh first, or set GCP_VPC_NAME."
    exit 1
fi
info "VPC ${VPC_NAME} exists"
echo ""

# ─── Step 1: Reserve static external IP ─────────────────────────────────────

echo "📍 Step 1/5 — Static external IP: ${VPN_IP_NAME}"

if gcloud compute addresses describe "$VPN_IP_NAME" \
    --project="$PROJECT" \
    --region="$REGION" &>/dev/null; then
    skip "Static IP ${VPN_IP_NAME} already exists, skipping"
else
    gcloud compute addresses create "$VPN_IP_NAME" \
        --project="$PROJECT" \
        --region="$REGION" \
        --quiet
    info "Reserved static IP ${VPN_IP_NAME}"
fi

VPN_IP=$(gcloud compute addresses describe "$VPN_IP_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --format="get(address)" 2>/dev/null)

if [[ -z "${VPN_IP}" ]]; then
    error "Failed to retrieve IP address for ${VPN_IP_NAME}. Address may still be provisioning."
    exit 1
fi
info "VPN gateway IP: ${VPN_IP}"
echo ""

# ─── Step 2: Create Classic VPN gateway ──────────────────────────────────────

echo "📍 Step 2/5 — Classic VPN gateway: ${VPN_GW_NAME}"

if gcloud compute target-vpn-gateways describe "$VPN_GW_NAME" \
    --project="$PROJECT" \
    --region="$REGION" &>/dev/null; then
    skip "VPN gateway ${VPN_GW_NAME} already exists, skipping"
else
    gcloud compute target-vpn-gateways create "$VPN_GW_NAME" \
        --project="$PROJECT" \
        --region="$REGION" \
        --network="$VPC_NAME" \
        --quiet
    info "Created VPN gateway ${VPN_GW_NAME}"
fi
echo ""

# ─── Step 3: Create forwarding rules ────────────────────────────────────────

echo "📍 Step 3/5 — Forwarding rules (ESP, UDP 500, UDP 4500)"

# Helper: ensure a forwarding rule exists with the correct static IP.
# If the rule exists but points to a stale IP (e.g. after teardown/rebuild),
# delete and recreate it. This prevents VPN tunnels silently failing because
# IKE packets arrive at a different IP than the VPN gateway is listening on.
ensure_forwarding_rule() {
    local rule_name="$1" ip_proto="$2" ports="$3"
    local port_args=()
    [[ -n "$ports" ]] && port_args=(--ports="$ports")

    if gcloud compute forwarding-rules describe "$rule_name" \
        --project="$PROJECT" --region="$REGION" &>/dev/null; then
        local existing_ip
        existing_ip=$(gcloud compute forwarding-rules describe "$rule_name" \
            --project="$PROJECT" --region="$REGION" \
            --format="value(IPAddress)" 2>/dev/null)
        if [[ "$existing_ip" != "$VPN_IP" ]]; then
            warn "Forwarding rule ${rule_name} has stale IP ${existing_ip} (expected ${VPN_IP}), recreating"
            gcloud compute forwarding-rules delete "$rule_name" \
                --project="$PROJECT" --region="$REGION" --quiet
            gcloud compute forwarding-rules create "$rule_name" \
                --project="$PROJECT" --region="$REGION" \
                --ip-protocol="$ip_proto" "${port_args[@]}" \
                --target-vpn-gateway="$VPN_GW_NAME" \
                --address="$VPN_IP_NAME" --quiet
            info "Recreated forwarding rule ${rule_name} (${ip_proto}) with correct IP"
        else
            skip "Forwarding rule ${rule_name} already exists with correct IP, skipping"
        fi
    else
        gcloud compute forwarding-rules create "$rule_name" \
            --project="$PROJECT" --region="$REGION" \
            --ip-protocol="$ip_proto" "${port_args[@]}" \
            --target-vpn-gateway="$VPN_GW_NAME" \
            --address="$VPN_IP_NAME" --quiet
        info "Created forwarding rule ${rule_name} (${ip_proto})"
    fi
}

ensure_forwarding_rule "$FWD_ESP_NAME" ESP ""
ensure_forwarding_rule "$FWD_UDP500_NAME" UDP 500
ensure_forwarding_rule "$FWD_UDP4500_NAME" UDP 4500
echo ""

# ─── Step 4: Create VPN tunnel ───────────────────────────────────────────────

echo "📍 Step 4/5 — VPN tunnel: ${TUNNEL_NAME}"

if gcloud compute vpn-tunnels describe "$TUNNEL_NAME" \
    --project="$PROJECT" \
    --region="$REGION" &>/dev/null; then
    skip "VPN tunnel ${TUNNEL_NAME} already exists, skipping"
else
    # NOTE: Classic VPN does not support --ipsec-policies. GCP negotiates from
    # its default cipher list. Azure vpn-gateway.bicep enforces AES256/SHA256/
    # DHGroup14/PFS2048 (these are in GCP's defaults, so negotiation should
    # succeed). If the tunnel fails to establish, check cipher mismatch —
    # HA VPN may be needed for explicit policy control.
    #
    # SECURITY: --shared-secret is visible in process listings during execution.
    # Acceptable for PoC; in production, use HA VPN with secret manager.
    gcloud compute vpn-tunnels create "$TUNNEL_NAME" \
        --project="$PROJECT" \
        --region="$REGION" \
        --target-vpn-gateway="$VPN_GW_NAME" \
        --peer-address="$AZURE_PEER_IP" \
        --shared-secret="$SHARED_KEY" \
        --ike-version=2 \
        --local-traffic-selector="0.0.0.0/0" \
        --remote-traffic-selector="0.0.0.0/0" \
        --quiet
    info "Created VPN tunnel ${TUNNEL_NAME}"
fi
echo ""

# ─── Step 5: Create route to Azure VNet ──────────────────────────────────────

echo "📍 Step 5/5 — Route to Azure: ${ROUTE_NAME}"

if gcloud compute routes describe "$ROUTE_NAME" \
    --project="$PROJECT" &>/dev/null; then
    skip "Route ${ROUTE_NAME} already exists, skipping"
else
    gcloud compute routes create "$ROUTE_NAME" \
        --project="$PROJECT" \
        --network="$VPC_NAME" \
        --destination-range="$AZURE_CIDR" \
        --next-hop-vpn-tunnel="$TUNNEL_NAME" \
        --next-hop-vpn-tunnel-region="$REGION" \
        --quiet
    info "Created route ${ROUTE_NAME} → ${AZURE_CIDR}"
fi
echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────

echo "⏳ Retrieving tunnel status..."

TUNNEL_STATUS=$(gcloud compute vpn-tunnels describe "$TUNNEL_NAME" \
    --project="$PROJECT" \
    --region="$REGION" \
    --format="get(status)" 2>/dev/null || echo "UNKNOWN")

echo ""
echo "============================================================"
echo "  ✅  GCP Classic Cloud VPN Provisioned Successfully"
echo "============================================================"
echo ""
echo "  GCP VPN gateway IP:  ${VPN_IP}"
echo "  Tunnel name:         ${TUNNEL_NAME}"
echo "  Tunnel status:       ${TUNNEL_STATUS}"
echo "  Azure peer address:  ${AZURE_PEER_IP}"
echo "  Azure VNet CIDR:     ${AZURE_CIDR}"
echo "  IKE version:         2"
echo ""
echo "  ⚠️  Ensure Azure VPN Gateway Local Network Gateway uses this IP: ${VPN_IP}"
echo ""
echo "  If tunnel status is not ESTABLISHED, verify:"
echo "    1. Azure VPN Gateway is provisioned and running"
echo "    2. Azure Local Network Gateway peer IP is set to ${VPN_IP}"
echo "    3. Both sides use the same pre-shared key"
echo "    4. Azure NSG allows ESP, UDP 500, and UDP 4500"
echo ""
