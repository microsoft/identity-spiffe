#!/usr/bin/env bash
# =============================================================================
# AIM Prototype Platform — Google Cross-Cloud Agent Teardown
# =============================================================================
# Removes all GCP resources created by deploy.sh --google:
#   1. GCE VM (google-budget-reader)
#   2. VPN tunnel + gateway + forwarding rules + static IP
#   3. Firewall rules
#   4. VPC subnet + network
#   5. Service account (aim-agent)
#
# Does NOT remove:
#   - The GCP project itself (may have other resources)
#   - Azure-side Entra Agent Identities (use scripts/cleanup-entra-agent-ids.py)
#   - Azure-side VPN Gateway (handled by scripts/teardown.sh)
#
# Usage:
#   GCP_PROJECT=aim-crosscloud-poc ./scripts/teardown-google.sh
#   ./scripts/teardown-google.sh  # reads GCP_PROJECT from azd env
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── Configuration ───────────────────────────────────────────────────────────

# Try loading GCP_PROJECT from azd env if not set
if [ -z "${GCP_PROJECT:-}" ]; then
    GCP_PROJECT=$(cd "$REPO_ROOT" && azd env get-values 2>/dev/null \
        | grep "^GCP_PROJECT=" | cut -d'=' -f2 | tr -d '"' || true)
fi

if [ -z "${GCP_PROJECT:-}" ]; then
    echo "❌ ERROR: GCP_PROJECT not set. Provide it via env var or azd env." >&2
    echo "   Usage: GCP_PROJECT=my-project ./scripts/teardown-google.sh" >&2
    exit 1
fi

PROJECT="${GCP_PROJECT}"
REGION="${GCP_REGION:-us-west1}"
ZONE="${REGION}-a"
VM_NAME="google-budget-reader"
VPC_NAME="aim-crosscloud"
SUBNET_NAME="aim-agents"
SA_NAME="aim-agent"
SA_EMAIL="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"

DELETED=()
SKIPPED=()
FAILED=()

echo ""
echo "============================================="
echo "  GCP Cross-Cloud Teardown"
echo "============================================="
echo "  Project: ${PROJECT}"
echo "  Region:  ${REGION}"
echo ""

# ─── Preflight: verify gcloud auth ──────────────────────────────────────────

if ! gcloud auth list --filter="status=ACTIVE" --format="value(account)" 2>/dev/null | head -1 | grep -q .; then
    echo "❌ ERROR: No active gcloud account. Run: gcloud auth login" >&2
    exit 1
fi
echo "🔑 Authenticated as: $(gcloud auth list --filter='status=ACTIVE' --format='value(account)' 2>/dev/null | head -1)"
echo ""

# ─── Helper: delete a resource if it exists ──────────────────────────────────

delete_resource() {
    local label="$1"
    local check_cmd="$2"
    local delete_cmd="$3"

    printf "   %-50s" "$label"
    if eval "$check_cmd" >/dev/null 2>&1; then
        if eval "$delete_cmd" 2>/dev/null; then
            echo "✅ deleted"
            DELETED+=("$label")
        else
            echo "❌ failed"
            FAILED+=("$label")
        fi
    else
        echo "⏭  not found"
        SKIPPED+=("$label")
    fi
}

# ─── Step 1: Delete GCE VM ──────────────────────────────────────────────────

echo "🖥  Step 1: GCE VM"
delete_resource \
    "VM: $VM_NAME" \
    "gcloud compute instances describe $VM_NAME --zone=$ZONE --project=$PROJECT" \
    "gcloud compute instances delete $VM_NAME --zone=$ZONE --project=$PROJECT --quiet"
echo ""

# ─── Step 2: Delete VPN tunnel ───────────────────────────────────────────────

echo "🔒 Step 2: VPN tunnel"
delete_resource \
    "VPN tunnel: aim-vpn-tunnel-azure" \
    "gcloud compute vpn-tunnels describe aim-vpn-tunnel-azure --region=$REGION --project=$PROJECT" \
    "gcloud compute vpn-tunnels delete aim-vpn-tunnel-azure --region=$REGION --project=$PROJECT --quiet"
echo ""

# ─── Step 3: Delete forwarding rules ────────────────────────────────────────

echo "📨 Step 3: VPN forwarding rules"
for rule in aim-vpn-fr-esp aim-vpn-fr-udp500 aim-vpn-fr-udp4500; do
    delete_resource \
        "Forwarding rule: $rule" \
        "gcloud compute forwarding-rules describe $rule --region=$REGION --project=$PROJECT" \
        "gcloud compute forwarding-rules delete $rule --region=$REGION --project=$PROJECT --quiet"
done
echo ""

# ─── Step 4: Delete VPN gateway ─────────────────────────────────────────────

echo "🌐 Step 4: VPN gateway"
delete_resource \
    "Target VPN gateway: aim-vpn-gateway" \
    "gcloud compute target-vpn-gateways describe aim-vpn-gateway --region=$REGION --project=$PROJECT" \
    "gcloud compute target-vpn-gateways delete aim-vpn-gateway --region=$REGION --project=$PROJECT --quiet"
echo ""

# ─── Step 5: Delete static IP ───────────────────────────────────────────────

echo "🔢 Step 5: VPN static IP"
delete_resource \
    "Static IP: aim-vpn-ip" \
    "gcloud compute addresses describe aim-vpn-ip --region=$REGION --project=$PROJECT" \
    "gcloud compute addresses delete aim-vpn-ip --region=$REGION --project=$PROJECT --quiet"
echo ""

# ─── Step 6: Delete firewall rules ──────────────────────────────────────────

echo "🔥 Step 6: Firewall rules"
for rule in aim-allow-ssh aim-allow-https aim-allow-spire aim-allow-agent-http; do
    delete_resource \
        "Firewall: $rule" \
        "gcloud compute firewall-rules describe $rule --project=$PROJECT" \
        "gcloud compute firewall-rules delete $rule --project=$PROJECT --quiet"
done
echo ""

# ─── Step 7: Delete subnet ──────────────────────────────────────────────────

echo "🔗 Step 7: VPC subnet"
delete_resource \
    "Subnet: $SUBNET_NAME" \
    "gcloud compute networks subnets describe $SUBNET_NAME --region=$REGION --project=$PROJECT" \
    "gcloud compute networks subnets delete $SUBNET_NAME --region=$REGION --project=$PROJECT --quiet"
echo ""

# ─── Step 8: Delete VPC network ─────────────────────────────────────────────

echo "🌐 Step 8: VPC network"
delete_resource \
    "VPC: $VPC_NAME" \
    "gcloud compute networks describe $VPC_NAME --project=$PROJECT" \
    "gcloud compute networks delete $VPC_NAME --project=$PROJECT --quiet"
echo ""

# ─── Step 9: Delete service account ─────────────────────────────────────────

echo "👤 Step 9: Service account"
delete_resource \
    "Service account: $SA_EMAIL" \
    "gcloud iam service-accounts describe $SA_EMAIL --project=$PROJECT" \
    "gcloud iam service-accounts delete $SA_EMAIL --project=$PROJECT --quiet"
echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────

echo "============================================="
echo "  GCP Teardown Summary"
echo "============================================="
echo "  Deleted: ${#DELETED[@]}"
for item in "${DELETED[@]+"${DELETED[@]}"}"; do
    [ -n "$item" ] && echo "    ✅ $item"
done
echo "  Skipped: ${#SKIPPED[@]} (not found)"
for item in "${SKIPPED[@]+"${SKIPPED[@]}"}"; do
    [ -n "$item" ] && echo "    ⏭  $item"
done
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "  Failed:  ${#FAILED[@]}"
    for item in "${FAILED[@]}"; do
        echo "    ❌ $item"
    done
fi
echo ""
echo "Note: GCP project '$PROJECT' was NOT deleted."
echo "      Azure-side Entra resources need separate cleanup."
echo ""
