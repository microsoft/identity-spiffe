#!/usr/bin/env bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Provision GCE VM for Cross-Cloud Agent
# =============================================================================
# Creates GCP infrastructure for the Google-hosted cross-cloud agent:
#   1. VPC network (custom subnet mode)
#   2. Subnet in the specified region
#   3. Firewall rules (SSH, HTTPS, SPIRE)
#   4. Ubuntu 22.04 VM with Docker pre-installed
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (gcloud auth login)
#   - A GCP project (set GCP_PROJECT env var)
#
# Idempotent: checks if each resource exists before creating it.
#
# Usage:
#   GCP_PROJECT=my-project ./scripts/provision-gce-vm.sh
#
# Configuration (env vars with defaults):
#   GCP_PROJECT      — required, no default
#   GCP_REGION       — default: us-west1
#   GCP_ZONE         — default: ${GCP_REGION}-a
#   GCP_MACHINE_TYPE — default: e2-medium
#   GCP_VM_NAME      — default: google-budget-reader
#   GCP_VPC_NAME     — default: aim-crosscloud
#   GCP_SUBNET_NAME  — default: aim-agents
#   GCP_SUBNET_CIDR  — default: 10.128.0.0/20
# =============================================================================
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

if [[ -z "${GCP_PROJECT:-}" ]]; then
    echo "❌ ERROR: GCP_PROJECT environment variable is required." >&2
    echo "   Usage: GCP_PROJECT=my-project ./scripts/provision-gce-vm.sh" >&2
    exit 1
fi

PROJECT="${GCP_PROJECT}"
REGION="${GCP_REGION:-us-west1}"
ZONE="${GCP_ZONE:-${REGION}-a}"
MACHINE_TYPE="${GCP_MACHINE_TYPE:-e2-medium}"
VM_NAME="${GCP_VM_NAME:-google-budget-reader}"
VPC_NAME="${GCP_VPC_NAME:-aim-crosscloud}"
SUBNET_NAME="${GCP_SUBNET_NAME:-aim-agents}"
SUBNET_CIDR="${GCP_SUBNET_CIDR:-10.128.0.0/20}"
GCP_SA_NAME="${GCP_SA_NAME:-aim-agent}"
SA_EMAIL="${GCP_SA_NAME}@${PROJECT}.iam.gserviceaccount.com"

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

# ─── Pre-flight checks ──────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Identity Research for Agent Management Using SPIFFE — Provision GCE VM for Cross-Cloud Agent"
echo "============================================================"
echo ""
echo "  Project:      ${PROJECT}"
echo "  Region:       ${REGION}"
echo "  Zone:         ${ZONE}"
echo "  Machine type: ${MACHINE_TYPE}"
echo "  VM name:      ${VM_NAME}"
echo "  VPC:          ${VPC_NAME}"
echo "  Subnet:       ${SUBNET_NAME} (${SUBNET_CIDR})"
echo "  Service acct: ${SA_EMAIL}"
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

info "Checking Compute Engine API..."
if ! gcloud services list --project="$PROJECT" --enabled --filter="name:compute.googleapis.com" --format="value(name)" 2>/dev/null | grep -q 'compute'; then
    error "Compute Engine API not enabled. Run: gcloud services enable compute.googleapis.com --project=${PROJECT}"
    exit 1
fi
echo ""

# ─── Step 1: Create service account ─────────────────────────────────────────

echo "📍 Step 1/5 — Service account: ${SA_EMAIL}"

if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT" &>/dev/null; then
    skip "Service account ${GCP_SA_NAME} already exists, skipping"
else
    gcloud iam service-accounts create "$GCP_SA_NAME" \
        --project="$PROJECT" \
        --display-name="Identity Research for Agent Management Using SPIFFE cross-cloud agent identity" \
        --quiet
    info "Created service account ${SA_EMAIL}"
fi
echo ""

# ─── Step 2: Create VPC network ─────────────────────────────────────────────

echo "📍 Step 2/5 — VPC network: ${VPC_NAME}"

if gcloud compute networks describe "$VPC_NAME" --project="$PROJECT" &>/dev/null; then
    skip "VPC ${VPC_NAME} already exists, skipping"
else
    gcloud compute networks create "$VPC_NAME" \
        --project="$PROJECT" \
        --subnet-mode=custom \
        --quiet
    info "Created VPC ${VPC_NAME}"
fi
echo ""

# ─── Step 3: Create subnet ──────────────────────────────────────────────────

echo "📍 Step 3/5 — Subnet: ${SUBNET_NAME} (${SUBNET_CIDR})"

if gcloud compute networks subnets describe "$SUBNET_NAME" \
    --project="$PROJECT" \
    --region="$REGION" &>/dev/null; then
    skip "Subnet ${SUBNET_NAME} already exists, skipping"
else
    gcloud compute networks subnets create "$SUBNET_NAME" \
        --project="$PROJECT" \
        --network="$VPC_NAME" \
        --region="$REGION" \
        --range="$SUBNET_CIDR" \
        --quiet
    info "Created subnet ${SUBNET_NAME} in ${REGION}"
fi
echo ""

# ─── Step 4: Create firewall rules ──────────────────────────────────────────

echo "📍 Step 4/5 — Firewall rules"

# WARNING: SSH open to internet for PoC convenience. Restrict to operator IPs
# (e.g., --source-ranges="YOUR_IP/32") in production.
# aim-allow-ssh: TCP 22 from anywhere
if gcloud compute firewall-rules describe "aim-allow-ssh" --project="$PROJECT" &>/dev/null; then
    skip "Firewall rule aim-allow-ssh already exists, skipping"
else
    gcloud compute firewall-rules create "aim-allow-ssh" \
        --project="$PROJECT" \
        --network="$VPC_NAME" \
        --allow=tcp:22 \
        --source-ranges="0.0.0.0/0" \
        --description="Allow SSH access to Identity Research for Agent Management Using SPIFFE agents" \
        --quiet
    info "Created firewall rule aim-allow-ssh"
fi

# aim-allow-https: TCP 443 from anywhere
if gcloud compute firewall-rules describe "aim-allow-https" --project="$PROJECT" &>/dev/null; then
    skip "Firewall rule aim-allow-https already exists, skipping"
else
    gcloud compute firewall-rules create "aim-allow-https" \
        --project="$PROJECT" \
        --network="$VPC_NAME" \
        --allow=tcp:443,tcp:8443 \
        --source-ranges="0.0.0.0/0" \
        --description="Allow HTTPS access to Identity Research for Agent Management Using SPIFFE agents (443 + 8443 for invoke_url)" \
        --quiet
    info "Created firewall rule aim-allow-https"
fi

# aim-allow-spire: TCP 8081 from Azure VPN CIDR only (internal control-plane traffic)
if gcloud compute firewall-rules describe "aim-allow-spire" --project="$PROJECT" &>/dev/null; then
    skip "Firewall rule aim-allow-spire already exists, skipping"
else
    gcloud compute firewall-rules create "aim-allow-spire" \
        --project="$PROJECT" \
        --network="$VPC_NAME" \
        --allow=tcp:8081 \
        --source-ranges="10.200.0.0/16" \
        --description="Allow SPIRE agent communication from Azure VPN CIDR only" \
        --quiet
    info "Created firewall rule aim-allow-spire"
fi

# aim-allow-agent-http: TCP 8000 from Azure VPN CIDR only → instances tagged aim-agent
if gcloud compute firewall-rules describe "aim-allow-agent-http" --project="$PROJECT" &>/dev/null; then
    skip "Firewall rule aim-allow-agent-http already exists, skipping"
else
    gcloud compute firewall-rules create "aim-allow-agent-http" \
        --project="$PROJECT" \
        --network="$VPC_NAME" \
        --allow=tcp:8000 \
        --source-ranges="10.200.0.0/16" \
        --target-tags=aim-agent \
        --description="Allow HTTP access to Identity Research for Agent Management Using SPIFFE agent endpoint (port 8000) from Azure VPN CIDR" \
        --quiet
    info "Created firewall rule aim-allow-agent-http"
fi
echo ""

# ─── Step 5: Create VM instance ─────────────────────────────────────────────

echo "📍 Step 5/5 — VM instance: ${VM_NAME}"

STARTUP_SCRIPT='#!/bin/bash
set -euo pipefail
apt-get update
apt-get install -y docker.io jq
systemctl enable docker
systemctl start docker
usermod -aG docker "$(whoami)" || true'

if gcloud compute instances describe "$VM_NAME" \
    --project="$PROJECT" \
    --zone="$ZONE" &>/dev/null; then
    skip "VM ${VM_NAME} already exists, skipping"
else
    gcloud compute instances create "$VM_NAME" \
        --project="$PROJECT" \
        --zone="$ZONE" \
        --machine-type="$MACHINE_TYPE" \
        --image-family=ubuntu-2204-lts \
        --image-project=ubuntu-os-cloud \
        --subnet="$SUBNET_NAME" \
        --service-account="$SA_EMAIL" \
        --scopes=compute-ro,logging-write,monitoring-write \
        --tags=aim-agent \
        --metadata=startup-script="$STARTUP_SCRIPT" \
        --quiet
    info "Created VM ${VM_NAME}"
fi
echo ""

# ─── Summary ─────────────────────────────────────────────────────────────────

echo "⏳ Retrieving VM details..."

EXTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --format="get(networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null || echo "N/A")

INTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" \
    --project="$PROJECT" \
    --zone="$ZONE" \
    --format="get(networkInterfaces[0].networkIP)" 2>/dev/null || echo "N/A")

echo ""
echo "============================================================"
echo "  ✅  GCE VM Provisioned Successfully"
echo "============================================================"
echo ""
echo "  VM name:       ${VM_NAME}"
echo "  GCP project:   ${PROJECT}"
echo "  Zone:          ${ZONE}"
echo "  Machine type:  ${MACHINE_TYPE}"
echo "  External IP:   ${EXTERNAL_IP}"
echo "  Internal IP:   ${INTERNAL_IP}"
echo "  VPC:           ${VPC_NAME}"
echo "  Subnet:        ${SUBNET_NAME} (${SUBNET_CIDR})"
echo ""
echo "  Next steps:"
echo "    1. Set up VPN between GCP (${SUBNET_CIDR}) and Azure (10.200.0.0/16)"
echo "    2. Deploy the agent container:"
echo "       gcloud compute ssh ${VM_NAME} --zone=${ZONE} --project=${PROJECT}"
echo "    3. Register with Identity Research for Agent Management Using SPIFFE portal:"
echo "       ./scripts/add-google-agent.sh --gcp-sa <sa-email> --invoke-url https://${EXTERNAL_IP}:8443"
echo ""
