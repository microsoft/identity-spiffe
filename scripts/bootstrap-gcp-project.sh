#!/usr/bin/env bash
# =============================================================================
# AIM Prototype Platform — GCP Project Bootstrap
# =============================================================================
# One-time setup for a GCP project to support the cross-cloud PoC.
# Run this ONCE, then use the existing provisioning scripts.
#
# What this script does:
#   1. Creates a GCP project (or uses existing)
#   2. Links a billing account
#   3. Enables required APIs (Compute, IAM, Networking)
#   4. Creates a service account for the cross-cloud agent
#   5. Prints next steps
#
# Prerequisites:
#   - gcloud CLI installed: https://cloud.google.com/sdk/docs/install
#   - Authenticated: gcloud auth login
#   - You have a billing account (check: gcloud billing accounts list)
#
# Usage:
#   ./scripts/bootstrap-gcp-project.sh
#
# Optional env vars:
#   GCP_PROJECT_ID   — project ID to create (default: aim-crosscloud-poc)
#   GCP_BILLING_ID   — billing account ID (prompted if not set)
#   GCP_REGION       — default: us-west1
#   GCP_ORG_ID       — optional, org to create project under
# =============================================================================
set -euo pipefail

GCP_PROJECT_ID="${GCP_PROJECT_ID:-aim-crosscloud-poc}"
GCP_REGION="${GCP_REGION:-us-west1}"
GCP_ORG_ID="${GCP_ORG_ID:-}"
GCP_SA_NAME="${GCP_SA_NAME:-aim-agent}"

echo "============================================="
echo "  AIM Prototype — GCP Project Bootstrap"
echo "============================================="
echo ""

# ─── Step 0: Verify gcloud is installed and authenticated ───
if ! command -v gcloud &>/dev/null; then
    echo "ERROR: gcloud CLI not found."
    echo ""
    echo "Install it:"
    echo "  brew install google-cloud-sdk"
    echo ""
    echo "Then authenticate:"
    echo "  gcloud auth login"
    exit 1
fi

ACCOUNT=$(gcloud config get-value account 2>/dev/null || true)
if [ -z "$ACCOUNT" ]; then
    echo "ERROR: Not authenticated. Run:"
    echo "  gcloud auth login"
    exit 1
fi
echo "✓ Authenticated as: $ACCOUNT"

# ─── Step 1: Create or select the GCP project ───
echo ""
echo "─── Step 1: GCP Project ───"

if gcloud projects describe "$GCP_PROJECT_ID" &>/dev/null; then
    echo "  ✓ Project '$GCP_PROJECT_ID' already exists"
else
    echo "  Creating project '$GCP_PROJECT_ID'..."
    CREATE_ARGS=(--name "AIM Cross-Cloud PoC")
    if [ -n "$GCP_ORG_ID" ]; then
        CREATE_ARGS+=(--organization "$GCP_ORG_ID")
    fi
    gcloud projects create "$GCP_PROJECT_ID" "${CREATE_ARGS[@]}"
    echo "  ✓ Project created"
fi

gcloud config set project "$GCP_PROJECT_ID"
echo "  ✓ Active project: $GCP_PROJECT_ID"

# ─── Step 2: Link billing account ───
echo ""
echo "─── Step 2: Billing ───"

CURRENT_BILLING=$(gcloud billing projects describe "$GCP_PROJECT_ID" --format="value(billingAccountName)" 2>/dev/null || true)
if [ -n "$CURRENT_BILLING" ] && [ "$CURRENT_BILLING" != "" ]; then
    echo "  ✓ Billing already linked: $CURRENT_BILLING"
else
    if [ -z "${GCP_BILLING_ID:-}" ]; then
        echo "  Available billing accounts:"
        gcloud billing accounts list --format="table(name, displayName, open)" 2>&1
        echo ""
        echo "  Set GCP_BILLING_ID and re-run, or enter the billing account ID now."
        echo "  (format: 01AAAA-BBBBBB-CCCCCC)"
        if [ -t 0 ]; then
            read -rp "  Billing Account ID: " GCP_BILLING_ID
        else
            echo "ERROR: GCP_BILLING_ID is required (no TTY available for interactive input)" >&2
            exit 1
        fi
    fi

    if [ -z "$GCP_BILLING_ID" ]; then
        echo "ERROR: No billing account provided. Cannot enable APIs without billing."
        exit 1
    fi

    gcloud billing projects link "$GCP_PROJECT_ID" --billing-account="$GCP_BILLING_ID"
    echo "  ✓ Billing linked"
fi

# ─── Step 3: Enable required APIs ───
echo ""
echo "─── Step 3: Enable APIs ───"

REQUIRED_APIS=(
    "compute.googleapis.com"        # GCE VMs, VPC, firewall, VPN
    "iam.googleapis.com"            # Service accounts, IAM
    "iamcredentials.googleapis.com" # Service account token creation
    "cloudresourcemanager.googleapis.com" # Project metadata
)

for api in "${REQUIRED_APIS[@]}"; do
    if gcloud services list --enabled --filter="name:$api" --format="value(name)" 2>/dev/null | grep -q "$api"; then
        echo "  ✓ $api (already enabled)"
    else
        echo "  Enabling $api..."
        gcloud services enable "$api"
        echo "  ✓ $api"
    fi
done

# ─── Step 4: Create service account ───
echo ""
echo "─── Step 4: Service Account ───"

GCP_SA_EMAIL="${GCP_SA_NAME}@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

if gcloud iam service-accounts describe "$GCP_SA_EMAIL" &>/dev/null 2>&1; then
    echo "  ✓ Service account exists: $GCP_SA_EMAIL"
else
    gcloud iam service-accounts create "$GCP_SA_NAME" \
        --display-name="AIM Cross-Cloud Agent" \
        --description="Service account for the Google-hosted AIM budget reader agent"
    echo "  ✓ Created: $GCP_SA_EMAIL"
fi

# Get the numeric unique ID (needed for Entra FIC — see hard-won-learnings #30)
GCP_SA_UNIQUE_ID=$(gcloud iam service-accounts describe "$GCP_SA_EMAIL" --format="value(uniqueId)")
echo "  ✓ Numeric unique ID: $GCP_SA_UNIQUE_ID"
echo "    ⚠️  Use this (not the email) for the Entra FIC subject field!"

# ─── Step 5: Grant minimal IAM roles ───
echo ""
echo "─── Step 5: IAM Roles ───"

# The SA needs to request identity tokens from the metadata server
# This is automatic when attached to a VM — no extra roles needed for basic OIDC
# But we grant minimal compute access for the VM to pull container images
echo "  Service account IAM roles:"
echo "  (The SA gets OIDC tokens automatically when attached to a GCE VM)"
echo "  (No extra roles needed for the cross-cloud agent PoC)"
echo "  ✓ Minimal permissions — no additional roles required"

# ─── Done ───
echo ""
echo "============================================="
echo "  GCP Project Bootstrap Complete"
echo "============================================="
echo ""
echo "  Project ID:            $GCP_PROJECT_ID"
echo "  Region:                $GCP_REGION"
echo "  Service Account:       $GCP_SA_EMAIL"
echo "  SA Numeric Unique ID:  $GCP_SA_UNIQUE_ID"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Provision the GCE VM:"
echo "     GCP_PROJECT=$GCP_PROJECT_ID ./scripts/provision-gce-vm.sh"
echo ""
echo "  2. Note the VM external IP from the output, then deploy the"
echo "     Azure VPN Gateway (takes ~30 min):"
echo "     azd env set GCP_VPN_PUBLIC_IP <VM_EXTERNAL_IP>"
echo "     ./scripts/deploy-azure-vpn.sh"
echo ""
echo "  3. Provision the GCP-side VPN tunnel:"
echo "     AZURE_VPN_GW_IP=<from azd env> VPN_SHARED_KEY=<generate one> \\"
echo "       GCP_PROJECT=$GCP_PROJECT_ID ./scripts/provision-gcp-vpn.sh"
echo ""
echo "  4. Validate connectivity:"
echo "     GCE_VM_IP=<external> BUDGET_BACKEND_PRIVATE_IP=<from Azure VNet> \\"
echo "       ./scripts/test-crosscloud-connectivity.sh"
echo ""
echo "  5. Run the Entra provisioning script:"
echo "     ./scripts/add-google-agent.sh \\"
echo "       --gcp-sa $GCP_SA_EMAIL \\"
echo "       --invoke-url https://<VM_EXTERNAL_IP> \\"
echo "       --name google-budget-reader"
echo ""
