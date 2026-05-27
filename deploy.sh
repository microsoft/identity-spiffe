#!/bin/bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE - SPIFFE/SPIRE Deployment (Join Token Attestation)
# =============================================================================
# Deploys the full PoC: SPIRE Server on VM, four agents on Container Apps
# with SPIFFE mTLS sidecar proxies using join_token attestation.
#
# What this does:
#   1. Provision infrastructure (VM for SPIRE Server, Container Apps for agents)
#   2. Wait for Azure role propagation and VM initialization
#   3. Build the Go proxy image in ACR, deploy FastAPI agent apps
#   4. Pull image to VM and start SPIRE Server (trust root)
#   5. For each agent: generate a one-time join token, inject it into the
#      sidecar container, and trigger Container App revision (restarts sidecar
#      with token → sidecar attests to SPIRE Server → receives X.509 SVID)
#   6. Register workload entries that map agent identities to workload SPIFFE IDs,
#      wait for SVIDs to be issued to the proxy processes
#
# After completion, run `python3 scripts/test_agents.py` to verify:
#   A1 → A2: ✅ allowed (mTLS succeeds, SPIFFE ID in allow list)
#   A3 → A2: ❌ blocked (mTLS handshake rejected, SPIFFE ID not in allow list)
#   A4 → A2: ✅ allowed
#
# NOTE: macOS bash 3.x compatible — no declare -A, no grep -oP
#
# Usage:
#   ./deploy.sh                              # Full deploy from scratch
#   ./deploy.sh --new --with-admin=alice@contoso.com  # Seed initial portal admin
#   ./deploy.sh --skip-provision             # Rebuild image + redeploy
#   ./deploy.sh --skip-provision --skip-build # Re-attest only (fresh tokens)
#   ./deploy.sh --portal-only                # Rebuild/update portal apps only (no re-attestation)
#   ./deploy.sh --skip-provisioning          # Alias for --skip-provision
#   ./deploy.sh --no-verify                  # Skip post-deploy validation
#   ./deploy.sh --portal                     # Launch portal after success
#   REQUIRE_REAL_CA=false ./deploy.sh        # Allow YAML fallback if Entra CA fails
#   ISP_INITIAL_ADMINS=alice@contoso.com,bob@contoso.com ./deploy.sh --new
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

# shellcheck source=scripts/lib/deploy-config.sh
source "${SCRIPT_DIR}/scripts/lib/deploy-config.sh"
# shellcheck source=scripts/lib/azure-helpers.sh
source "${SCRIPT_DIR}/scripts/lib/azure-helpers.sh"
# shellcheck source=scripts/lib/entra-scope.sh
source "${SCRIPT_DIR}/scripts/lib/entra-scope.sh"

SKIP_PROVISION=false
SKIP_BUILD=false
RUN_VERIFY=true
LAUNCH_PORTAL=false
SHOW_HELP=false
HAD_INVALID_ARG=false
PORTAL_ONLY=false
GOOGLE_AGENT=false
GITHUB_AGENT=false

REUSE_ENV=""
NEW_ENV=false
WITH_ADMIN_ARGS=""

for arg in "$@"; do
    case $arg in
        --skip-provision|--skip-provisioning) SKIP_PROVISION=true ;;
        --skip-build) SKIP_BUILD=true ;;
        --portal-only) PORTAL_ONLY=true ;;
        --no-verify) RUN_VERIFY=false ;;
        --verify) RUN_VERIFY=true ;;
        --portal) LAUNCH_PORTAL=true ;;
        --no-portal) LAUNCH_PORTAL=false ;;
        --new) NEW_ENV=true ;;
        --google) GOOGLE_AGENT=true ;;
        --github) GITHUB_AGENT=true ;;
        --help|-h) SHOW_HELP=true ;;
        --reuse=*) REUSE_ENV="${arg#--reuse=}" ;;
        --with-admin=*)
            _val="${arg#--with-admin=}"
            if [ -z "$_val" ]; then
                echo "ERROR: --with-admin requires a value (UPN/email or object ID)" >&2
                SHOW_HELP=true
                HAD_INVALID_ARG=true
            elif [ -z "$WITH_ADMIN_ARGS" ]; then
                WITH_ADMIN_ARGS="$_val"
            else
                WITH_ADMIN_ARGS="${WITH_ADMIN_ARGS},${_val}"
            fi
            unset _val
            ;;
        *)
            echo "ERROR: Unknown argument: $arg" >&2
            SHOW_HELP=true
            HAD_INVALID_ARG=true
            ;;
    esac
done

if [ "$PORTAL_ONLY" = true ]; then
    SKIP_PROVISION=true
    RUN_VERIFY=false
    if [ "$GOOGLE_AGENT" = true ]; then
        echo "ERROR: --google cannot be used with --portal-only" >&2
        exit 1
    fi
    if [ "$GITHUB_AGENT" = true ]; then
        echo "ERROR: --github cannot be used with --portal-only" >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Google Cloud preflight — validate BEFORE spending 20 min on Azure deploy
# ---------------------------------------------------------------------------
if [ "$GOOGLE_AGENT" = true ]; then
    echo ""
    echo "🔍 Google Cloud preflight checks..."
    _google_ok=true

    if ! command -v gcloud &>/dev/null; then
        echo "   ❌ gcloud CLI not found. Install: brew install google-cloud-sdk"
        _google_ok=false
    else
        echo "   ✅ gcloud CLI found"
        if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 | grep -q "@"; then
            echo "   ❌ gcloud not authenticated. Run: gcloud auth login"
            _google_ok=false
        else
            echo "   ✅ gcloud authenticated"
        fi
    fi

    # Load azd env to check GCP_PROJECT
    _preflight_values=$(azd env get-values 2>/dev/null || true)
    _gcp_project=$(echo "$_preflight_values" | grep "^GCP_PROJECT=" | head -1 | cut -d'"' -f2 || true)
    if [ -z "$_gcp_project" ]; then
        echo "   ❌ GCP_PROJECT not set"
        echo ""
        echo "   Set it now with:"
        echo "     azd env set GCP_PROJECT <your-gcp-project-id>"
        echo ""
        echo "   If you don't have a GCP project yet, the script will create one."
        echo "   You'll also need a billing account:"
        echo "     azd env set GCP_BILLING_ID <billing-account-id>"
        echo "     (find yours with: gcloud billing accounts list)"
        _google_ok=false
    else
        echo "   ✅ GCP_PROJECT=$_gcp_project"
    fi

    if [ "$_google_ok" = false ]; then
        echo ""
        echo "   Fix the above issues and re-run: ./deploy.sh --google"
        exit 1
    fi

    # Early GCP environment health check — warn upfront about missing resources
    if [ -n "$_gcp_project" ]; then
        _gcp_region=$(echo "$_preflight_values" | grep "^GCP_REGION=" | head -1 | cut -d'"' -f2 || true)
        _gcp_region="${_gcp_region:-us-west1}"
        _rg_preflight=$(echo "$_preflight_values" | grep "^AZURE_RESOURCE_GROUP_NAME=" | head -1 | cut -d'"' -f2 || true)

        echo "   Checking GCP environment state..."
        _early_missing=0
        _early_vm=$(gcloud compute instances describe google-budget-reader \
            --zone "${_gcp_region}-a" --project "$_gcp_project" \
            --format "value(status)" 2>/dev/null || true)
        [ -z "$_early_vm" ] && _early_missing=$((_early_missing + 1))

        _early_vpc=$(gcloud compute networks describe isp-crosscloud \
            --project "$_gcp_project" --format "value(name)" 2>/dev/null || true)
        [ -z "$_early_vpc" ] && _early_missing=$((_early_missing + 1))

        _early_vpn=$(gcloud compute vpn-tunnels list --project "$_gcp_project" \
            --filter "name:isp-vpn" --format "value(name)" 2>/dev/null || true)
        [ -z "$_early_vpn" ] && _early_missing=$((_early_missing + 1))

        _early_az_vpn=""
        if [ -n "$_rg_preflight" ]; then
            _early_az_vpn=$(az network vnet-gateway list -g "$_rg_preflight" \
                --query "[0].name" -o tsv 2>/dev/null || true)
            [ -z "$_early_az_vpn" ] && _early_missing=$((_early_missing + 1))
        fi

        if [ "$_early_missing" -ge 3 ]; then
            echo ""
            echo "   ⚠️  GCP environment appears torn down (${_early_missing} core resources missing)."
            echo "   ⚠️  Full rebuild required. Expect ~45 min for VPN Gateway provisioning."
            [ -z "$_early_vm" ]     && echo "      ❌ GCE VM: google-budget-reader"
            [ -z "$_early_vpc" ]    && echo "      ❌ VPC: isp-crosscloud"
            [ -z "$_early_vpn" ]    && echo "      ❌ GCP VPN tunnel"
            [ -z "$_early_az_vpn" ] && echo "      ❌ Azure VPN Gateway"
            echo ""
        elif [ "$_early_missing" -gt 0 ]; then
            echo "   ⚠️  ${_early_missing} GCP resource(s) missing — will be provisioned."
            [ -z "$_early_vm" ]     && echo "      ❌ GCE VM: google-budget-reader"
            [ -z "$_early_vpn" ]    && echo "      ❌ GCP VPN tunnel (~30 min)"
            [ -z "$_early_az_vpn" ] && echo "      ❌ Azure VPN Gateway (~30 min)"
        else
            echo "   ✅ GCP environment looks healthy"
        fi
    fi
    echo ""
fi

# ---------------------------------------------------------------------------
# GitHub Actions preflight — validate BEFORE spending 20 min on Azure deploy
# ---------------------------------------------------------------------------
if [ "$GITHUB_AGENT" = true ]; then
    echo ""
    echo "🔍 GitHub Actions preflight checks..."
    _github_ok=true

    # Load azd env early for preflight (main AZD_VALUES is set later at line ~808)
    _preflight_azd=$(azd_env_load)

    GITHUB_ORG=$(azd_env_get_from_blob "$_preflight_azd" "GITHUB_ORG")
    if [ -z "$GITHUB_ORG" ]; then
        GITHUB_ORG="microsoft"
    fi

    GITHUB_REPO=$(azd_env_get_from_blob "$_preflight_azd" "GITHUB_REPO")
    if [ -z "$GITHUB_REPO" ]; then
        GITHUB_REPO="identity-spiffe"
    fi

    if ! command -v gh &>/dev/null; then
        echo "   ❌ gh CLI not found. Install: brew install gh"
        _github_ok=false
    else
        echo "   ✅ gh CLI found"
    fi

    # Check gh auth
    if command -v gh &>/dev/null; then
        if ! gh auth status &>/dev/null; then
            echo "   ❌ gh not authenticated. Run: gh auth login"
            _github_ok=false
        else
            echo "   ✅ gh authenticated"
        fi
    fi

    echo "   GitHub org:  $GITHUB_ORG"
    echo "   GitHub repo: $GITHUB_REPO"

    if [ "$_github_ok" = false ]; then
        echo ""
        echo "   Fix the above issues and re-run: ./deploy.sh --github"
        exit 1
    fi
fi

# Runtime values populated later from azd env / Azure resource queries. Initialize
# them explicitly so `set -u` doesn't break skip-paths like --portal-only.
ENTRA_ID_BUDGET_REPORT=""
ENTRA_ID_BUDGET_BACKEND=""
ENTRA_ID_EMPLOYEE_MENUS=""
ENTRA_ID_BUDGET_APPROVAL=""
ENTRA_ID_ADMIN_CONTROL_PLANE=""
ENTRA_OAUTH2_AUDIENCE=""
AZURE_TENANT_ID_VAL=""
MI_CLIENT_ID_BUDGET_REPORT=""
MI_CLIENT_ID_BUDGET_APPROVAL=""
MI_CLIENT_ID_EMPLOYEE_MENUS=""

ensure_containerapp_envs() {
    local app_name="$1"
    shift

    if [ "$#" -eq 0 ]; then
        return 0
    fi

    local live_env_names
    live_env_names=$(az containerapp show \
        --name "$app_name" \
        --resource-group "$RESOURCE_GROUP" \
        --query "properties.template.containers[?name=='${app_name}'].env[].name" \
        -o tsv 2>/dev/null || true)

    local missing_pairs=()
    local pair key
    for pair in "$@"; do
        key=${pair%%=*}
        if ! printf '%s\n' "$live_env_names" | grep -qx "$key"; then
            missing_pairs+=("$pair")
        fi
    done

    if [ "${#missing_pairs[@]}" -eq 0 ]; then
        return 0
    fi

    echo "   ⚠️  ${app_name} missing critical env: $(printf '%s ' "${missing_pairs[@]%%=*}")"
    echo "   Repairing live env on ${app_name}..."
    az containerapp update \
        --name "$app_name" \
        --resource-group "$RESOURCE_GROUP" \
        --container-name "$app_name" \
        --set-env-vars "${missing_pairs[@]}" >/dev/null
    echo "   ✓ ${app_name} env repaired"
}

export_containerapp_yaml_with_retry() {
    local app_name="$1"
    local resource_group="$2"
    local yaml_file="$3"
    local attempts="${4:-6}"
    local wait_secs="${5:-10}"
    local raw_file
    local err_file
    local attempt
    local err_output=""

    raw_file="$(mktemp "${TMPDIR:-/tmp}/aca-show.yaml.XXXXXX")"
    err_file="$(mktemp "${TMPDIR:-/tmp}/aca-show.err.XXXXXX")"

    for attempt in $(seq 1 "$attempts"); do
        if az containerapp show \
            --name "$app_name" \
            --resource-group "$resource_group" \
            -o yaml >"$raw_file" 2>"$err_file"; then
            grep -v 'revisionSuffix' "$raw_file" > "$yaml_file"
            rm -f "$raw_file" "$err_file"
            return 0
        fi

        err_output=$(tail -1 "$err_file" 2>/dev/null || true)
        echo "   ⏳ ${app_name}: failed to export Container App spec (attempt ${attempt}/${attempts})"
        [ -n "$err_output" ] && echo "      ${err_output}"
        if [ "$attempt" -lt "$attempts" ]; then
            sleep "$wait_secs"
        fi
    done

    echo "ERROR: Unable to export Container App spec for '${app_name}' from resource group '${resource_group}'." >&2
    [ -n "$err_output" ] && echo "Last Azure CLI error: ${err_output}" >&2
    rm -f "$raw_file" "$err_file"
    return 1
}

apply_containerapp_yaml_with_retry() {
    local app_name="$1"
    local resource_group="$2"
    local yaml_file="$3"
    local attempts="${4:-4}"
    local wait_secs="${5:-15}"
    local attempt
    local output=""

    for attempt in $(seq 1 "$attempts"); do
        output=$(az containerapp update \
            --name "$app_name" \
            --resource-group "$resource_group" \
            --yaml "$yaml_file" 2>&1) && {
            printf '%s\n' "$output" | tail -3
            return 0
        }

        echo "   ⏳ ${app_name}: Container App update failed (attempt ${attempt}/${attempts})"
        printf '%s\n' "$output" | tail -3
        if [ "$attempt" -lt "$attempts" ]; then
            sleep "$wait_secs"
        fi
    done

    echo "ERROR: Failed to apply updated Container App spec for '${app_name}'." >&2
    return 1
}

json_get_field() {
    local json_input="$1"
    local field="$2"
    printf '%s' "$json_input" | python3 -c "import json, sys; data=json.load(sys.stdin); print(data.get(sys.argv[1], '') if isinstance(data, dict) else '')" "$field" 2>/dev/null || true
}

run_az_step() {
    local description="$1"
    shift
    local output=""
    if ! output=$("$@" 2>&1); then
        echo "ERROR: ${description}" >&2
        if [ -n "$output" ]; then
            printf '%s\n' "$output" >&2
        fi
        return 1
    fi
}

ensure_portal_group() {
    local stored_id="$1"
    local display_name="$2"
    local mail_nickname="$3"
    local group_id="$stored_id"
    local group_json="{}"
    local resolved_display_name=""

    if [ -n "$group_id" ]; then
        group_json=$(az ad group show --group "$group_id" --query "{id:id,displayName:displayName}" -o json 2>/dev/null || echo '{}')
        group_id=$(json_get_field "$group_json" "id")
        resolved_display_name=$(json_get_field "$group_json" "displayName")
        if [ -z "$group_id" ]; then
            echo "   Stored group id not found for ${display_name}; falling back to display-name lookup" >&2
        elif [ "$resolved_display_name" != "$display_name" ]; then
            echo "   Stored group id points to '${resolved_display_name}', not '${display_name}'; falling back to display-name lookup" >&2
            group_id=""
        fi
    fi

    if [ -z "$group_id" ]; then
        group_id=$(az ad group list --filter "displayName eq '${display_name}'" --query "[0].id" -o tsv 2>/dev/null || true)
    fi

    if [ -z "$group_id" ]; then
        echo "   Creating '${display_name}' security group..." >&2
        group_id=$(az ad group create \
            --display-name "$display_name" \
            --mail-nickname "$mail_nickname" \
            --query "id" -o tsv)
        echo "   ✅ Created: ${group_id}" >&2
    else
        echo "   Group ready: ${display_name} (${group_id})" >&2
    fi

    printf '%s\n' "$group_id"
}

build_redirect_uris_json() {
    python3 - "$@" <<'PY'
import json
import sys

uris = [uri for uri in sys.argv[1:] if uri]
print(json.dumps(uris))
PY
}

build_portal_images() {
    local cache_bust_val
    cache_bust_val=$(date +%s)

    echo ""
    echo "🌐 Building portal images..."
    echo "   Building isp-portal:${IMAGE_TAG} (cache-bust=${cache_bust_val})..."
    az acr build \
        --registry "$ACR_NAME" \
        --image "isp-portal:${IMAGE_TAG}" \
        --file portal/Dockerfile \
        --build-arg "CACHE_BUST=${cache_bust_val}" \
        --build-arg "BUILD_VERSION=${IMAGE_TAG}" \
        .

    echo "   Building securityportal-mock:${IMAGE_TAG} (cache-bust=${cache_bust_val})..."
    az acr build \
        --registry "$ACR_NAME" \
        --image "securityportal-mock:${IMAGE_TAG}" \
        --file securityportal-mock/Dockerfile \
        --build-arg "CACHE_BUST=${cache_bust_val}" \
        --build-arg "BUILD_VERSION=${IMAGE_TAG}" \
        .

    echo "✅ Portal images built"
}

ensure_portal_app() {
    local stored_client_id="$1"
    local display_name="$2"
    local primary_redirect="$3"
    local localhost_redirect="$4"
    local app_id="$stored_client_id"
    local app_obj_id=""
    local app_json="{}"
    local primary_redirect_with_slash=""
    local redirect_uris_json=""
    local existing_permissions=""
    local existing_grants=""

    if [ -n "$app_id" ]; then
        app_json=$(az ad app show --id "$app_id" --query "{appId: appId, id: id}" -o json 2>/dev/null || echo '{}')
        app_id=$(json_get_field "$app_json" "appId")
        app_obj_id=$(json_get_field "$app_json" "id")
        if [ -z "$app_id" ]; then
            echo "   Stored app id not found for ${display_name}; falling back to display-name lookup" >&2
        fi
    fi

    if [ -z "$app_id" ]; then
        app_json=$(az ad app list --display-name "$display_name" --query "[0].{appId: appId, id: id}" -o json 2>/dev/null || echo '{}')
        app_id=$(json_get_field "$app_json" "appId")
        app_obj_id=$(json_get_field "$app_json" "id")
    fi

    if [ -z "$app_id" ]; then
        echo "   Creating '${display_name}' app registration..." >&2
        app_json=$(az ad app create \
            --display-name "$display_name" \
            --sign-in-audience "AzureADMyOrg" \
            --enable-id-token-issuance true \
            --query "{appId: appId, id: id}" -o json 2>/dev/null || echo '{}')
        app_id=$(json_get_field "$app_json" "appId")
        app_obj_id=$(json_get_field "$app_json" "id")
    else
        echo "   App ready: ${display_name} (${app_id})" >&2
    fi

    if [ -n "$app_id" ] && [ -z "$app_obj_id" ]; then
        app_json=$(az ad app show --id "$app_id" --query "{appId: appId, id: id}" -o json 2>/dev/null || echo '{}')
        app_obj_id=$(json_get_field "$app_json" "id")
    fi

    if [ -n "$app_id" ] && [ -n "$app_obj_id" ]; then
        if [ -n "$primary_redirect" ]; then
            primary_redirect_with_slash="${primary_redirect}/"
        fi
        redirect_uris_json=$(build_redirect_uris_json "$primary_redirect_with_slash" "$localhost_redirect")
        run_az_step "Failed to configure redirect URIs and token claims for ${display_name}" \
            az rest --method PATCH \
            --uri "https://graph.microsoft.com/v1.0/applications/${app_obj_id}" \
            --headers "Content-Type=application/json" \
            --body "{\"spa\":{\"redirectUris\":${redirect_uris_json}},\"groupMembershipClaims\":\"SecurityGroup\",\"optionalClaims\":{\"idToken\":[{\"name\":\"groups\",\"essential\":false,\"additionalProperties\":[]}],\"accessToken\":[{\"name\":\"groups\",\"essential\":false,\"additionalProperties\":[]}]}}"
        existing_permissions=$(az ad app permission list --id "$app_id" \
            --query "[?resourceAppId=='00000003-0000-0000-c000-000000000000'].resourceAccess[].id" -o tsv 2>/dev/null || true)
        if ! printf '%s\n' "$existing_permissions" | grep -qx "e1fe6dd8-ba31-4d61-89e7-88639da4683d"; then
            run_az_step "Failed to add User.Read permission to ${display_name}" \
                az ad app permission add --id "$app_id" --api 00000003-0000-0000-c000-000000000000 --api-permissions e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope
        fi
        if ! az ad sp show --id "$app_id" >/dev/null 2>&1; then
            run_az_step "Failed to create service principal for ${display_name}" \
                az ad sp create --id "$app_id"
        fi
        existing_grants=$(az ad app permission list-grants --id "$app_id" \
            --query "[?contains(scope, 'User.Read')].scope" -o tsv 2>/dev/null || true)
        if ! printf '%s\n' "$existing_grants" | grep -qw "User.Read"; then
            run_az_step "Failed to grant User.Read permission to ${display_name}" \
                az ad app permission grant --id "$app_id" --api 00000003-0000-0000-c000-000000000000 --scope "User.Read"
        fi
    else
        echo "ERROR: Failed to resolve app registration identifiers for ${display_name}" >&2
        return 1
    fi

    printf '%s\t%s\n' "$app_id" "$app_obj_id"
}

VM_RUN_COUNTER=0
VM_RUN_EPOCH=$(date +%s)
if [ "$SHOW_HELP" = true ]; then
    cat <<EOF
Usage: ./deploy.sh [options]

Options:
  --skip-provision, --skip-provisioning  Skip azd provision and propagation wait
  --skip-build                           Skip az acr build and azd deploy
  --portal-only                          Rebuild/update only the portal apps (skip SPIRE + re-attestation)
  --no-verify                            Skip scripts/test_agents.py
  --portal                               Launch portal after a successful deploy
  --no-portal                            Do not launch portal (default)
  --new                                  Force a new deployment (skip environment detection)
  --reuse=<rg-name>                      Reuse an existing resource group (non-interactive)
  --with-admin=<upn|oid>                 Add a tenant user to the portal Administrators group
                                         (repeatable; UPN/email or object ID; also reads
                                         ISP_INITIAL_ADMINS env var, comma-separated).
                                         Without this, only the signed-in az CLI user is added.
  --google                               Also deploy a Google Cloud cross-cloud agent
  --github                               Also deploy a GitHub Actions self-hosted runner agent
  --aws                                  (future) AWS cross-cloud agent
  --servicenow                           (future) ServiceNow cross-cloud agent
  --help, -h                             Show this help

Environment:
  REQUIRE_REAL_CA=false                  Allow YAML fallback if real Entra CA provisioning fails
  ISP_INITIAL_ADMINS=<upn|oid>[,...]     Comma-separated list of users to seed into the portal
                                         Administrators group (alternative to --with-admin)
EOF
    if [ "$HAD_INVALID_ARG" = true ]; then
        exit 1
    fi
    exit 0
fi

for cmd in az azd python3 pip3; do
    require_command "$cmd"
done

REQUIRE_REAL_CA="${REQUIRE_REAL_CA:-true}"

# ---------------------------------------------------------------------------
# Enforce identity-spiffe / isp-* naming convention for azd environments
# ---------------------------------------------------------------------------
# Resource groups are named rg-${AZURE_ENV_NAME}. The detection logic at Step 0
# searches for rg-identity-spiffe* and rg-isp-* — any env not matching one of
# those becomes invisible to its own environment detection and violates the
# agreed naming convention.
AZD_ENV_NAME=$(azd env get-values 2>/dev/null | grep -E "^AZURE_ENV_NAME=" | cut -d'=' -f2- | tr -d '"' || true)
if [ -n "$AZD_ENV_NAME" ] && [[ ! "$AZD_ENV_NAME" =~ ^(identity-spiffe|isp-) ]]; then
    echo "❌ azd environment name '${AZD_ENV_NAME}' does not follow the identity-spiffe / isp-* naming convention."
    echo "   Resource group would be 'rg-${AZD_ENV_NAME}' instead of 'rg-identity-spiffe' or 'rg-isp-*'."
    echo ""
    echo "   Fix: create a new azd environment with a conforming name:"
    echo "     azd env new identity-spiffe        # default"
    echo "     azd env select identity-spiffe"
    echo "     ./deploy.sh"
    echo ""
    echo "   Or use a scoped name like 'isp-dev':"
    echo "     azd env new isp-dev"
    echo "     azd env select isp-dev"
    echo "     ./deploy.sh"
    exit 1
fi

# ---------------------------------------------------------------------------
# Ensure AZURE_LOCATION is set (azd needs this for subscription-level deploys)
# ---------------------------------------------------------------------------
# Bicep hardcodes location='westus' for resources, but azd itself needs
# AZURE_LOCATION to create the ARM deployment object. A fresh `azd env new`
# leaves this blank, causing a cryptic "location property must be specified" error.
AZURE_LOCATION=$(azd env get-values 2>/dev/null | grep -E "^AZURE_LOCATION=" | cut -d'=' -f2- | tr -d '"' || true)
if [ -z "$AZURE_LOCATION" ]; then
    echo "📍 Setting AZURE_LOCATION=westus (matches Bicep default)"
    azd env set AZURE_LOCATION westus
fi

if ! validate_entra_scope; then
    exit 1
fi

if [ "$NEW_ENV" = true ] && [ "${ISP_ENV_SCOPE_MODE_SOURCE:-}" = "auto-legacy" ]; then
    echo "❌ This azd environment resolved to legacy Entra naming because it already has stored legacy bootstrap IDs."
    echo "   A new deployment must not silently reuse the legacy Blueprint/FIC/group/app objects."
    echo "   Clear the copied azd env values or set ISP_ENV_SCOPE_MODE=scoped before rerunning."
    exit 1
fi

echo "🧭 Entra scope preflight:"
print_entra_scope_summary "budget-report" "budget-backend" "employee-menus" "budget-approval" "admin-control-plane"
echo ""

# ---------------------------------------------------------------------------
# SSH key detection (optional — for manual SSH access to SPIRE VM)
# ---------------------------------------------------------------------------
# deploy.sh uses az vm run-command (managed API) for all SPIRE Server VM
# operations. SSH keys are still injected into the VM via Bicep for manual
# debugging access, but are NOT required for deployment.
SSH_PUB_KEY=""
for keyfile in ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub ~/.ssh/id_ecdsa.pub; do
    if [ -f "$keyfile" ]; then
        SSH_PUB_KEY=$(cat "$keyfile")
        echo "🔑 SSH key detected: ${keyfile} (for manual VM access)"
        break
    fi
done

if [ -z "$SSH_PUB_KEY" ]; then
    echo "   (No SSH key found — manual VM access unavailable, deployment unaffected)"
fi

# Set in azd env so Bicep picks it up via readEnvironmentVariable (optional)
export adminSshPublicKey="${SSH_PUB_KEY:-}"

# =============================================================================
# Step 0: Detect existing Identity Research for Agent Management Using SPIFFE environments in the subscription
# =============================================================================
# Queries the active subscription for resource groups matching the
# identity-spiffe / isp-* naming convention. If an existing environment is
# found, offers to reuse it (which implies --skip-provision) or proceed with
# a fresh deployment.
ISP_RG_PREFIXES=("rg-identity-spiffe" "rg-isp-")

detect_existing_environment() {
    echo "🔍 Checking for existing Identity Research for Agent Management Using SPIFFE environments in subscription..."
    local sub_name
    sub_name=$(az account show --query "name" -o tsv 2>/dev/null || echo "unknown")
    local sub_id
    sub_id=$(az account show --query "id" -o tsv 2>/dev/null || echo "unknown")
    echo "   Subscription: ${sub_name} (${sub_id})"

    local query_filter=""
    for p in "${ISP_RG_PREFIXES[@]}"; do
        [ -n "$query_filter" ] && query_filter+=" || "
        query_filter+="starts_with(name,'${p}')"
    done
    local existing_rgs
    existing_rgs=$(az group list \
        --query "[?${query_filter}].{name:name, location:location, state:properties.provisioningState}" \
        -o tsv 2>/dev/null || true)

    if [ -z "$existing_rgs" ]; then
        echo "   No existing Identity Research for Agent Management Using SPIFFE environments found (no resource groups matching '${ISP_RG_PREFIXES[*]}')"
        echo ""
        return 1
    fi

    echo ""
    echo "   Found existing Identity Research for Agent Management Using SPIFFE environment(s):"
    echo "   ──────────────────────────────────────────────"
    local rg_count=0
    local rg_names=()
    while IFS=$'\t' read -r rg_name rg_location rg_state; do
        rg_count=$((rg_count + 1))
        rg_names+=("$rg_name")
        # Query resource count inside the group
        local res_count
        res_count=$(az resource list --resource-group "$rg_name" --query "length([])" -o tsv 2>/dev/null || echo "?")
        echo "   [$rg_count] ${rg_name}  (${rg_location}, ${rg_state}, ${res_count} resources)"
    done <<< "$existing_rgs"
    echo "   ──────────────────────────────────────────────"
    echo ""

    # Non-interactive: --reuse=<name> was passed
    if [ -n "$REUSE_ENV" ]; then
        local found=false
        for rg_name in "${rg_names[@]}"; do
            if [ "$rg_name" = "$REUSE_ENV" ]; then
                found=true
                break
            fi
        done
        if [ "$found" = true ]; then
            echo "   ✅ Reusing existing environment: ${REUSE_ENV} (--reuse)"
            SKIP_PROVISION=true
            return 0
        else
            echo "   ❌ --reuse=${REUSE_ENV} does not match any discovered resource group" >&2
            return 1
        fi
    fi

    # Interactive: ask the user
    if is_tty_stdin; then
        echo "   Options:"
        echo "     [R] Reuse existing environment (skip provisioning)"
        echo "     [N] Deploy a new environment"
        echo "     [Q] Quit"
        echo ""
        printf "   Choose [R/N/Q]: "
        local choice
        read -r choice
        case "$choice" in
            [Rr]*)
                if [ "$rg_count" -eq 1 ]; then
                    echo "   ✅ Reusing: ${rg_names[0]}"
                    SKIP_PROVISION=true
                    return 0
                else
                    printf "   Which environment? [1-%d]: " "$rg_count"
                    local idx
                    read -r idx
                    if [ "$idx" -ge 1 ] 2>/dev/null && [ "$idx" -le "$rg_count" ] 2>/dev/null; then
                        echo "   ✅ Reusing: ${rg_names[$((idx - 1))]}"
                        SKIP_PROVISION=true
                        return 0
                    else
                        echo "   ❌ Invalid selection" >&2
                        exit 1
                    fi
                fi
                ;;
            [Nn]*)
                echo "   → Proceeding with new deployment"
                return 1
                ;;
            [Qq]*)
                echo "   Aborted."
                exit 0
                ;;
            *)
                echo "   ❌ Invalid choice. Aborting." >&2
                exit 1
                ;;
        esac
    else
        # Non-interactive, no --reuse flag: warn and proceed with new deploy
        echo "   ⚠️  Existing environment found but running non-interactively."
        echo "   Use --reuse=<rg-name> to reuse, or --new to skip this check."
        echo "   Proceeding with new deployment..."
        return 1
    fi
}

if [ "$SKIP_PROVISION" = false ] && [ "$NEW_ENV" = false ]; then
    detect_existing_environment || true
fi

vm_run() {
    local cmd_name="$1"
    local script="$2"
    local timeout_secs="${3:-300}"
    echo "   [vm-run] ${cmd_name}..."
    azure_vm_run "$RG" "$SPIRE_SERVER_VM_NAME" "$cmd_name" "$script" "$timeout_secs"
}

echo ""
echo "============================================="
echo "  Identity Research for Agent Management Using SPIFFE - SPIFFE mTLS PoC"
echo "  Attestation: join_token"
echo "  SPIRE Server: Azure VM"
echo "  Trust Domain: ${TRUST_DOMAIN}"
echo "  Image Tag: ${IMAGE_TAG}"
echo "  REQUIRE_REAL_CA: ${REQUIRE_REAL_CA}"
echo "  PORTAL_ONLY: ${PORTAL_ONLY}"
echo "============================================="
echo ""

# =============================================================================
# Step 1: Provision infrastructure
# =============================================================================
# Creates: Resource Group, Azure Container Registry, Container Apps Environment,
# four Container Apps (each with a FastAPI container + empty sidecar slot),
# and a VM (Standard_B1s) with cloud-init that installs Docker.
# Bicep templates in infra/ define all resources.
if [ "$SKIP_PROVISION" = true ]; then
    echo "⏭️  Step 1/6: Skipping provision (--skip-provision)"
else
    # Set cross-cloud Bicep params before provisioning so they're included
    # in the first azd provision run (avoids a second provision cycle later)
    if [ "$GITHUB_AGENT" = true ]; then
        echo "   Setting deployGitHubRunner=true for Bicep..."
        azd env set DEPLOY_GITHUB_RUNNER true
        azd env set GITHUB_ORG "${GITHUB_ORG:-microsoft}"
        azd env set GITHUB_REPO "${GITHUB_REPO:-identity-spiffe}"
    fi

    echo "🔧 Step 1/6: Provisioning infrastructure..."
    echo "   SPIRE Server → VM (Standard_B1s, Docker via cloud-init)"
    echo "   Agents → Container Apps (with sidecar slots for SPIFFE proxy)"

    azd provision
    echo "✅ Done"
fi
echo ""

# =============================================================================
# Step 2: Wait for AcrPull role propagation + VM cloud-init
# =============================================================================
# Why 90s? Two things need to happen in parallel:
#   1. User-assigned managed identity AcrPull role takes ~60s to propagate
#   2. VM cloud-init installs Docker (~45s on Standard_B1s)
# Without this wait, `az acr build` or agent image pulls may fail.
if [ "$SKIP_PROVISION" = true ]; then
    echo "⏭️  Step 2/6: Skipping wait"
else
    echo "⏳ Step 2/6: Waiting 90s for AcrPull role propagation + VM cloud-init..."
    echo "   (VM needs time to install Docker via cloud-init)"
    sleep 90
    echo "✅ Done"
fi
echo ""

AZD_VALUES=$(azd_env_load)
RESOURCE_GROUP=$(azd_env_get_from_blob "$AZD_VALUES" "AZURE_RESOURCE_GROUP")

# Fallback RG discovery when AZURE_RESOURCE_GROUP isn't in azd env
# (common with --skip-provision on environments created before this was persisted)
if [ -z "$RESOURCE_GROUP" ]; then
    RESOURCE_GROUP=$(az group list --query "[?tags.project=='isp-prototype-platform'] | [0].name" -o tsv 2>/dev/null || true)
fi
if [ -z "$RESOURCE_GROUP" ]; then
    RESOURCE_GROUP=$(az group list --query "[?contains(name,'isp-') || contains(name,'identity-spiffe')] | [0].name" -o tsv 2>/dev/null || true)
fi
RG="$RESOURCE_GROUP"

# =============================================================================
# Step 2.5: Bootstrap Entra deploy permissions
# =============================================================================
SKIP_ENTRA=${SKIP_ENTRA:-false}
if [ "$PORTAL_ONLY" = true ]; then
    echo "⏭️  Step 2.5: Skipped Entra bootstrap (--portal-only)"
elif [ "$SKIP_ENTRA" = true ]; then
    echo "⏭️  Step 2.5: Skipped Entra bootstrap (SKIP_ENTRA=true)"
else
    echo "🔐 Step 2.5: Ensuring dedicated Entra provisioner app + Graph permissions..."
    ./scripts/setup-entra-deploy-permissions.sh
    echo "✅ Entra provisioner bootstrap complete"
fi
echo ""

# =============================================================================
# Step 2.6: Read Entra Agent Identity OIDs
# =============================================================================
# These OIDs define the SPIFFE ID format:
#   spiffe://aim.microsoft.com/ests/bp/<blueprint-oid>/aid/<agent-oid>
# Reads from azd env: ENTRA_BLUEPRINT_OBJECT_ID and ENTRA_AGENT_ID_* (set by create-entra-agent-ids.py).
# Falls back to placeholder UUIDs if not provisioned yet.
ENTRA_BP_OID=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_BLUEPRINT_OBJECT_ID")
ENTRA_BP_OID="${ENTRA_BP_OID:-00000000-0000-0000-0000-000000000001}"
ENTRA_AGENT_OID_BUDGET_REPORT=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_REPORT")
ENTRA_AGENT_OID_BUDGET_REPORT="${ENTRA_AGENT_OID_BUDGET_REPORT:-00000000-0000-0000-0000-000000000010}"
ENTRA_AGENT_OID_BUDGET_BACKEND=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_BACKEND")
ENTRA_AGENT_OID_BUDGET_BACKEND="${ENTRA_AGENT_OID_BUDGET_BACKEND:-00000000-0000-0000-0000-000000000020}"
ENTRA_AGENT_OID_EMPLOYEE_MENUS=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_EMPLOYEE_MENUS")
ENTRA_AGENT_OID_EMPLOYEE_MENUS="${ENTRA_AGENT_OID_EMPLOYEE_MENUS:-00000000-0000-0000-0000-000000000030}"
ENTRA_AGENT_OID_BUDGET_APPROVAL=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_APPROVAL")
ENTRA_AGENT_OID_BUDGET_APPROVAL="${ENTRA_AGENT_OID_BUDGET_APPROVAL:-00000000-0000-0000-0000-000000000040}"
ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE")
ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE="${ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE:-00000000-0000-0000-0000-000000000050}"

echo "📋 Step 2.6: Entra Agent Identity OIDs"
echo "   Blueprint OID:   ${ENTRA_BP_OID}"
echo "   Budget Report:   ${ENTRA_AGENT_OID_BUDGET_REPORT}"
echo "   Budget Backend:  ${ENTRA_AGENT_OID_BUDGET_BACKEND}"
echo "   Employee Menus:  ${ENTRA_AGENT_OID_EMPLOYEE_MENUS}"
echo "   Budget Approval: ${ENTRA_AGENT_OID_BUDGET_APPROVAL}"
echo "   Admin Control:   ${ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE}"
echo ""

# =============================================================================
# Step 2.7: Create Entra Agent Identities
# =============================================================================
# Creates an Agent Identity Blueprint and per-agent Agent Identities in
# Microsoft Entra ID via the Graph beta API using the dedicated provisioner app.

echo "🔑 Step 2.7: Creating Entra Agent Identities..."

if [ "$PORTAL_ONLY" = true ]; then
    echo "⏭️  Step 2.7: Skipped Entra Agent Identities (--portal-only)"
elif [ "$SKIP_ENTRA" = true ]; then
    echo "⏭️  Step 2.7: Skipped (SKIP_ENTRA=true)"
else
    pip3 install --quiet requests 2>/dev/null || pip3 install --quiet --break-system-packages requests 2>/dev/null || true
    python3 scripts/create-entra-agent-ids.py

    # Read back Entra Agent IDs from azd env
    AZD_VALUES=$(azd_env_load)
    ENTRA_ID_BUDGET_REPORT=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_REPORT")
    ENTRA_ID_BUDGET_BACKEND=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_BACKEND")
    ENTRA_ID_EMPLOYEE_MENUS=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_EMPLOYEE_MENUS")
    ENTRA_ID_BUDGET_APPROVAL=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_APPROVAL")
    ENTRA_ID_ADMIN_CONTROL_PLANE=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE")

    echo "   Budget Report:   ${ENTRA_ID_BUDGET_REPORT:-not set}"
    echo "   Budget Backend:  ${ENTRA_ID_BUDGET_BACKEND:-not set}"
    echo "   Employee Menus:  ${ENTRA_ID_EMPLOYEE_MENUS:-not set}"
    echo "   Budget Approval: ${ENTRA_ID_BUDGET_APPROVAL:-not set}"
    echo "   Admin Control:   ${ENTRA_ID_ADMIN_CONTROL_PLANE:-not set}"

    # Re-read Entra OIDs after create-entra-agent-ids.py may have updated them.
    # Step 2.5 read these BEFORE the script ran, so they may still be placeholder zeros.
    ENTRA_BP_OID=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_BLUEPRINT_OBJECT_ID")
    ENTRA_BP_OID="${ENTRA_BP_OID:-00000000-0000-0000-0000-000000000001}"
    ENTRA_AGENT_OID_BUDGET_REPORT=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_REPORT")
    ENTRA_AGENT_OID_BUDGET_REPORT="${ENTRA_AGENT_OID_BUDGET_REPORT:-00000000-0000-0000-0000-000000000010}"
    ENTRA_AGENT_OID_BUDGET_BACKEND=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_BACKEND")
    ENTRA_AGENT_OID_BUDGET_BACKEND="${ENTRA_AGENT_OID_BUDGET_BACKEND:-00000000-0000-0000-0000-000000000020}"
    ENTRA_AGENT_OID_EMPLOYEE_MENUS=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_EMPLOYEE_MENUS")
    ENTRA_AGENT_OID_EMPLOYEE_MENUS="${ENTRA_AGENT_OID_EMPLOYEE_MENUS:-00000000-0000-0000-0000-000000000030}"
    ENTRA_AGENT_OID_BUDGET_APPROVAL=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_APPROVAL")
    ENTRA_AGENT_OID_BUDGET_APPROVAL="${ENTRA_AGENT_OID_BUDGET_APPROVAL:-00000000-0000-0000-0000-000000000040}"
    ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE")
    ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE="${ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE:-00000000-0000-0000-0000-000000000050}"
    echo "   Refreshed Entra OIDs for SPIFFE ID construction:"
    echo "     Blueprint OID:   ${ENTRA_BP_OID}"
    echo "     Budget Report:   ${ENTRA_AGENT_OID_BUDGET_REPORT}"
    echo "     Budget Backend:  ${ENTRA_AGENT_OID_BUDGET_BACKEND}"
    echo "     Employee Menus:  ${ENTRA_AGENT_OID_EMPLOYEE_MENUS}"
    echo "     Budget Approval: ${ENTRA_AGENT_OID_BUDGET_APPROVAL}"
    echo "     Admin Control:   ${ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE}"

    ENTRA_OAUTH2_AUDIENCE=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_OAUTH2_AUDIENCE")
    AZURE_TENANT_ID_VAL=$(azd_env_get_from_blob "$AZD_VALUES" "AZURE_TENANT_ID")

    # Step 2.8: Provision custom security attributes for CA Layer 4
    echo ""
    echo "🏷️  Step 2.8: Provisioning custom security attributes (Layer 4 CA)..."
    if ! python3 scripts/create-custom-attributes.py; then
        if [ "$REQUIRE_REAL_CA" = "false" ]; then
            echo "   ⚠️  Real CA provisioning failed. Continuing because REQUIRE_REAL_CA=false."
            echo "   CA tag enforcement will use YAML fallback values."
        else
            echo "ERROR: Real CA provisioning failed and REQUIRE_REAL_CA is enabled."
            echo "Set REQUIRE_REAL_CA=false only if you explicitly want fallback mode."
            exit 1
        fi
    fi
fi

if [ "$PORTAL_ONLY" != true ]; then
    # Read MI client IDs directly from Container Apps (not azd env) to avoid stale
    # values after azd down --purge recreates Managed Identities with new client IDs.
    MI_CLIENT_ID_BUDGET_REPORT=$(az containerapp show --name budget-report --resource-group "$RESOURCE_GROUP" \
        --query "identity.userAssignedIdentities.*.clientId | [0]" -o tsv 2>/dev/null || true)
    MI_CLIENT_ID_BUDGET_APPROVAL=$(az containerapp show --name budget-approval --resource-group "$RESOURCE_GROUP" \
        --query "identity.userAssignedIdentities.*.clientId | [0]" -o tsv 2>/dev/null || true)
    MI_CLIENT_ID_EMPLOYEE_MENUS=$(az containerapp show --name employee-menus --resource-group "$RESOURCE_GROUP" \
        --query "identity.userAssignedIdentities.*.clientId | [0]" -o tsv 2>/dev/null || true)
    if [ -n "$MI_CLIENT_ID_BUDGET_REPORT" ]; then
        azd_env_set_repo "MI_CLIENT_ID_BUDGET_REPORT" "$MI_CLIENT_ID_BUDGET_REPORT"
    fi
    if [ -n "$MI_CLIENT_ID_BUDGET_APPROVAL" ]; then
        azd_env_set_repo "MI_CLIENT_ID_BUDGET_APPROVAL" "$MI_CLIENT_ID_BUDGET_APPROVAL"
    fi
    if [ -n "$MI_CLIENT_ID_EMPLOYEE_MENUS" ]; then
        azd_env_set_repo "MI_CLIENT_ID_EMPLOYEE_MENUS" "$MI_CLIENT_ID_EMPLOYEE_MENUS"
    fi
    echo "   MI Client IDs (from Container Apps):"
    echo "     budget-report:   ${MI_CLIENT_ID_BUDGET_REPORT:-not set}"
    echo "     budget-approval: ${MI_CLIENT_ID_BUDGET_APPROVAL:-not set}"
    echo "     employee-menus:  ${MI_CLIENT_ID_EMPLOYEE_MENUS:-not set}"
fi

# Also read Entra IDs if previously stored (even if skipped this run)
if [ -z "$ENTRA_ID_BUDGET_REPORT" ]; then
    AZD_VALUES=$(azd_env_load)
    ENTRA_ID_BUDGET_REPORT=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_REPORT")
    ENTRA_ID_BUDGET_BACKEND=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_BACKEND")
    ENTRA_ID_EMPLOYEE_MENUS=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_EMPLOYEE_MENUS")
    ENTRA_ID_BUDGET_APPROVAL=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_APPROVAL")
    ENTRA_ID_ADMIN_CONTROL_PLANE=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE")
    ENTRA_OAUTH2_AUDIENCE=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_OAUTH2_AUDIENCE")
    AZURE_TENANT_ID_VAL=$(azd_env_get_from_blob "$AZD_VALUES" "AZURE_TENANT_ID")
fi

# Ensure OAuth2 vars are always populated, even when SKIP_ENTRA=true and
# ENTRA_ID_BUDGET_REPORT was pre-populated from a previous run (which skips
# the block above). Without this, AZURE_TENANT_ID_VAL and ENTRA_OAUTH2_AUDIENCE
# remain empty, silently disabling Layer 3 JWT enforcement on ALL agents —
# including BudgetApproval's /approval/status A2A endpoint (validate_entra_jwt
# returns None when either env var is missing, causing 401/403 on direct calls).
if [ -z "${AZURE_TENANT_ID_VAL:-}" ] || [ -z "${ENTRA_OAUTH2_AUDIENCE:-}" ]; then
    AZD_VALUES_OAUTH2=$(azd_env_load)
    AZURE_TENANT_ID_VAL=${AZURE_TENANT_ID_VAL:-$(azd_env_get_from_blob "$AZD_VALUES_OAUTH2" "AZURE_TENANT_ID")}
    ENTRA_OAUTH2_AUDIENCE=${ENTRA_OAUTH2_AUDIENCE:-$(azd_env_get_from_blob "$AZD_VALUES_OAUTH2" "ENTRA_OAUTH2_AUDIENCE")}
    # ENTRA_OAUTH2_AUDIENCE is the Blueprint's Application (client) ID, also stored
    # as ENTRA_BLUEPRINT_APP_ID by create-entra-agent-ids.py. Try that as fallback.
    if [ -z "${ENTRA_OAUTH2_AUDIENCE:-}" ]; then
        ENTRA_OAUTH2_AUDIENCE=$(azd_env_get_from_blob "$AZD_VALUES_OAUTH2" "ENTRA_BLUEPRINT_APP_ID")
    fi
fi
# Final fallback: get tenant ID from the active Azure CLI session. This covers
# --skip-provision runs where azd env may not have AZURE_TENANT_ID yet.
if [ -z "${AZURE_TENANT_ID_VAL:-}" ]; then
    AZURE_TENANT_ID_VAL=$(az account show --query tenantId -o tsv 2>/dev/null || true)
fi
echo "   OAuth2 config:"
echo "     AZURE_TENANT_ID:      ${AZURE_TENANT_ID_VAL:-NOT SET}"
echo "     ENTRA_OAUTH2_AUDIENCE: ${ENTRA_OAUTH2_AUDIENCE:-NOT SET}"
if [ -z "${AZURE_TENANT_ID_VAL:-}" ]; then
    echo "   ⚠️  WARNING: AZURE_TENANT_ID is empty — Layer 3 JWT validation will be disabled on all agents"
fi
if [ -z "${ENTRA_OAUTH2_AUDIENCE:-}" ]; then
    echo "   ⚠️  WARNING: ENTRA_OAUTH2_AUDIENCE is empty — Layer 3 JWT validation will be disabled on all agents"
    echo "   Run 'python3 scripts/create-entra-agent-ids.py' to provision the Blueprint app registration"
fi

# Retrieve Graph API credentials for CA policy evaluation (provisioner app)
# Portal and security portal mock need ReadWrite; sidecar + agents need Read.
# Always load fresh azd env to ensure credentials are available regardless of --skip-provision.
AZD_VALUES_GRAPH=$(azd_env_load)
GRAPH_CLIENT_ID=$(azd_env_get_from_blob "$AZD_VALUES_GRAPH" "ENTRA_AGENTID_CLIENT_ID")
GRAPH_CLIENT_SECRET=$(azd_env_get_from_blob "$AZD_VALUES_GRAPH" "ENTRA_AGENTID_CLIENT_SECRET")
if [ -n "${GRAPH_CLIENT_ID:-}" ] && [ -n "${GRAPH_CLIENT_SECRET:-}" ]; then
    echo "   Graph API credentials: ✓ (CA policy evaluation enabled)"
else
    echo "   ⚠️  Graph API credentials not found — CA policy-driven risk enforcement disabled"
    echo "      Run 'python3 scripts/create-entra-agent-ids.py' to provision the Graph app"
fi
echo ""

# =============================================================================
# Step 3: Build spiffe-proxy image + deploy agent apps
# =============================================================================
# `az acr build` compiles the Go proxy and packages it with SPIRE binaries
# into a single Docker image (multi-stage Dockerfile).
# `azd deploy` pushes the FastAPI agent containers to each Container App.
# At this point sidecars have the placeholder image — Step 5 updates them.
ACR_SERVER=$(azd_env_get_from_blob "$AZD_VALUES" "AZURE_CONTAINER_REGISTRY_ENDPOINT")
if [ -z "$ACR_SERVER" ]; then
    ACR_SERVER=$(az acr list -g "$RG" --query "[0].loginServer" -o tsv 2>/dev/null || true)
fi
ACR_NAME=$(echo "$ACR_SERVER" | cut -d'.' -f1)
RG=$(azd_env_get_from_blob "$AZD_VALUES" "AZURE_RESOURCE_GROUP")
if [ -z "$RG" ]; then
    RG="$RESOURCE_GROUP"
fi
SPIRE_SERVER_FQDN=$(azd_env_get_from_blob "$AZD_VALUES" "SPIRE_SERVER_FQDN")
if [ -z "$SPIRE_SERVER_FQDN" ]; then
    SPIRE_SERVER_FQDN=$(az vm show -g "$RG" -n spire-server -d --query fqdns -o tsv 2>/dev/null | cut -d',' -f1 || true)
fi
SPIFFE_IMAGE="${ACR_SERVER}/spiffe-proxy:${IMAGE_TAG}"

# When ACA is VNet-integrated, agents must connect to the SPIRE server via
# its private IP (10.200.0.x), not the public FQDN. The public FQDN resolves
# to the public IP which is blocked by the NSG (only allows 8081 from the ACA
# subnet CIDR). Resolve the private IP from the VM's NIC.
SPIRE_SERVER_PRIVATE_IP=$(az vm show -g "$RG" -n spire-server --show-details --query privateIps -o tsv 2>/dev/null || true)
if [ -n "$SPIRE_SERVER_PRIVATE_IP" ]; then
    SPIRE_AGENT_TARGET="$SPIRE_SERVER_PRIVATE_IP"
else
    SPIRE_AGENT_TARGET="$SPIRE_SERVER_FQDN"
fi

if [ "$PORTAL_ONLY" = true ]; then
    if [ -z "$RG" ] || [ -z "$ACR_SERVER" ]; then
        echo "ERROR: Missing required azd environment values for --portal-only." >&2
        echo "  AZURE_RESOURCE_GROUP=${RG:-<empty>}" >&2
        echo "  AZURE_CONTAINER_REGISTRY_ENDPOINT=${ACR_SERVER:-<empty>}" >&2
        echo "Run a full deploy first so portal resources exist, then rerun with --portal-only." >&2
        exit 1
    fi
elif [ -z "$RG" ] || [ -z "$ACR_SERVER" ] || [ -z "$SPIRE_SERVER_FQDN" ]; then
    echo "ERROR: Missing required azd environment values." >&2
    echo "  AZURE_RESOURCE_GROUP=${RG:-<empty>}" >&2
    echo "  AZURE_CONTAINER_REGISTRY_ENDPOINT=${ACR_SERVER:-<empty>}" >&2
    echo "  SPIRE_SERVER_FQDN=${SPIRE_SERVER_FQDN:-<empty>}" >&2
    echo "Run './deploy.sh' without skip flags first, or verify the active azd environment." >&2
    exit 1
fi

echo "   ACR: ${ACR_SERVER}"
echo "   SPIRE Server FQDN: ${SPIRE_SERVER_FQDN}"
echo "   SPIRE Agent Target: ${SPIRE_AGENT_TARGET} (${SPIRE_SERVER_PRIVATE_IP:+private IP}${SPIRE_SERVER_PRIVATE_IP:-public FQDN})"

# Print portal URLs early so they're visible even if a later step fails
_EARLY_PORTAL_URL=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_ISP_PORTAL_ENDPOINT_URL")
_EARLY_SECURITY_PORTAL_URL=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_SECURITYPORTAL_MOCK_ENDPOINT_URL")
if [ -n "$_EARLY_PORTAL_URL" ]; then
    echo ""
    echo "   Portal:          ${_EARLY_PORTAL_URL}"
    echo "   Security Portal Mock: ${_EARLY_SECURITY_PORTAL_URL}"
fi
echo ""

if [ "$SKIP_BUILD" = true ]; then
    echo "⏭️  Step 3/6: Skipping build (--skip-build)"
elif [ "$PORTAL_ONLY" = true ]; then
    echo "🌐 Step 3/6: Building portal apps only (--portal-only)..."
    build_portal_images
else
    echo "🐳 Step 3/6: Building spiffe-proxy image + deploying agent apps..."

    # Copy shared modules into each agent directory before Docker build
    echo "   Copying shared modules (ca_evaluator.py, entra_token_exchange.py) into agent dirs..."
    for agent_dir in src/budget-report src/budget-backend src/budget-approval src/employee-menus src/admin-control-plane src/demo-agent; do
        if [ -d "$agent_dir" ]; then
            cp src/shared/ca_evaluator.py "$agent_dir/ca_evaluator.py"
            cp src/shared/entra_token_exchange.py "$agent_dir/entra_token_exchange.py"
        fi
    done

    echo "   Building spiffe-proxy:${IMAGE_TAG}..."
    az acr build \
        --registry "$ACR_NAME" \
        --image "spiffe-proxy:${IMAGE_TAG}" \
        --file src/spiffe-proxy/Dockerfile \
        src/spiffe-proxy/

    echo "   Deploying agent apps (FastAPI containers)..."
    azd deploy

    echo "✅ Image: ${SPIFFE_IMAGE}"
    echo "✅ Agent apps deployed"

    # Build portal and security portal mock images
    # CACHE_BUST arg invalidates Docker layer cache after the ARG line,
    # ensuring source file changes are always picked up (see Learning #22).
    CACHE_BUST_VAL=$(date +%s)
    build_portal_images
fi
echo ""

# =============================================================================
# Step 4: Pull image to VM + start SPIRE Server
# =============================================================================
# The VM authenticates to ACR using its managed identity (IMDS → ARM token →
# ACR exchange → Docker login). This is a 3-step OAuth dance because ACR
# doesn't accept ARM tokens directly.
# The SPIRE Server runs with --network host so agents can reach it on port 8081
# via the VM's public FQDN.
MGMT_API_KEY=$(azd_env_get_from_blob "$AZD_VALUES" "MGMT_API_KEY")

if [ "$PORTAL_ONLY" = true ]; then
    if [ -z "$MGMT_API_KEY" ]; then
        echo "ERROR: MGMT_API_KEY is not set in the current azd environment." >&2
        echo "Run a full deploy once so the admin control plane and portal share the same key, then use --portal-only." >&2
        exit 1
    fi
    echo "⏭️  Step 4/6: Skipping SPIRE VM startup (--portal-only)"
    echo ""
else
echo "🔒 Step 4/6: Pulling image to SPIRE Server VM + starting server..."

# The VM guest agent may be slow right after provisioning (cloud-init running,
# Docker installing, etc.). Retry with back-off to ride out resource contention.
SPIRE_SERVER_SCRIPT="
        # Authenticate to ACR via VM managed identity (3-step OAuth)
        ACR_TOKEN=\$(curl -s -H 'Metadata: true' \
            'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
            | jq -r .access_token)

        REFRESH_TOKEN=\$(curl -s -X POST 'https://${ACR_SERVER}/oauth2/exchange' \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            -d \"grant_type=access_token&service=${ACR_SERVER}&access_token=\$ACR_TOKEN\" \
            | jq -r .refresh_token)

        ACCESS_TOKEN=\$(curl -s -X POST 'https://${ACR_SERVER}/oauth2/token' \
            -H 'Content-Type: application/x-www-form-urlencoded' \
            -d \"grant_type=refresh_token&service=${ACR_SERVER}&scope=repository:spiffe-proxy:pull&refresh_token=\$REFRESH_TOKEN\" \
            | jq -r .access_token)

        echo \"\$ACCESS_TOKEN\" | sudo docker login '${ACR_SERVER}' -u 00000000-0000-0000-0000-000000000000 --password-stdin

        sudo docker pull '${SPIFFE_IMAGE}'
        sudo docker stop spire-server 2>/dev/null || true
        sudo docker rm spire-server 2>/dev/null || true
        sudo docker run -d --name spire-server --restart always --network host \
            --log-driver=syslog --log-opt tag=spire-server \
            -e CONTAINER_MODE=server '${SPIFFE_IMAGE}'
        sleep 10
        sudo docker logs spire-server 2>&1 | tail -5
    "

SPIRE_START_OK=false
for attempt in 1 2 3; do
    echo "   [attempt ${attempt}/3] Connecting to SPIRE Server VM..."
    if vm_run "spire-server-start" "$SPIRE_SERVER_SCRIPT" 300; then
        SPIRE_START_OK=true
        break
    fi
    if [ "$attempt" -lt 3 ]; then
        wait_secs=$((attempt * 30))
        echo "   ⏳ VM command failed, waiting ${wait_secs}s before retry..."
        sleep "$wait_secs"
    fi
done

if [ "$SPIRE_START_OK" != true ]; then
    echo "   ERROR: Could not connect to SPIRE Server VM after 3 attempts."
    echo "   Check VM status: az vm get-instance-view -g ${RG} -n spire-server"
    exit 1
fi

echo "✅ SPIRE Server running on VM"
echo ""

# =============================================================================
# Step 4.5: Extract SPIRE trust bundle for secure agent bootstrap
# =============================================================================
# The SPIRE server generates its CA keypair on first startup. We extract the
# trust bundle (the CA's public certificate chain in SPIFFE format) and pass it
# to each agent sidecar so the SPIRE agent can verify the server's identity
# during bootstrap. This eliminates the MITM risk from insecure_bootstrap=true
# (GitHub issue #63).
#
# The bundle is injected as the SPIRE_TRUST_BUNDLE env var. The entrypoint.sh
# writes it to /opt/spire/conf/trust-bundle.pem before starting the agent.
echo "🔐 Step 4.5: Extracting SPIRE trust bundle for secure bootstrap..."

# The B1s VM is resource-starved after pulling/starting the Docker image.
# The guest agent may be slow to respond. Retry with increasing back-off.
SPIRE_TRUST_BUNDLE=""
for attempt in 1 2 3 4 5; do
    echo "   [attempt ${attempt}/5] Extracting trust bundle..."
    BUNDLE_OUTPUT=$(vm_run "trust-bundle" "sudo docker exec spire-server /opt/spire/bin/spire-server bundle show -format pem" 120 2>&1) || true

    # Extract PEM certificates from the vm_run output (which includes wrapper text)
    SPIRE_TRUST_BUNDLE=$(echo "$BUNDLE_OUTPUT" | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' || true)

    if [ -n "$SPIRE_TRUST_BUNDLE" ]; then
        break
    fi

    if [ "$attempt" -lt 5 ]; then
        wait_secs=$((attempt * 15))
        echo "   ⏳ VM not ready yet, waiting ${wait_secs}s before retry..."
        sleep "$wait_secs"
    fi
done

if [ -z "$SPIRE_TRUST_BUNDLE" ]; then
    echo "   ERROR: Failed to extract SPIRE trust bundle after 5 attempts."
    echo "   Last output: ${BUNDLE_OUTPUT}"
    echo "   Cannot proceed - agents would start with no trust anchor."
    exit 1
fi

SPIRE_TRUST_BUNDLE_BYTES=$(printf '%s' "$SPIRE_TRUST_BUNDLE" | wc -c | tr -d ' ')
echo "   Trust bundle extracted (${SPIRE_TRUST_BUNDLE_BYTES} bytes)"
echo ""

# Generate or retrieve management API key (never hardcode in source)
if [ -z "$MGMT_API_KEY" ]; then
    MGMT_API_KEY=$(python3 -c "import secrets; print(secrets.token_hex(24))")
    azd_env_set_repo "MGMT_API_KEY" "$MGMT_API_KEY"
    echo "   Generated new MGMT_API_KEY (stored in azd env)"
else
    echo "   Using existing MGMT_API_KEY from azd env"
fi

# =============================================================================
# Step 5: Generate join tokens + update agent sidecars
# =============================================================================
# For each agent, we:
#   1. Generate a one-time join token on the SPIRE Server
#      - The -spiffeID flag tells SPIRE to auto-create an entry mapping the
#        real join_token agent ID to our friendly name (agent/<name>)
#   2. Export the Container App's current YAML spec
#   3. Inject the token and proxy config into the sidecar container via Python
#   4. Apply the updated YAML, which creates a new Container App revision
#      - The new revision restarts the sidecar with the token
#      - On startup, the sidecar uses the token to attest to SPIRE Server
#      - SPIRE validates the token, issues an X.509 SVID to the agent
#      - The token is consumed and can never be reused
#
# IMPORTANT: Tokens have a 600s (10 min) TTL. The agent must attest within
# that window or the token expires. Container App revision updates typically
# complete in 30-60s, well within the window.
echo "📦 Step 5/6: Generating join tokens + updating agent sidecars..."
echo ""

pip3 install pyyaml --quiet 2>/dev/null || true

# Read Container App FQDNs for A2A endpoint injection (set by azd deploy in Step 3)
AZD_VALS_STEP5=$(azd_env_load)
FQDN_BUDGET_REPORT=$(azd_env_get_from_blob "$AZD_VALS_STEP5" "SERVICE_BUDGET_REPORT_ENDPOINT_URL")
FQDN_EMPLOYEE_MENUS=$(azd_env_get_from_blob "$AZD_VALS_STEP5" "SERVICE_EMPLOYEE_MENUS_ENDPOINT_URL")
FQDN_BUDGET_APPROVAL=$(azd_env_get_from_blob "$AZD_VALS_STEP5" "SERVICE_BUDGET_APPROVAL_ENDPOINT_URL")
FQDN_ADMIN_CONTROL_PLANE=$(azd_env_get_from_blob "$AZD_VALS_STEP5" "SERVICE_ADMIN_CONTROL_PLANE_ENDPOINT_URL")

for AGENT in "${AGENTS[@]}"; do
    echo "   [$AGENT] Generating join token..."

    # Map agent name → Entra Agent OID (from Step 2.5)
    case "$AGENT" in
        budget-report)   AGENT_OID="$ENTRA_AGENT_OID_BUDGET_REPORT" ;;
        budget-backend)  AGENT_OID="$ENTRA_AGENT_OID_BUDGET_BACKEND" ;;
        employee-menus)  AGENT_OID="$ENTRA_AGENT_OID_EMPLOYEE_MENUS" ;;
        budget-approval) AGENT_OID="$ENTRA_AGENT_OID_BUDGET_APPROVAL" ;;
        admin-control-plane) AGENT_OID="$ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE" ;;
        *)               AGENT_OID="" ;;
    esac

    # Map agent name → Entra Agent ID (from Step 2.6)
    case "$AGENT" in
        budget-report)   ENTRA_ID="$ENTRA_ID_BUDGET_REPORT" ;;
        budget-backend)  ENTRA_ID="$ENTRA_ID_BUDGET_BACKEND" ;;
        employee-menus)  ENTRA_ID="$ENTRA_ID_EMPLOYEE_MENUS" ;;
        budget-approval) ENTRA_ID="$ENTRA_ID_BUDGET_APPROVAL" ;;
        admin-control-plane) ENTRA_ID="$ENTRA_ID_ADMIN_CONTROL_PLANE" ;;
        *)               ENTRA_ID="" ;;
    esac

    # The -spiffeID flag causes SPIRE to auto-create a registration entry:
    #   parent: spiffe://.../spire/agent/join_token/<uuid>  (real agent ID)
    #   child:  spiffe://.../agent/<agent-name>             (our friendly name)
    # This is critical for Step 6 — see the parent ID strategy comment there.
    AGENT_SPIFFE_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT}"

    TOKEN_OUTPUT=$(vm_run "token-${AGENT}" "sudo docker exec spire-server /opt/spire/bin/spire-server token generate \
            -spiffeID '${AGENT_SPIFFE_ID}' \
            -ttl 600" 120 2>&1)

    # Extract UUID token (macOS compatible — no grep -oP)
    JOIN_TOKEN=$(echo "$TOKEN_OUTPUT" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)

    if [ -z "$JOIN_TOKEN" ]; then
        echo "   ERROR: Failed to generate token for ${AGENT}"
        echo "   Output: ${TOKEN_OUTPUT}"
        exit 1
    fi

    echo "   [$AGENT] Token: (present, not logged)"

    # a2-resource runs the ingress proxy (accepts incoming mTLS connections)
    # All others run egress proxies (initiate outbound mTLS connections to a2)
    PROXY_MODE=$(agent_proxy_mode "$AGENT")

    # Update the sidecar container via YAML export/modify/apply.
    # We can't use `az containerapp update --set-env-vars` because it resets
    # other containers in multi-container apps. The YAML approach preserves
    # the FastAPI main container while updating only the sidecar.
    echo "   [$AGENT] Updating Container App sidecar..."
    YAML_FILE="$(mktemp "${TMPDIR:-/tmp}/aca-update.XXXXXX")"
    export_containerapp_yaml_with_retry "$AGENT" "$RG" "$YAML_FILE"

    (
        export YAML_FILE="$YAML_FILE"
        export AGENT="$AGENT"
        export SPIFFE_IMAGE="$SPIFFE_IMAGE"
        export PROXY_MODE="$PROXY_MODE"
        export SPIRE_SERVER_FQDN="$SPIRE_SERVER_FQDN"
        export SPIRE_AGENT_TARGET="$SPIRE_AGENT_TARGET"
        export JOIN_TOKEN="$JOIN_TOKEN"
        export AGENT_OID="$AGENT_OID"
        export ENTRA_ID="$ENTRA_ID"
        export ENTRA_BP_OID="$ENTRA_BP_OID"
        export SPIRE_TRUST_BUNDLE="$SPIRE_TRUST_BUNDLE"
        export MGMT_API_KEY="$MGMT_API_KEY"
        export FQDN_BUDGET_REPORT="$FQDN_BUDGET_REPORT"
        export FQDN_EMPLOYEE_MENUS="$FQDN_EMPLOYEE_MENUS"
        export FQDN_BUDGET_APPROVAL="$FQDN_BUDGET_APPROVAL"
        export FQDN_ADMIN_CONTROL_PLANE="$FQDN_ADMIN_CONTROL_PLANE"
        export AZURE_TENANT_ID_VAL="$AZURE_TENANT_ID_VAL"
        export ENTRA_OAUTH2_AUDIENCE="$ENTRA_OAUTH2_AUDIENCE"
        export MI_CLIENT_ID_BUDGET_REPORT="$MI_CLIENT_ID_BUDGET_REPORT"
        export MI_CLIENT_ID_BUDGET_APPROVAL="$MI_CLIENT_ID_BUDGET_APPROVAL"
        export MI_CLIENT_ID_EMPLOYEE_MENUS="$MI_CLIENT_ID_EMPLOYEE_MENUS"
        export GRAPH_CLIENT_ID="$GRAPH_CLIENT_ID"
        export GRAPH_CLIENT_SECRET="$GRAPH_CLIENT_SECRET"
        export ENTRA_AGENT_OID_BUDGET_REPORT="$ENTRA_AGENT_OID_BUDGET_REPORT"
        export ENTRA_AGENT_OID_BUDGET_APPROVAL="$ENTRA_AGENT_OID_BUDGET_APPROVAL"
        export ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE="$ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE"
        export ENTRA_AGENT_OID_BUDGET_BACKEND="$ENTRA_AGENT_OID_BUDGET_BACKEND"
        export ENTRA_AGENT_OID_EMPLOYEE_MENUS="$ENTRA_AGENT_OID_EMPLOYEE_MENUS"
        export ENTRA_ID_BUDGET_REPORT="$ENTRA_ID_BUDGET_REPORT"
        export ENTRA_ID_BUDGET_BACKEND="$ENTRA_ID_BUDGET_BACKEND"
        export ENTRA_ID_EMPLOYEE_MENUS="$ENTRA_ID_EMPLOYEE_MENUS"
        export ENTRA_ID_BUDGET_APPROVAL="$ENTRA_ID_BUDGET_APPROVAL"
        export ENTRA_ID_ADMIN_CONTROL_PLANE="$ENTRA_ID_ADMIN_CONTROL_PLANE"
        python3 << 'PYTHON_SCRIPT'
import os
import yaml

yaml_file = os.environ["YAML_FILE"]
agent_name = os.environ["AGENT"]
spiffe_image = os.environ["SPIFFE_IMAGE"]
proxy_mode = os.environ["PROXY_MODE"]
spire_server_fqdn = os.environ["SPIRE_SERVER_FQDN"]
spire_agent_target = os.environ.get("SPIRE_AGENT_TARGET", "")
join_token = os.environ["JOIN_TOKEN"]
agent_oid = os.environ.get("AGENT_OID", "")
entra_id = os.environ.get("ENTRA_ID", "")
bp_oid = os.environ.get("ENTRA_BP_OID", "")
spire_trust_bundle = os.environ.get("SPIRE_TRUST_BUNDLE", "")
mgmt_api_key = os.environ.get("MGMT_API_KEY", "")
fqdn_budget_report = os.environ.get("FQDN_BUDGET_REPORT", "")
fqdn_employee_menus = os.environ.get("FQDN_EMPLOYEE_MENUS", "")
fqdn_budget_approval = os.environ.get("FQDN_BUDGET_APPROVAL", "")
fqdn_admin_control_plane = os.environ.get("FQDN_ADMIN_CONTROL_PLANE", "")

# OAuth2 config (for caller agents — Managed Identity federation)
oauth2_vars = {
    'tenant_id': os.environ.get("AZURE_TENANT_ID_VAL", ""),
    'audience': os.environ.get("ENTRA_OAUTH2_AUDIENCE", ""),
    'report_mi_client_id': os.environ.get("MI_CLIENT_ID_BUDGET_REPORT", ""),
    'approval_mi_client_id': os.environ.get("MI_CLIENT_ID_BUDGET_APPROVAL", ""),
    'menus_mi_client_id': os.environ.get("MI_CLIENT_ID_EMPLOYEE_MENUS", ""),
}

# Graph API credentials for CA policy evaluation (provisioner app)
graph_client_id = os.environ.get("GRAPH_CLIENT_ID", "")
graph_client_secret = os.environ.get("GRAPH_CLIENT_SECRET", "")

with open(yaml_file) as f:
    app = yaml.safe_load(f)

containers = app['properties']['template']['containers']
sidecar_name = f"{agent_name}-spiffe-proxy"

# Derive workload SPIFFE IDs using Entra Agent Identity Blueprint format:
# spiffe://aim.microsoft.com/ests/bp/<blueprint-oid>/aid/<agent-oid>
def workload_id(agent_oid):
    return f"spiffe://aim.microsoft.com/ests/bp/{bp_oid}/aid/{agent_oid}"

# Build caller workload IDs for the ingress allow list
# Only budget-report and budget-approval are in the mTLS allow list.
# employee-menus is intentionally EXCLUDED — it gets blocked at the TLS handshake.
caller_ids = {
    "budget-report": workload_id(os.environ.get("ENTRA_AGENT_OID_BUDGET_REPORT", "")),
    "budget-approval": workload_id(os.environ.get("ENTRA_AGENT_OID_BUDGET_APPROVAL", "")),
    "admin-control-plane": workload_id(os.environ.get("ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE", "")),
}

for container in containers:
    if container['name'] == sidecar_name:
        container['image'] = spiffe_image

        common_env = [
            {'name': 'CONTAINER_MODE', 'value': 'agent-proxy'},
            {'name': 'PROXY_MODE', 'value': proxy_mode},
            {'name': 'SPIRE_SERVER_ADDR', 'value': spire_agent_target},
            {'name': 'JOIN_TOKEN', 'value': join_token},
            {'name': 'SPIRE_TRUST_BUNDLE', 'value': spire_trust_bundle},
        ]

        if proxy_mode == 'egress':
            # Egress proxy: local agent sends HTTP to :8080, proxy tunnels
            # it over gRPC+mTLS to budget-backend:8443 (ingress proxy)
            backend_id = workload_id(os.environ.get("ENTRA_AGENT_OID_BUDGET_BACKEND", ""))
            container['env'] = common_env + [
                {'name': 'HTTP_LISTEN_ADDR', 'value': ':8080'},
                {'name': 'REMOTE_PROXY_ADDR', 'value': 'budget-backend:8443'},
                {'name': 'ALLOWED_REMOTE_SPIFFE_ID', 'value': backend_id},
            ]
        else:
            # Ingress proxy: accepts gRPC+mTLS on :8443, validates caller
            # SPIFFE ID against allow list, forwards to local app on :8000.
            # RBAC_POLICY_PATH enables the L7 gateway extension (M1-M3):
            # RBAC policy evaluation, caller context injection, structured
            # logging, and the management API on localhost:9443.
            allowed = ",".join(caller_ids.values())
            ingress_env = common_env + [
                {'name': 'GRPC_LISTEN_ADDR', 'value': ':8443'},
                {'name': 'APP_ADDR', 'value': 'localhost:8000'},
                {'name': 'ALLOWED_CALLER_SPIFFE_IDS', 'value': allowed},
                {'name': 'RBAC_POLICY_PATH', 'value': '/app/config/spiffe-rbac-policy.yaml'},
                {'name': 'OAUTH_CONFIG_PATH', 'value': '/app/config/oauth-config.yaml'},
            ]
            # Inject OAuth2 tenant + audience into the sidecar for Layer 3 JWT validation.
            if oauth2_vars.get('tenant_id'):
                ingress_env.append({'name': 'AZURE_TENANT_ID', 'value': oauth2_vars['tenant_id']})
            if oauth2_vars.get('audience'):
                ingress_env.append({'name': 'ENTRA_OAUTH2_AUDIENCE', 'value': oauth2_vars['audience']})
            # Inject Graph credentials for CA policy cache (evaluateCA reads CA policies from Entra)
            if graph_client_id and graph_client_secret:
                ingress_env.append({'name': 'GRAPH_CLIENT_ID', 'value': graph_client_id})
                ingress_env.append({'name': 'GRAPH_CLIENT_SECRET', 'value': graph_client_secret})
            # Inject per-agent SPIFFE prefixes and Entra IDs so the RBAC engine
            # can enrich policy metadata from env vars at startup (EnrichFromEnv).
            agent_prefixes = {
                'BUDGET_REPORT':   (os.environ.get('ENTRA_AGENT_OID_BUDGET_REPORT', ''), os.environ.get('ENTRA_ID_BUDGET_REPORT', '')),
                'BUDGET_BACKEND':  (os.environ.get('ENTRA_AGENT_OID_BUDGET_BACKEND', ''), os.environ.get('ENTRA_ID_BUDGET_BACKEND', '')),
                'EMPLOYEE_MENUS':  (os.environ.get('ENTRA_AGENT_OID_EMPLOYEE_MENUS', ''), os.environ.get('ENTRA_ID_EMPLOYEE_MENUS', '')),
                'BUDGET_APPROVAL': (os.environ.get('ENTRA_AGENT_OID_BUDGET_APPROVAL', ''), os.environ.get('ENTRA_ID_BUDGET_APPROVAL', '')),
                'ADMIN_CONTROL_PLANE': (os.environ.get('ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE', ''), os.environ.get('ENTRA_ID_ADMIN_CONTROL_PLANE', '')),
            }
            for key, (aoid, eid) in agent_prefixes.items():
                if aoid:
                    prefix = f"spiffe://aim.microsoft.com/ests/bp/{bp_oid}/aid/{aoid}"
                    ingress_env.append({'name': f'SPIFFE_PREFIX_{key}', 'value': prefix})
                if eid:
                    ingress_env.append({'name': f'ENTRA_ID_{key}', 'value': eid})
            container['env'] = ingress_env
        break

# Also inject ENTRA_AGENT_ID and OAuth2 credentials into the main FastAPI container
for container in containers:
    if container['name'] == agent_name:
        env_list = container.get('env', [])
        # Remove existing identity/oauth2/mgmt env vars
        remove_keys = {'ENTRA_AGENT_ID', 'MI_CLIENT_ID',
                       'AZURE_TENANT_ID', 'ENTRA_OAUTH2_AUDIENCE',
                       'MGMT_API_KEY', 'ADMIN_API_KEY', 'AGENT_TAG', 'APPROVAL_ENDPOINT',
                       'A2A_TARGET_URL_BUDGET_REPORT', 'A2A_TARGET_URL_EMPLOYEE_MENUS',
                       'A2A_TARGET_URL_BUDGET_APPROVAL',
                       'ADMIN_CONTROL_PLANE_ENDPOINT',
                       'RISK_STORE_URL',
                       'GRAPH_CLIENT_ID', 'GRAPH_CLIENT_SECRET',
                       'ENTRA_AGENT_ID_BUDGET_REPORT', 'ENTRA_AGENT_ID_BUDGET_APPROVAL',
                       'ENTRA_AGENT_ID_EMPLOYEE_MENUS'}
        env_list = [e for e in env_list if e.get('name') not in remove_keys]
        if entra_id:
            env_list.append({'name': 'ENTRA_AGENT_ID', 'value': entra_id})
        # OAuth2: inject tenant + audience for all agents
        if oauth2_vars['tenant_id']:
            env_list.append({'name': 'AZURE_TENANT_ID', 'value': oauth2_vars['tenant_id']})
        if oauth2_vars['audience']:
            env_list.append({'name': 'ENTRA_OAUTH2_AUDIENCE', 'value': oauth2_vars['audience']})
        # OAuth2: inject MI client ID for caller agents (used by ManagedIdentityCredential)
        if agent_name == 'budget-report' and oauth2_vars['report_mi_client_id']:
            env_list.append({'name': 'MI_CLIENT_ID', 'value': oauth2_vars['report_mi_client_id']})
        elif agent_name == 'budget-approval' and oauth2_vars['approval_mi_client_id']:
            env_list.append({'name': 'MI_CLIENT_ID', 'value': oauth2_vars['approval_mi_client_id']})
        elif agent_name == 'employee-menus' and oauth2_vars['menus_mi_client_id']:
            env_list.append({'name': 'MI_CLIENT_ID', 'value': oauth2_vars['menus_mi_client_id']})
        # Potential A2A targets need all caller MI client IDs for JWT appid → agent resolution.
        # Also inject Agent Identity client IDs — the two-hop token exchange produces
        # JWTs with appid = Agent Identity client ID (not MI client ID).
        if agent_name in ('budget-report', 'budget-approval', 'employee-menus'):
            if oauth2_vars['report_mi_client_id']:
                env_list.append({'name': 'MI_CLIENT_ID_BUDGET_REPORT', 'value': oauth2_vars['report_mi_client_id']})
            if oauth2_vars['approval_mi_client_id']:
                env_list.append({'name': 'MI_CLIENT_ID_BUDGET_APPROVAL', 'value': oauth2_vars['approval_mi_client_id']})
            if oauth2_vars['menus_mi_client_id']:
                env_list.append({'name': 'MI_CLIENT_ID_EMPLOYEE_MENUS', 'value': oauth2_vars['menus_mi_client_id']})
            # Agent Identity client IDs for two-hop JWT appid resolution
            entra_id_report = os.environ.get("ENTRA_ID_BUDGET_REPORT", "")
            entra_id_approval = os.environ.get("ENTRA_ID_BUDGET_APPROVAL", "")
            entra_id_menus = os.environ.get("ENTRA_ID_EMPLOYEE_MENUS", "")
            if entra_id_report:
                env_list.append({'name': 'ENTRA_AGENT_ID_BUDGET_REPORT', 'value': entra_id_report})
            if entra_id_approval:
                env_list.append({'name': 'ENTRA_AGENT_ID_BUDGET_APPROVAL', 'value': entra_id_approval})
            if entra_id_menus:
                env_list.append({'name': 'ENTRA_AGENT_ID_EMPLOYEE_MENUS', 'value': entra_id_menus})
        # Management API key for agents that proxy/validate mgmt requests
        # and for caller apps that expose /flush-token to clear cached JWTs.
        if agent_name in ('budget-backend', 'budget-approval', 'budget-report', 'employee-menus', 'admin-control-plane') and mgmt_api_key:
            env_list.append({'name': 'MGMT_API_KEY', 'value': mgmt_api_key})
            if agent_name == 'admin-control-plane':
                env_list.append({'name': 'ADMIN_API_KEY', 'value': mgmt_api_key})
        # Layer 4: CA tag + A2A endpoints for S2S OAuth direct calling
        if agent_name in ('budget-report', 'budget-approval'):
            env_list.append({'name': 'AGENT_TAG', 'value': 'Finance'})
        if agent_name == 'employee-menus':
            env_list.append({'name': 'AGENT_TAG', 'value': 'HR'})
        if agent_name == 'admin-control-plane':
            env_list.append({'name': 'AGENT_TAG', 'value': 'Operations'})
        if agent_name in ('budget-report', 'employee-menus') and fqdn_budget_approval:
            env_list.append({'name': 'APPROVAL_ENDPOINT', 'value': fqdn_budget_approval})
        if agent_name in ('budget-report', 'budget-approval', 'employee-menus'):
            if fqdn_budget_report:
                env_list.append({'name': 'A2A_TARGET_URL_BUDGET_REPORT', 'value': fqdn_budget_report})
            if fqdn_employee_menus:
                env_list.append({'name': 'A2A_TARGET_URL_EMPLOYEE_MENUS', 'value': fqdn_employee_menus})
            if fqdn_budget_approval:
                env_list.append({'name': 'A2A_TARGET_URL_BUDGET_APPROVAL', 'value': fqdn_budget_approval})
        if agent_name in ('admin-control-plane', 'budget-approval', 'budget-report', 'employee-menus') and fqdn_admin_control_plane:
            env_list.append({'name': 'ADMIN_CONTROL_PLANE_ENDPOINT', 'value': fqdn_admin_control_plane})
        # BudgetApproval's A2A endpoint queries risk/policy via its own mgmt-proxy
        # (proxies through SPIFFE tunnel to BudgetBackend's sidecar mgmt API).
        # RISK_STORE_URL defaults to localhost in app code — no env var needed.
        # Graph API credentials for CA policy evaluation (shared by sidecar + agents)
        if graph_client_id and graph_client_secret:
            env_list.append({'name': 'GRAPH_CLIENT_ID', 'value': graph_client_id})
            env_list.append({'name': 'GRAPH_CLIENT_SECRET', 'value': graph_client_secret})
        container['env'] = env_list
        break

with open(yaml_file, 'w') as f:
    yaml.dump(app, f, default_flow_style=False)
PYTHON_SCRIPT
    )

    apply_containerapp_yaml_with_retry "$AGENT" "$RG" "$YAML_FILE"
    echo "   ✓ ${AGENT} updated"

    case "$AGENT" in
        budget-report)
            ensure_containerapp_envs "$AGENT" \
                "MGMT_API_KEY=${MGMT_API_KEY}" \
                "ADMIN_CONTROL_PLANE_ENDPOINT=${FQDN_ADMIN_CONTROL_PLANE}" \
                "AGENT_TAG=Finance"
            ;;
        budget-approval)
            ensure_containerapp_envs "$AGENT" \
                "MGMT_API_KEY=${MGMT_API_KEY}" \
                "ADMIN_CONTROL_PLANE_ENDPOINT=${FQDN_ADMIN_CONTROL_PLANE}" \
                "AGENT_TAG=Finance"
            ;;
        employee-menus)
            ensure_containerapp_envs "$AGENT" \
                "MGMT_API_KEY=${MGMT_API_KEY}" \
                "ADMIN_CONTROL_PLANE_ENDPOINT=${FQDN_ADMIN_CONTROL_PLANE}" \
                "AGENT_TAG=HR"
            ;;
        admin-control-plane)
            ensure_containerapp_envs "$AGENT" \
                "MGMT_API_KEY=${MGMT_API_KEY}" \
                "ADMIN_API_KEY=${MGMT_API_KEY}" \
                "ADMIN_CONTROL_PLANE_ENDPOINT=${FQDN_ADMIN_CONTROL_PLANE}" \
                "AGENT_TAG=Operations"
            ;;
    esac

    rm -f "$YAML_FILE"
    sleep 5
done

echo ""
echo "✅ All sidecars updated with join tokens"
echo ""

# =============================================================================
# Step 6: Wait for attestation + register workload entries
# =============================================================================
# After Step 5, each agent's sidecar restarts and:
#   1. SPIRE Agent uses the join token to attest to the SPIRE Server
#   2. Server validates the token and issues an agent SVID
#   3. The token is consumed (single-use)
#
# We then register workload entries that tell the server:
#   "Any process running as root (unix:uid:0) under this agent should receive
#    a workload SVID with SPIFFE ID ests/bp/<bp-oid>/aid/<agent-oid>"
#
# The Go proxy (spiffe-proxy) runs as root in the sidecar, so it matches
# the unix:uid:0 selector and receives the workload SVID. It uses this SVID
# for mTLS connections to/from other agents.
echo "🔑 Step 6/6: Waiting for attestation + registering workload entries..."
echo ""
echo "   Waiting 60s for SPIRE Agents to attest..."
sleep 60

# Check how many agents successfully attested
echo "   Checking attested agents..."
AGENT_LIST_OUTPUT=$(vm_run "agent-list" "sudo docker exec spire-server /opt/spire/bin/spire-server agent list" 120 2>&1)
echo "$AGENT_LIST_OUTPUT" | grep -E 'SPIFFE ID|Attestation|Found' || true

# Count attested agents — JSON output has escaped \n, so count occurrences not lines
ATTESTED_COUNT=$(echo "$AGENT_LIST_OUTPUT" | grep -oE 'SPIFFE ID' | wc -l | tr -d ' ')
echo ""
EXPECTED_ATTESTED_COUNT=${#AGENTS[@]}
echo "   Attested agents: ${ATTESTED_COUNT}/${EXPECTED_ATTESTED_COUNT}"

if [ "$ATTESTED_COUNT" -lt "$EXPECTED_ATTESTED_COUNT" ]; then
    echo "   ⚠️  Not all agents attested. Waiting 30s more..."
    sleep 30
    AGENT_LIST_OUTPUT=$(vm_run "agent-list-retry" "sudo docker exec spire-server /opt/spire/bin/spire-server agent list" 120 2>&1)
    ATTESTED_COUNT=$(echo "$AGENT_LIST_OUTPUT" | grep -oE 'SPIFFE ID' | wc -l | tr -d ' ')
    echo "   Attested agents: ${ATTESTED_COUNT}/${EXPECTED_ATTESTED_COUNT}"
fi

echo ""
echo "   Registering workload entries..."
echo ""

# ─── Parent ID strategy (important!) ─────────────────────────────────────
# SPIRE auto-assigns join_token agents an internal SPIFFE ID:
#   spiffe://aim.microsoft.com/spire/agent/join_token/<token-uuid>
#
# In Step 5, we passed -spiffeID spiffe://aim.microsoft.com/agent/<name>
# to `token generate`. This causes SPIRE to auto-create a registration entry:
#   parent: spiffe://.../spire/agent/join_token/<uuid>
#   child:  spiffe://.../agent/<name>
#
# So the agent receives an SVID for agent/<name>. We then create our own
# workload entry with agent/<name> as the parent:
#   parent: spiffe://.../agent/<name>
#   child:  spiffe://.../ests/bp/<bp-oid>/aid/<agent-oid>
#
# This gives a two-hop SVID chain:
#   join_token/<uuid> → agent/<name> → ests/bp/<bp-oid>/aid/<agent-oid>
#
# The proxy process (running as uid:0) matches the unix:uid:0 selector
# and receives the ests/bp/... workload SVID for mTLS.
# ─────────────────────────────────────────────────────────────────────────

for AGENT in "${AGENTS[@]}"; do
    PARENT_ID="spiffe://${TRUST_DOMAIN}/agent/${AGENT}"

    # Derive workload SPIFFE ID using Entra Agent Identity Blueprint format
    case "$AGENT" in
        budget-report)   AGENT_OID="$ENTRA_AGENT_OID_BUDGET_REPORT" ;;
        budget-backend)  AGENT_OID="$ENTRA_AGENT_OID_BUDGET_BACKEND" ;;
        employee-menus)  AGENT_OID="$ENTRA_AGENT_OID_EMPLOYEE_MENUS" ;;
        budget-approval) AGENT_OID="$ENTRA_AGENT_OID_BUDGET_APPROVAL" ;;
        admin-control-plane) AGENT_OID="$ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE" ;;
        *)               AGENT_OID="" ;;
    esac

    WORKLOAD_ID="spiffe://${TRUST_DOMAIN}/ests/bp/${ENTRA_BP_OID}/aid/${AGENT_OID}"

    echo "   ${AGENT}:"
    echo "     Parent:     ${PARENT_ID}"
    echo "     Workload:   ${WORKLOAD_ID}"

    vm_run "entry-${AGENT}" "sudo docker exec spire-server /opt/spire/bin/spire-server entry create \
            -parentID '${PARENT_ID}' \
            -spiffeID '${WORKLOAD_ID}' \
            -selector unix:uid:0 \
            -ttl 3600" 120 2>&1 | grep -E 'Entry ID|already exists|stdout' || true

    echo ""
done

echo "   Waiting 30s for SVID issuance..."
sleep 30
fi

# =============================================================================
# Generate portal-config.json so the Control Panel is always ready
# =============================================================================
echo "📋 Generating portal-config.json..."

# Read FQDNs from azd env (set by azd deploy)
AZD_VALUES=$(azd_env_load)
FQDN_BUDGET_REPORT=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_BUDGET_REPORT_ENDPOINT_URL")
FQDN_BUDGET_BACKEND=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_BUDGET_BACKEND_ENDPOINT_URL")
FQDN_EMPLOYEE_MENUS=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_EMPLOYEE_MENUS_ENDPOINT_URL")
FQDN_BUDGET_APPROVAL=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_BUDGET_APPROVAL_ENDPOINT_URL")
FQDN_ADMIN_CONTROL_PLANE=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_ADMIN_CONTROL_PLANE_ENDPOINT_URL")

# Fall back to az containerapp show if azd env doesn't have URLs
if [ -z "$FQDN_BUDGET_REPORT" ]; then
    for APP in "${AGENTS[@]}"; do
        FQDN=$(az containerapp show --name "$APP" --resource-group "$RG" \
            --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null || true)
        if [ -n "$FQDN" ]; then
            var_name="FQDN_$(echo "$APP" | tr '-' '_' | tr '[:lower:]' '[:upper:]')"
            printf -v "$var_name" 'https://%s' "$FQDN"
        fi
    done
fi

# Read Entra Agent IDs from azd env
ENTRA_ID_BR=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_REPORT")
ENTRA_ID_BB=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_BACKEND")
ENTRA_ID_EM=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_EMPLOYEE_MENUS")
ENTRA_ID_BA=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_BUDGET_APPROVAL")
ENTRA_ID_ACP=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE")

# Build SPIFFE IDs using Entra Agent Identity Blueprint format
SPIFFE_BR="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_BUDGET_REPORT}"
SPIFFE_BB="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_BUDGET_BACKEND}"
SPIFFE_EM="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_EMPLOYEE_MENUS}"
SPIFFE_BA="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_BUDGET_APPROVAL}"
SPIFFE_ACP="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE}"

PORTAL_CONFIG="$(cd "$(dirname "$0")" && pwd)/portal/portal-config.json"
cat > "$PORTAL_CONFIG" <<PORTAL_EOF
{
  "mode": "live",
  "trust_domain": "aim.microsoft.com",
  "resource_group": "${RG}",
  "location": "${AZURE_LOCATION:-westus}",
  "portal_port": 8550,
  "agents": {
    "budget-report": {
      "name": "BudgetReport",
      "app_name": "budget-report",
      "url": "${FQDN_BUDGET_REPORT}",
      "spiffe_id": "${SPIFFE_BR}",
      "entra_agent_id": "${ENTRA_ID_BR}",
      "role": "Read-only Caller",
      "entra_role": "BudgetFrontEnds"
    },
    "budget-backend": {
      "name": "BudgetBackend",
      "app_name": "budget-backend",
      "url": "${FQDN_BUDGET_BACKEND}",
      "spiffe_id": "${SPIFFE_BB}",
      "entra_agent_id": "${ENTRA_ID_BB}",
      "role": "Protected Resource (MCP Server)",
      "entra_role": "—"
    },
    "employee-menus": {
      "name": "EmployeeMenus",
      "app_name": "employee-menus",
      "url": "${FQDN_EMPLOYEE_MENUS}",
      "spiffe_id": "${SPIFFE_EM}",
      "entra_agent_id": "${ENTRA_ID_EM}",
      "role": "Blocked Caller",
      "entra_role": "Menus"
    },
    "budget-approval": {
      "name": "BudgetApproval",
      "app_name": "budget-approval",
      "url": "${FQDN_BUDGET_APPROVAL}",
      "spiffe_id": "${SPIFFE_BA}",
      "entra_agent_id": "${ENTRA_ID_BA}",
      "role": "Full-access Caller",
      "entra_role": "BudgetFrontEnds"
    }
  },
  "control_plane": {
    "name": "AdminControlPlane",
    "app_name": "admin-control-plane",
    "url": "${FQDN_ADMIN_CONTROL_PLANE}",
    "spiffe_id": "${SPIFFE_ACP}",
    "entra_agent_id": "${ENTRA_ID_ACP}",
    "role": "Dedicated Management Service"
  },
  "spire_server_ip": "${SPIRE_SERVER_FQDN:-}",
  "management_api_port": 9443,
  "mgmt_api_key": "${MGMT_API_KEY}"
}
PORTAL_EOF
echo "✅ Portal config written to portal/portal-config.json"
echo ""

# =============================================================================
# Step 7: Create Entra security groups + portal app registrations
# =============================================================================
echo "👥 Step 7: Setting up portal auth (Entra groups + app registrations)..."

PORTAL_ADMIN_GROUP_NAME=$(portal_admin_group_display_name)
PORTAL_VIEWER_GROUP_NAME=$(portal_viewer_group_display_name)
PORTAL_ADMIN_GROUP_NICKNAME=$(portal_admin_group_mail_nickname)
PORTAL_VIEWER_GROUP_NICKNAME=$(portal_viewer_group_mail_nickname)
PORTAL_MANAGEMENT_APP_NAME=$(portal_management_app_display_name)
PORTAL_SECURITYPORTAL_APP_NAME=$(portal_securityportal_app_display_name)

ISP_ADMIN_GROUP_ID=$(azd_env_get_from_blob "$AZD_VALUES" "ISP_ADMIN_GROUP_ID")
ISP_ADMIN_GROUP_ID=$(ensure_portal_group "$ISP_ADMIN_GROUP_ID" "$PORTAL_ADMIN_GROUP_NAME" "$PORTAL_ADMIN_GROUP_NICKNAME")

ISP_VIEWER_GROUP_ID=$(azd_env_get_from_blob "$AZD_VALUES" "ISP_VIEWER_GROUP_ID")
ISP_VIEWER_GROUP_ID=$(ensure_portal_group "$ISP_VIEWER_GROUP_ID" "$PORTAL_VIEWER_GROUP_NAME" "$PORTAL_VIEWER_GROUP_NICKNAME")

# Seed portal Administrators group members.
# Precedence:
#   1. --with-admin=<upn|oid> flag(s) (comma-aggregated into WITH_ADMIN_ARGS)
#   2. ISP_INITIAL_ADMINS env var (comma-separated UPNs/OIDs)
#   3. Fallback: the signed-in az CLI user
# Each entry is resolved to an Entra object ID before being added.
resolve_user_oid() {
    local value="$1"
    if [[ "$value" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        printf '%s\n' "$value"
        return 0
    fi
    az ad user show --id "$value" --query "id" -o tsv 2>/dev/null
}

add_user_to_admin_group() {
    local raw="$1"
    local oid
    oid=$(resolve_user_oid "$raw")
    if [ -z "$oid" ]; then
        echo "   ⚠  Could not resolve '${raw}' to an Entra user; skipped" >&2
        return 1
    fi
    if az ad group member add --group "$ISP_ADMIN_GROUP_ID" --member-id "$oid" 2>/dev/null; then
        echo "   ✅ Added '${raw}' (${oid}) to ${PORTAL_ADMIN_GROUP_NAME}"
    else
        # Already a member is a success path
        if az ad group member check --group "$ISP_ADMIN_GROUP_ID" --member-id "$oid" --query "value" -o tsv 2>/dev/null | grep -qi true; then
            echo "   ℹ  '${raw}' (${oid}) already in ${PORTAL_ADMIN_GROUP_NAME}"
        else
            echo "   ⚠  Failed to add '${raw}' (${oid}) to ${PORTAL_ADMIN_GROUP_NAME}" >&2
            return 1
        fi
    fi
}

INITIAL_ADMINS_CSV="${WITH_ADMIN_ARGS}"
if [ -z "$INITIAL_ADMINS_CSV" ] && [ -n "${ISP_INITIAL_ADMINS:-}" ]; then
    INITIAL_ADMINS_CSV="$ISP_INITIAL_ADMINS"
fi

if [ -n "$INITIAL_ADMINS_CSV" ]; then
    IFS=',' read -r -a _initial_admins <<< "$INITIAL_ADMINS_CSV"
    for _entry in "${_initial_admins[@]}"; do
        _entry="$(echo "$_entry" | tr -d '[:space:]')"
        [ -z "$_entry" ] && continue
        add_user_to_admin_group "$_entry" || true
    done
    unset _initial_admins _entry
else
    CURRENT_USER_OID=$(az ad signed-in-user show --query "id" -o tsv 2>/dev/null || true)
    if [ -n "$CURRENT_USER_OID" ]; then
        az ad group member add --group "$ISP_ADMIN_GROUP_ID" --member-id "$CURRENT_USER_OID" 2>/dev/null || true
        echo "   Current az-login user added to ${PORTAL_ADMIN_GROUP_NAME}"
        echo "   Tip: pass --with-admin=<upn|oid> (repeatable) or set ISP_INITIAL_ADMINS to seed others."
    fi
fi

# Get portal FQDNs for redirect URIs (reload azd values — portal apps were just provisioned)
AZD_VALUES=$(azd_env_load)
PORTAL_FQDN=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_ISP_PORTAL_ENDPOINT_URL")
PORTAL_FQDN="${PORTAL_FQDN:-}"
SECURITY_PORTAL_MOCK_FQDN=$(azd_env_get_from_blob "$AZD_VALUES" "SERVICE_SECURITYPORTAL_MOCK_ENDPOINT_URL")
SECURITY_PORTAL_MOCK_FQDN="${SECURITY_PORTAL_MOCK_FQDN:-}"

# Create portal app registration
PORTAL_AUTH_CLIENT_ID=$(azd_env_get_from_blob "$AZD_VALUES" "PORTAL_AUTH_CLIENT_ID")
PORTAL_APP_RESULT=$(ensure_portal_app "$PORTAL_AUTH_CLIENT_ID" "$PORTAL_MANAGEMENT_APP_NAME" "$PORTAL_FQDN" "http://localhost:8550/")
PORTAL_AUTH_CLIENT_ID=$(printf '%s' "$PORTAL_APP_RESULT" | cut -f1)
PORTAL_APP_OBJ_ID=$(printf '%s' "$PORTAL_APP_RESULT" | cut -f2)
if [ -n "$PORTAL_AUTH_CLIENT_ID" ]; then
    azd env set PORTAL_AUTH_CLIENT_ID "$PORTAL_AUTH_CLIENT_ID"
    echo "   ✅ Portal app: ${PORTAL_AUTH_CLIENT_ID}"
else
    echo "   ⚠️  Portal app registration failed — auth will be disabled"
fi

# Create security portal mock app registration
SECURITY_PORTAL_AUTH_CLIENT_ID=$(azd_env_get_from_blob "$AZD_VALUES" "SECURITYPORTAL_AUTH_CLIENT_ID")
SECURITY_PORTAL_APP_RESULT=$(ensure_portal_app "$SECURITY_PORTAL_AUTH_CLIENT_ID" "$PORTAL_SECURITYPORTAL_APP_NAME" "$SECURITY_PORTAL_MOCK_FQDN" "http://localhost:8560/")
SECURITY_PORTAL_AUTH_CLIENT_ID=$(printf '%s' "$SECURITY_PORTAL_APP_RESULT" | cut -f1)
SECURITY_PORTAL_APP_OBJ_ID=$(printf '%s' "$SECURITY_PORTAL_APP_RESULT" | cut -f2)
if [ -n "$SECURITY_PORTAL_AUTH_CLIENT_ID" ]; then
    azd env set SECURITYPORTAL_AUTH_CLIENT_ID "$SECURITY_PORTAL_AUTH_CLIENT_ID"
    echo "   ✅ security portal mock app: ${SECURITY_PORTAL_AUTH_CLIENT_ID}"
else
    echo "   ⚠️  security portal mock app registration failed — auth will be disabled"
fi

# Store group IDs in azd env
azd env set ISP_ADMIN_GROUP_ID "$ISP_ADMIN_GROUP_ID" 2>/dev/null || true
azd env set ISP_VIEWER_GROUP_ID "$ISP_VIEWER_GROUP_ID" 2>/dev/null || true

# Grant admin consent for portal apps (required in tenants with admin consent policy)
if [ -n "$PORTAL_AUTH_CLIENT_ID" ]; then
    echo "   Granting admin consent for portal app..."
    az ad app permission admin-consent --id "$PORTAL_AUTH_CLIENT_ID" 2>/dev/null || true
fi
if [ -n "$SECURITY_PORTAL_AUTH_CLIENT_ID" ]; then
    echo "   Granting admin consent for security portal mock app..."
    az ad app permission admin-consent --id "$SECURITY_PORTAL_AUTH_CLIENT_ID" 2>/dev/null || true
fi

echo "✅ Portal auth setup complete"
echo ""

# =============================================================================
# Step 8: Update portal Container Apps with auth config
# =============================================================================
echo "🌐 Step 8: Updating portal Container Apps with auth + config..."

GRAPH_CLIENT_ID_VAL=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENTID_CLIENT_ID")
GRAPH_CLIENT_SECRET_VAL=$(azd_env_get_from_blob "$AZD_VALUES" "ENTRA_AGENTID_CLIENT_SECRET")
ADMIN_CP_URL="${FQDN_ADMIN_CONTROL_PLANE:-}"
MGMT_KEY="${MGMT_API_KEY:-}"
AZURE_TENANT="${AZURE_TENANT_ID_VAL:-}"
PORTAL_MI_CLIENT_ID=$(az containerapp show --name isp-portal --resource-group "$RG" \
    --query "identity.userAssignedIdentities.*.clientId | [0]" -o tsv 2>/dev/null || true)
SECURITY_PORTAL_MOCK_MI_CLIENT_ID=$(az containerapp show --name securityportal-mock --resource-group "$RG" \
    --query "identity.userAssignedIdentities.*.clientId | [0]" -o tsv 2>/dev/null || true)

if { [ -n "$GRAPH_CLIENT_ID_VAL" ] && [ -z "$GRAPH_CLIENT_SECRET_VAL" ]; } || { [ -z "$GRAPH_CLIENT_ID_VAL" ] && [ -n "$GRAPH_CLIENT_SECRET_VAL" ]; }; then
    echo "ERROR: Graph portal credentials are partially configured." >&2
    echo "  ENTRA_AGENTID_CLIENT_ID=${GRAPH_CLIENT_ID_VAL:-<empty>}" >&2
    echo "  ENTRA_AGENTID_CLIENT_SECRET=${GRAPH_CLIENT_SECRET_VAL:+<set>}${GRAPH_CLIENT_SECRET_VAL:-<empty>}" >&2
    exit 1
fi

if [ -n "$PORTAL_AUTH_CLIENT_ID" ] || [ -n "$ADMIN_CP_URL" ]; then
    if [ -z "$PORTAL_MI_CLIENT_ID" ]; then
        echo "ERROR: isp-portal managed identity client ID could not be resolved." >&2
        exit 1
    fi
    if [ -z "$SECURITY_PORTAL_MOCK_MI_CLIENT_ID" ]; then
        echo "ERROR: securityportal-mock managed identity client ID could not be resolved." >&2
        exit 1
    fi

    portal_secret_args=("mgmt-api-key=${MGMT_KEY}")
    securityportal_secret_args=("mgmt-api-key=${MGMT_KEY}")
    # Derive storage account name from resource group
    STORAGE_ACCOUNT=$(az storage account list --resource-group "$RG" --query "[0].name" -o tsv 2>/dev/null)
    if [ -z "$STORAGE_ACCOUNT" ]; then
        echo "   ⚠️  Storage account not found; blob-backed stores will not be configured"
    fi

    portal_env_vars=(
        "ADMIN_CP_URL=${ADMIN_CP_URL}"
        "MGMT_API_KEY=secretref:mgmt-api-key"
        "AZURE_TENANT_ID=${AZURE_TENANT}"
        "AZURE_CLIENT_ID=${PORTAL_MI_CLIENT_ID}"
        "AUTH_CLIENT_ID=${PORTAL_AUTH_CLIENT_ID}"
        "ISP_ADMIN_GROUP_ID=${ISP_ADMIN_GROUP_ID}"
        "ISP_VIEWER_GROUP_ID=${ISP_VIEWER_GROUP_ID}"
        "PORTAL_MODE=cloud"
    )
    if [ -n "$STORAGE_ACCOUNT" ]; then
        portal_env_vars+=(
            "POLICY_CONFIG_STORE_PROVIDER=blob"
            "POLICY_CONFIG_BLOB_ACCOUNT_URL=https://${STORAGE_ACCOUNT}.blob.core.windows.net/"
            "POLICY_CONFIG_BLOB_CONTAINER=portal-policy-configs"
            "POLICY_CONFIG_BLOB_NAME=policy-configs.json"
            "EXTERNAL_AGENT_STORE_PROVIDER=blob"
            "EXTERNAL_AGENT_STORE_BLOB_ACCOUNT_URL=https://${STORAGE_ACCOUNT}.blob.core.windows.net/"
            "EXTERNAL_AGENT_STORE_BLOB_CONTAINER=portal-external-agents"
            "EXTERNAL_AGENT_STORE_BLOB_NAME=external-agents.json"
        )
    fi
    securityportal_env_vars=(
        "ADMIN_CP_URL=${ADMIN_CP_URL}"
        "MGMT_API_KEY=secretref:mgmt-api-key"
        "AZURE_TENANT_ID=${AZURE_TENANT}"
        "AZURE_CLIENT_ID=${SECURITY_PORTAL_MOCK_MI_CLIENT_ID}"
        "AUTH_CLIENT_ID=${SECURITY_PORTAL_AUTH_CLIENT_ID}"
        "ISP_ADMIN_GROUP_ID=${ISP_ADMIN_GROUP_ID}"
        "ISP_VIEWER_GROUP_ID=${ISP_VIEWER_GROUP_ID}"
        "PORTAL_MODE=cloud"
    )
    if [ -n "$GRAPH_CLIENT_ID_VAL" ]; then
        portal_secret_args+=("graph-client-id=${GRAPH_CLIENT_ID_VAL}" "graph-client-secret=${GRAPH_CLIENT_SECRET_VAL}")
        securityportal_secret_args+=("graph-client-id=${GRAPH_CLIENT_ID_VAL}" "graph-client-secret=${GRAPH_CLIENT_SECRET_VAL}")
        portal_env_vars+=("GRAPH_CLIENT_ID=secretref:graph-client-id" "GRAPH_CLIENT_SECRET=secretref:graph-client-secret")
        securityportal_env_vars+=("GRAPH_CLIENT_ID=secretref:graph-client-id" "GRAPH_CLIENT_SECRET=secretref:graph-client-secret")
    else
        echo "   ⚠️  Graph client credentials are not configured; portal Graph features will be disabled"
    fi

    run_az_step "Failed to set isp-portal secrets" \
        az containerapp secret set \
        --name isp-portal \
        --resource-group "$RG" \
        --secrets "${portal_secret_args[@]}"

    # Update Identity Research for Agent Management Using SPIFFE Portal container app
    echo "   Updating isp-portal container app..."
    run_az_step "Failed to update isp-portal container app" \
        az containerapp update \
        --name isp-portal \
        --resource-group "$RG" \
        --image "${ACR_SERVER}/isp-portal:${IMAGE_TAG}" \
        --set-env-vars "${portal_env_vars[@]}"

    run_az_step "Failed to set securityportal-mock secrets" \
        az containerapp secret set \
        --name securityportal-mock \
        --resource-group "$RG" \
        --secrets "${securityportal_secret_args[@]}"

    # Update security portal mock container app
    echo "   Updating securityportal-mock container app..."
    run_az_step "Failed to update securityportal-mock container app" \
        az containerapp update \
        --name securityportal-mock \
        --resource-group "$RG" \
        --image "${ACR_SERVER}/securityportal-mock:${IMAGE_TAG}" \
        --set-env-vars "${securityportal_env_vars[@]}"

    echo "✅ Portal Container Apps updated"
else
    echo "⏭️  Skipping portal Container App update (no auth config)"
fi
echo ""

if [ "$RUN_VERIFY" = true ]; then
    echo "🔄 Flushing caller token caches before verification..."
    if ./scripts/flush-tokens.sh; then
        echo "✅ Token caches flushed"
    else
        echo "⚠️  Token cache flush failed; continuing to verification"
    fi
    echo ""
    echo "🧪 Running post-deploy verification..."
    python3 scripts/test_agents.py || echo "⚠️  Post-deploy verification had failures (non-blocking)"
    echo ""
else
    echo "⏭️  Skipping post-deploy verification (--no-verify)"
    echo ""
fi

echo ""
echo "============================================="
echo "✅ DEPLOYMENT COMPLETE"
echo "============================================="
echo ""
echo "Test:     python3 scripts/test_agents.py"
echo "Teardown: azd down --purge"
echo ""
echo "Architecture:"
echo "  SPIRE Server: VM (join_token attestation)"
echo "  SPIRE Agents: Container Apps sidecars"
echo "  Trust Domain: ${TRUST_DOMAIN}"
echo "  Server: ${SPIRE_SERVER_FQDN}:8081"
echo ""
echo "Enforcement Matrix (Transport Layer - mTLS):"
echo "  BudgetReport   → BudgetBackend: ✅ mTLS succeeds"
echo "  EmployeeMenus  → BudgetBackend: ❌ mTLS rejected"
echo "  BudgetApproval → BudgetBackend: ✅ mTLS succeeds"
echo ""
echo "Enforcement Matrix (Application Layer - RBAC):"
echo "  BudgetReport   → GET  /budget/read:   ✅ allowed"
echo "  BudgetReport   → POST /budget/submit: ❌ 403 (RBAC deny)"
echo "  EmployeeMenus  → Any:                 ❌ blocked (mTLS)"
echo "  BudgetApproval → POST /budget/submit: ✅ allowed"
echo "  BudgetApproval → GET  /budget/read:   ✅ allowed"
echo ""
echo "Enforcement Matrix (Admin Governance - CA Layer 4b):"
echo "  A2A: BudgetReport → BudgetApproval:   ✅ tag match (finance)"
echo "  A2A: EmployeeMenus → BudgetApproval:  ❌ tag mismatch (blocked)"
echo "  Risk: High-risk agent → Any:          ❌ blocked at data plane"
echo ""
echo "Management API (BudgetBackend sidecar, localhost only):"
echo "  GET  /policy      - View active RBAC policy (v5.0 + CA)"
echo "  PUT  /policy      - Update policy (hot-swap)"
echo "  GET  /agent-risk  - View agent risk levels"
echo "  PUT  /agent-risk  - Update agent risk (mock Security Portal)"
echo "  GET  /health      - SPIRE connection + SVID status"
echo "  GET  /metrics     - Request counters per caller"
echo "  GET  /audit       - Recent access log entries"
echo ""
echo "─────────────────────────────────────────────"
echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  PORTAL URLs (cloud-hosted)                                      ║"
echo "║                                                                   ║"
echo "║  Management Portal: ${PORTAL_FQDN:-<not deployed>}"
echo "║  Security Portal Mock:  ${SECURITY_PORTAL_MOCK_FQDN:-<not deployed>}"
echo "║                                                                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
if [ "$LAUNCH_PORTAL" = true ]; then
    exec "${SCRIPT_DIR}/portal/deploy-portal.sh"
else
    echo "Local portal options:"
    echo "  ./portal/deploy-portal.sh       # Live mode (connected to deployed agents)"
fi

# =============================================================================
# Cross-Cloud Variable Resolution
# =============================================================================
# When running with --skip-provision, earlier deploy steps that normally set
# RESOURCE_GROUP, AZURE_TENANT_ID_VAL, ACR_SERVER, etc. are skipped.
# Resolve them here so both --google and --github blocks work reliably.
# =============================================================================
if [ "$GOOGLE_AGENT" = true ] || [ "$GITHUB_AGENT" = true ]; then
    _cc_azd_values=$(azd_env_load)

    if [ -z "${RESOURCE_GROUP:-}" ]; then
        RESOURCE_GROUP=$(azd_env_get_from_blob "$_cc_azd_values" "AZURE_RESOURCE_GROUP")
    fi
    if [ -z "${RESOURCE_GROUP:-}" ]; then
        RESOURCE_GROUP=$(az group list --query "[?tags.project=='isp-prototype-platform'] | [0].name" -o tsv 2>/dev/null || true)
    fi
    if [ -z "${RESOURCE_GROUP:-}" ]; then
        RESOURCE_GROUP=$(az group list --query "[?contains(name,'isp-') || contains(name,'identity-spiffe')] | [0].name" -o tsv 2>/dev/null || true)
    fi
    if [ -z "${RESOURCE_GROUP:-}" ]; then
        echo "ERROR: Could not discover Azure resource group. Run a full deploy first." >&2
        exit 1
    fi

    if [ -z "${AZURE_TENANT_ID_VAL:-}" ]; then
        AZURE_TENANT_ID_VAL=$(azd_env_get_from_blob "$_cc_azd_values" "AZURE_TENANT_ID")
        [ -z "$AZURE_TENANT_ID_VAL" ] && AZURE_TENANT_ID_VAL=$(az account show --query tenantId -o tsv 2>/dev/null || true)
    fi

    if [ -z "${ENTRA_BP_OID:-}" ]; then
        ENTRA_BP_OID=$(azd_env_get_from_blob "$_cc_azd_values" "ENTRA_BLUEPRINT_OBJECT_ID")
    fi

    if [ -z "${ACR_SERVER:-}" ]; then
        ACR_SERVER=$(azd_env_get_from_blob "$_cc_azd_values" "AZURE_CONTAINER_REGISTRY_ENDPOINT")
        [ -z "$ACR_SERVER" ] && ACR_SERVER=$(az acr list -g "$RESOURCE_GROUP" --query "[0].loginServer" -o tsv 2>/dev/null || true)
    fi

    if [ -z "${MGMT_API_KEY:-}" ]; then
        MGMT_API_KEY=$(azd_env_get_from_blob "$_cc_azd_values" "MGMT_API_KEY")
    fi

    if [ -z "${_EARLY_PORTAL_URL:-}" ]; then
        _EARLY_PORTAL_URL=$(azd_env_get_from_blob "$_cc_azd_values" "SERVICE_ISP_PORTAL_ENDPOINT_URL")
    fi

    echo ""
    echo "📋 Cross-cloud variable resolution:"
    echo "   Resource group:  ${RESOURCE_GROUP}"
    echo "   Tenant ID:       ${AZURE_TENANT_ID_VAL:-<not set>}"
    echo "   Blueprint OID:   ${ENTRA_BP_OID:-<not set>}"
    echo "   ACR server:      ${ACR_SERVER:-<not set>}"
    echo "   Portal URL:      ${_EARLY_PORTAL_URL:-localhost:8550}"
fi

# =============================================================================
# Google Cross-Cloud Agent (optional, --google flag)
# =============================================================================

if [ "$GOOGLE_AGENT" = true ]; then
    echo ""
    echo "============================================="
    echo "  Google Cross-Cloud Agent Setup"
    echo "============================================="
    echo ""

    # --- Prerequisites ---
    if ! command -v gcloud &>/dev/null; then
        echo "ERROR: gcloud CLI not found. Install: brew install google-cloud-sdk" >&2
        exit 1
    fi

    GCP_PROJECT=$(azd_env_get_from_blob "$AZD_VALUES" "GCP_PROJECT")
    if [ -z "$GCP_PROJECT" ]; then
        echo "ERROR: GCP_PROJECT not set. Run: azd env set GCP_PROJECT <project-id>" >&2
        exit 1
    fi

    GCP_BILLING_ID=$(azd_env_get_from_blob "$AZD_VALUES" "GCP_BILLING_ID")
    GCP_REGION=$(azd_env_get_from_blob "$AZD_VALUES" "GCP_REGION")
    GCP_REGION="${GCP_REGION:-us-west1}"

    # --- GCP Environment Health Check ---
    echo "🔍 GCP environment health check..."
    _gcp_missing=0
    _gcp_total=0

    # Check VM
    _gcp_total=$((_gcp_total + 1))
    _gcp_vm_ip=$(gcloud compute instances describe google-budget-reader \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --format "value(networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null || true)
    if [ -n "$_gcp_vm_ip" ]; then
        echo "   ✅ GCE VM: google-budget-reader ($_gcp_vm_ip)"
    else
        echo "   ❌ GCE VM: google-budget-reader — NOT FOUND"
        _gcp_missing=$((_gcp_missing + 1))
    fi

    # Check VPC
    _gcp_total=$((_gcp_total + 1))
    _gcp_vpc=$(gcloud compute networks describe isp-crosscloud --project "$GCP_PROJECT" --format "value(name)" 2>/dev/null || true)
    if [ -n "$_gcp_vpc" ]; then
        echo "   ✅ VPC: isp-crosscloud"
    else
        echo "   ❌ VPC: isp-crosscloud — NOT FOUND"
        _gcp_missing=$((_gcp_missing + 1))
    fi

    # Check firewall rules
    _gcp_total=$((_gcp_total + 1))
    _gcp_fw_count=$(gcloud compute firewall-rules list --project "$GCP_PROJECT" \
        --filter "name~isp-" --format "value(name)" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$_gcp_fw_count" -ge 4 ] 2>/dev/null; then
        echo "   ✅ Firewall rules: $_gcp_fw_count rules"
    else
        echo "   ❌ Firewall rules: $_gcp_fw_count/4 — MISSING"
        _gcp_missing=$((_gcp_missing + 1))
    fi

    # Check VPN tunnel
    _gcp_total=$((_gcp_total + 1))
    _gcp_vpn=$(gcloud compute vpn-tunnels list --project "$GCP_PROJECT" \
        --filter "name:isp-vpn" --format "value(name)" 2>/dev/null || true)
    if [ -n "$_gcp_vpn" ]; then
        echo "   ✅ VPN tunnel: $_gcp_vpn"
    else
        echo "   ❌ VPN tunnel — NOT FOUND (will take ~30 min to provision)"
        _gcp_missing=$((_gcp_missing + 1))
    fi

    # Check Azure VPN Gateway
    _gcp_total=$((_gcp_total + 1))
    _az_vpn=$(az network vnet-gateway list -g "$RG" --query "[0].name" -o tsv 2>/dev/null || true)
    if [ -n "$_az_vpn" ]; then
        echo "   ✅ Azure VPN Gateway: $_az_vpn"
    else
        echo "   ❌ Azure VPN Gateway — NOT FOUND (will take ~30 min to provision)"
        _gcp_missing=$((_gcp_missing + 1))
    fi

    # Summary
    if [ "$_gcp_missing" -gt 0 ]; then
        echo ""
        echo "   ⚠️  ${_gcp_missing}/${_gcp_total} GCP resources missing — will be provisioned."
        if [ "$_gcp_missing" -ge 4 ]; then
            echo "   ⚠️  Most of the GCP environment is torn down."
            echo "   ⚠️  Full rebuild required. This may take 45+ minutes (VPN provisioning)."
        fi
        echo ""
    else
        echo "   ✅ All GCP resources present"
        echo ""
    fi

    # --- Step G1: Bootstrap GCP project ---
    echo "🌐 Step G1: Bootstrapping GCP project..."
    GCP_PROJECT_ID="$GCP_PROJECT" GCP_BILLING_ID="${GCP_BILLING_ID:-}" GCP_REGION="$GCP_REGION" \
        "$REPO_ROOT/scripts/bootstrap-gcp-project.sh" || {
        echo "GCP project bootstrap failed. Set GCP_BILLING_ID and retry." >&2
        exit 1
    }

    # --- Step G2: Provision GCE VM ---
    echo "🖥️  Step G2: Provisioning GCE VM..."
    GCE_IP=$(gcloud compute instances describe google-budget-reader \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --format "value(networkInterfaces[0].accessConfigs[0].natIP)" 2>/dev/null || true)

    if [ -z "$GCE_IP" ]; then
        GCP_PROJECT="$GCP_PROJECT" GCP_REGION="$GCP_REGION" \
            "$REPO_ROOT/scripts/provision-gce-vm.sh"
        GCE_IP=$(gcloud compute instances describe google-budget-reader \
            --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
            --format "value(networkInterfaces[0].accessConfigs[0].natIP)" 2>&1)
    fi
    # Private IP for VPN-routable invoke_url (portal calls through VNet → VPN → GCP)
    GCE_PRIVATE_IP=$(gcloud compute instances describe google-budget-reader \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --format "value(networkInterfaces[0].networkIP)" 2>/dev/null || true)
    echo "   GCE VM public IP:  $GCE_IP"
    echo "   GCE VM private IP: $GCE_PRIVATE_IP (VPN-routable)"

    # --- Step G3: VPN Gateway (Azure side, ~30 min) ---
    echo "🔗 Step G3: Azure VPN Gateway..."
    VPN_EXISTS=$(az network vnet-gateway list -g "$RG" --query "[0].name" -o tsv 2>/dev/null || true)

    # Reserve GCP VPN static IP early so we have the correct peer IP for
    # the Azure Local Network Gateway (not the GCE VM IP).
    GCP_VPN_IP=$(gcloud compute addresses describe isp-vpn-ip \
        --region "$GCP_REGION" --project "$GCP_PROJECT" \
        --format "value(address)" 2>/dev/null || true)
    if [ -z "$GCP_VPN_IP" ]; then
        echo "   Reserving GCP VPN static IP..."
        gcloud compute addresses create isp-vpn-ip \
            --region "$GCP_REGION" --project "$GCP_PROJECT" 2>&1
        GCP_VPN_IP=$(gcloud compute addresses describe isp-vpn-ip \
            --region "$GCP_REGION" --project "$GCP_PROJECT" \
            --format "value(address)" 2>&1)
    fi
    echo "   GCP VPN IP: $GCP_VPN_IP"

    if [ -z "$VPN_EXISTS" ]; then
        echo "   ⚠️  VPN Gateway takes ~30 minutes to provision."

        azd env set GCP_VPN_PUBLIC_IP "$GCP_VPN_IP"

        VPN_KEY=$(azd_env_get_from_blob "$(azd_env_load)" "VPN_SHARED_KEY")
        if [ -z "$VPN_KEY" ]; then
            VPN_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
            azd env set VPN_SHARED_KEY "$VPN_KEY"
        fi

        "$REPO_ROOT/scripts/deploy-azure-vpn.sh"
    else
        echo "   ✅ VPN Gateway already exists: $VPN_EXISTS"
    fi

    AZURE_VPN_GW_IP=$(az network public-ip list -g "$RG" \
        --query "[?contains(name, 'vpn')].ipAddress" -o tsv 2>/dev/null | head -1)
    echo "   Azure VPN Gateway IP: $AZURE_VPN_GW_IP"

    # Ensure Local Network Gateway peer IP matches the GCP VPN IP (not the GCE VM IP).
    # This can drift if the GCP VPN static IP was created after the Azure deployment.
    LGW_NAME=$(az network local-gateway list -g "$RG" --query "[0].name" -o tsv 2>/dev/null || true)
    if [ -n "$LGW_NAME" ]; then
        LGW_PEER_IP=$(az network local-gateway show -g "$RG" --name "$LGW_NAME" \
            --query "gatewayIpAddress" -o tsv 2>/dev/null || true)
        if [ "$LGW_PEER_IP" != "$GCP_VPN_IP" ]; then
            echo "   ⚠️  Local Network Gateway peer IP mismatch: $LGW_PEER_IP → $GCP_VPN_IP"
            echo "   Updating Local Network Gateway..."
            az network local-gateway update -g "$RG" --name "$LGW_NAME" \
                --gateway-ip-address "$GCP_VPN_IP" -o none 2>&1
            echo "   ✅ Updated"
        fi
    fi

    # --- Step G4: GCP VPN tunnel ---
    echo "🔗 Step G4: GCP VPN tunnel..."
    GCP_TUNNEL=$(gcloud compute vpn-tunnels list --project "$GCP_PROJECT" \
        --filter "name:isp-vpn" --format "value(name)" 2>/dev/null || true)

    if [ -z "$GCP_TUNNEL" ]; then
        VPN_KEY=$(azd_env_get_from_blob "$(azd_env_load)" "VPN_SHARED_KEY")
        AZURE_VPN_GATEWAY_IP="$AZURE_VPN_GW_IP" VPN_SHARED_KEY="$VPN_KEY" \
            GCP_PROJECT="$GCP_PROJECT" \
            "$REPO_ROOT/scripts/provision-gcp-vpn.sh"
    else
        echo "   ✅ GCP VPN tunnel already exists: $GCP_TUNNEL"
    fi

    # --- Step G5: Connectivity test ---
    echo "🔍 Step G5: Testing cross-cloud connectivity..."
    gcloud compute ssh google-budget-reader --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --command "ping -c 1 -W 5 ${SPIRE_SERVER_PRIVATE_IP:-10.200.0.4} > /dev/null 2>&1 && echo CONNECTED || echo FAILED" 2>&1 | tail -1

    # --- Step G6: Budget-backend ingress ---
    echo "🔧 Step G6: Ensuring budget-backend has external TCP ingress..."
    BB_EXTERNAL=$(az containerapp show -g "$RG" -n budget-backend \
        --query "properties.configuration.ingress.external" -o tsv 2>/dev/null)
    if [ "$BB_EXTERNAL" != "true" ]; then
        az containerapp ingress update -g "$RG" -n budget-backend \
            --type external --target-port 8443 --transport tcp --exposed-port 8443 \
            -o none 2>&1
        echo "   Updated budget-backend to external TCP"
    else
        echo "   ✅ Budget-backend already has external TCP ingress"
    fi

    # --- Step G7: Entra provisioning ---
    echo "🔑 Step G7: Entra Agent Identity provisioning..."
    GCP_SA_EMAIL="isp-agent@${GCP_PROJECT}.iam.gserviceaccount.com"
    BB_FQDN=$(az containerapp show -g "$RG" -n budget-backend \
        --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null)

    "$REPO_ROOT/scripts/add-google-agent.sh" \
        --gcp-sa "$GCP_SA_EMAIL" \
        --invoke-url "http://${GCE_PRIVATE_IP}:8000" \
        --name google-budget-reader \
        --portal-url "${_EARLY_PORTAL_URL:-http://localhost:8550}" \
        --mgmt-key "$MGMT_API_KEY"

    # Get the Google Agent Identity ID from azd env
    GOOGLE_AGENT_ID=$(azd_env_get_from_blob "$(azd_env_load)" "ENTRA_AGENT_ID_GOOGLE_BUDGET_READER")
    GOOGLE_SPIFFE="spiffe://gcp.aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${GOOGLE_AGENT_ID}"
    echo "   Google SPIFFE ID: $GOOGLE_SPIFFE"

    # --- Step G8: Update RBAC policy ---
    echo "📜 Step G8: Updating RBAC policy with Google agent..."
    POLICY_FILE="$REPO_ROOT/src/spiffe-proxy/config/spiffe-rbac-policy.yaml"
    if grep -q "PLACEHOLDER" "$POLICY_FILE" 2>/dev/null; then
        sed -i '' "s|PLACEHOLDER_BP_OID|${ENTRA_BP_OID}|g" "$POLICY_FILE" 2>/dev/null || \
        sed -i "s|PLACEHOLDER_BP_OID|${ENTRA_BP_OID}|g" "$POLICY_FILE"
        sed -i '' "s|PLACEHOLDER_AGENT_OID|${GOOGLE_AGENT_ID}|g" "$POLICY_FILE" 2>/dev/null || \
        sed -i "s|PLACEHOLDER_AGENT_OID|${GOOGLE_AGENT_ID}|g" "$POLICY_FILE"
    fi

    # Push policy to sidecar
    ADMIN_URL=$(azd_env_get_from_blob "$(azd_env_load)" "SERVICE_ADMIN_CONTROL_PLANE_ENDPOINT_URL")
    curl -s -X PUT \
        -H "X-Spiffe-Admin-Key: $MGMT_API_KEY" \
        -H "Content-Type: application/x-yaml" \
        --data-binary "@$POLICY_FILE" \
        "${ADMIN_URL}/admin/policy" > /dev/null 2>&1
    echo "   Policy pushed"

    # --- Step G9: mTLS allow list ---
    echo "🔒 Step G9: Adding Google SPIFFE to mTLS allow list..."
    CURRENT_IDS=$(curl -s -H "X-Spiffe-Admin-Key: $MGMT_API_KEY" \
        "${ADMIN_URL}/admin/mtls-policy" 2>/dev/null)
    if ! echo "$CURRENT_IDS" | grep -q "$GOOGLE_AGENT_ID" 2>/dev/null; then
        NEW_IDS=$(echo "$CURRENT_IDS" | python3 -c "
import sys, json
d = json.load(sys.stdin)
ids = d.get('allowed_ids', [])
ids.append('$GOOGLE_SPIFFE')
print(json.dumps({'allowed_ids': ids}))
")
        curl -s -X PUT \
            -H "X-Spiffe-Admin-Key: $MGMT_API_KEY" \
            -H "Content-Type: application/json" \
            -d "$NEW_IDS" \
            "${ADMIN_URL}/admin/mtls-policy" > /dev/null 2>&1
        echo "   Added to mTLS allow list"
    else
        echo "   ✅ Already in mTLS allow list"
    fi

    # --- Step G10: Deploy agent runtime on GCE ---
    # Must happen BEFORE bundle exchange (G11) because SPIRE server is installed
    # on the GCE VM by setup-gce-agent.sh. Without it, there's no GCP SPIRE to
    # exchange bundles with.
    echo "🐍 Step G10: Deploying agent runtime on GCE VM..."

    # Resolve vars needed by setup-gce-agent.sh
    _GCE_BLUEPRINT_APP_ID="${ENTRA_OAUTH2_AUDIENCE}"
    _GCE_AZURE_TENANT_ID="${AZURE_TENANT_ID_VAL}"
    _GCE_SPIRE_SERVER_IP="${SPIRE_SERVER_PRIVATE_IP:-10.200.0.4}"
    _GCE_BB_FQDN=$(az containerapp show -g "$RG" -n budget-backend \
        --query "properties.configuration.ingress.fqdn" -o tsv 2>/dev/null)
    _GCE_BB_SPIFFE="spiffe://${TRUST_DOMAIN}/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_BUDGET_BACKEND}"

    # Generate a scoped ACR token for the GCE VM to pull spiffe-proxy
    ACR_GCE_TOKEN_NAME="gce-pull-$(date +%s)"
    ACR_GCE_SCOPE_MAP=$(az acr scope-map list -r "$ACR_NAME" \
        --query "[?contains(name,'pull')].name" -o tsv 2>/dev/null | head -1)
    if [ -z "$ACR_GCE_SCOPE_MAP" ]; then
        ACR_GCE_SCOPE_MAP="_repositories_pull"
    fi
    ACR_GCE_CREDS=$(az acr token create -r "$ACR_NAME" -n "$ACR_GCE_TOKEN_NAME" \
        --scope-map "$ACR_GCE_SCOPE_MAP" --query "credentials.passwords[0].value" -o tsv 2>/dev/null || true)
    if [ -z "$ACR_GCE_CREDS" ]; then
        echo "   ⚠️  Could not create ACR pull token; setup-gce-agent.sh may skip proxy pull"
        ACR_GCE_CREDS=""
    fi

    # Copy agent files + setup script to GCE
    gcloud compute scp \
        "$REPO_ROOT/scripts/setup-gce-agent.sh" \
        google-budget-reader:/tmp/ \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" 2>/dev/null

    gcloud compute ssh google-budget-reader \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --command "sudo BLUEPRINT_APP_ID='${_GCE_BLUEPRINT_APP_ID}' \
            GOOGLE_AGENT_ID='${GOOGLE_AGENT_ID}' \
            AZURE_TENANT_ID='${_GCE_AZURE_TENANT_ID}' \
            AZURE_SPIRE_SERVER_IP='${_GCE_SPIRE_SERVER_IP}' \
            BUDGET_BACKEND_FQDN='${_GCE_BB_FQDN}' \
            BUDGET_BACKEND_SPIFFE_ID='${_GCE_BB_SPIFFE}' \
            ACR_SERVER='${ACR_SERVER}' \
            ACR_TOKEN_USER='${ACR_GCE_TOKEN_NAME}' \
            ACR_TOKEN_PASS='${ACR_GCE_CREDS}' \
            MGMT_API_KEY='${MGMT_API_KEY}' \
            bash /tmp/setup-gce-agent.sh" 2>&1

    # --- Step G11: SPIRE bundle exchange ---
    # Must happen AFTER G10 (GCE agent deploy installs SPIRE server on GCE) and
    # BEFORE G12 (federated entry creation requires target trust domain bundle).
    echo "🔐 Step G11: Exchanging SPIRE trust bundles..."

    # Get Azure bundle, send to GCE
    AZURE_BUNDLE=$(vm_run "get-az-bun" "sudo docker exec spire-server /opt/spire/bin/spire-server bundle show -format spiffe" 60 2>/dev/null || true)
    if [ -n "$AZURE_BUNDLE" ]; then
        BUNDLE_EXCHANGE_FILE="${REPO_ROOT}/.azure-bundle-exchange.json"
        echo "$AZURE_BUNDLE" > "$BUNDLE_EXCHANGE_FILE"
        gcloud compute scp "$BUNDLE_EXCHANGE_FILE" \
            google-budget-reader:/tmp/azure-bundle.json \
            --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" 2>/dev/null
        gcloud compute ssh google-budget-reader \
            --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
            --command "cat /tmp/azure-bundle.json | sudo /opt/spire/bin/spire-server bundle set -socketPath /opt/spire/data/server/api.sock -format spiffe -id spiffe://aim.microsoft.com" 2>/dev/null
        rm -f "$BUNDLE_EXCHANGE_FILE"
        echo "   Azure bundle → GCP SPIRE: set"
    fi

    # Get GCP bundle, send to Azure
    GCP_BUNDLE_FILE="${REPO_ROOT}/.gcp-bundle-exchange.json"
    gcloud compute ssh google-budget-reader \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --command "sudo /opt/spire/bin/spire-server bundle show -socketPath /opt/spire/data/server/api.sock -format spiffe" > "$GCP_BUNDLE_FILE" 2>/dev/null
    if [ -s "$GCP_BUNDLE_FILE" ]; then
        GCP_B64=$(base64 < "$GCP_BUNDLE_FILE" | tr -d '\n')
        vm_run "set-gcp-bun" "echo '$GCP_B64' | base64 -d | sudo docker exec -i spire-server /opt/spire/bin/spire-server bundle set -format spiffe -id spiffe://gcp.aim.microsoft.com" 60 || true
        echo "   GCP bundle → Azure SPIRE: set"
    fi
    rm -f "$GCP_BUNDLE_FILE"

    # --- Step G12: Update budget-backend SPIRE entry with federation ---
    echo "🔗 Step G12: Updating budget-backend SPIRE entry with federation..."
    BB_SPIFFE="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_BUDGET_BACKEND}"

    # Check if already federated
    EXISTING_ENTRY=$(vm_run "check-bb-fed" "sudo docker exec spire-server /opt/spire/bin/spire-server entry show 2>&1 | grep -A5 '$BB_SPIFFE' | grep 'FederatesWith'" 60 2>/dev/null || true)
    if ! echo "$EXISTING_ENTRY" | grep -q "gcp.aim.microsoft.com" 2>/dev/null; then
        # Find and delete the old entry, recreate with federation
        ENTRY_ID=$(vm_run "find-bb-entry" "sudo docker exec spire-server /opt/spire/bin/spire-server entry show 2>&1 | grep -B1 '$BB_SPIFFE' | grep 'Entry ID' | awk '{print \$NF}'" 60 2>/dev/null || true)
        if [ -n "$ENTRY_ID" ]; then
            vm_run "del-bb-entry" "sudo docker exec spire-server /opt/spire/bin/spire-server entry delete -entryID $ENTRY_ID" 60 || true
        fi
        BB_PARENT="spiffe://${TRUST_DOMAIN}/agent/budget-backend"
        vm_run "create-bb-fed" "sudo docker exec spire-server /opt/spire/bin/spire-server entry create \
            -parentID $BB_PARENT \
            -spiffeID $BB_SPIFFE \
            -selector unix:uid:0 \
            -ttl 3600 \
            -federatesWith gcp.aim.microsoft.com" 60
        echo "   Updated with federatesWith gcp.aim.microsoft.com"
    else
        echo "   ✅ Already federated"
    fi

    # --- Step G13: Register external agent in portal blob store ---
    echo "📋 Step G13: Registering google-budget-reader in portal external-agent store..."
    _STORAGE_ACCOUNT="${STORAGE_ACCOUNT:-$(az storage account list --resource-group "$RG" --query "[0].name" -o tsv 2>/dev/null)}"
    if [ -n "$_STORAGE_ACCOUNT" ]; then
        _EXT_AGENT_JSON=$(cat <<EXTJSON
[{
  "name": "google-budget-reader",
  "invoke_url": "http://${GCE_PRIVATE_IP}:8000",
  "spiffe_id": "${GOOGLE_SPIFFE}",
  "entra_agent_id": "${GOOGLE_AGENT_ID}",
  "trust_domain": "gcp.aim.microsoft.com",
  "cloud_provider": "gcp"
}]
EXTJSON
)
        # Merge with existing agents if the blob already exists
        _EXISTING=$(az storage blob download --account-name "$_STORAGE_ACCOUNT" \
            --container-name "portal-external-agents" --name "external-agents.json" \
            --auth-mode key --query content -o tsv 2>/dev/null || echo "[]")
        if echo "$_EXISTING" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
            _MERGED=$(python3 -c "
import json, sys
existing = json.loads('''$_EXISTING''') if '''$_EXISTING'''.strip() else []
new_agent = json.loads('''$_EXT_AGENT_JSON''')[0]
# Replace if exists, otherwise append
merged = [a for a in existing if a.get('name') != new_agent['name']]
merged.append(new_agent)
print(json.dumps(merged, indent=2))
")
        else
            _MERGED="$_EXT_AGENT_JSON"
        fi
        echo "$_MERGED" | az storage blob upload --account-name "$_STORAGE_ACCOUNT" \
            --container-name "portal-external-agents" --name "external-agents.json" \
            --content-type "application/json" --overwrite --auth-mode key \
            --data @- >/dev/null 2>&1 \
            && echo "   ✅ Registered google-budget-reader (invoke_url=http://${GCE_PRIVATE_IP}:8000)" \
            || echo "   ⚠️  Failed to register external agent — set invoke_url manually via portal"
    else
        echo "   ⚠️  Storage account not found — register external agent manually via portal"
    fi

    # --- Step G14: Verify ---
    echo "🧪 Step G14: Verifying Google agent..."
    sleep 5
    HEALTH=$(gcloud compute ssh google-budget-reader \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --command "curl -s http://localhost:8000/health" 2>/dev/null || true)
    echo "   Agent health: $HEALTH"

    TEST_RESULT=$(gcloud compute ssh google-budget-reader \
        --zone "${GCP_REGION}-a" --project "$GCP_PROJECT" \
        --command "curl -s -X POST 'http://localhost:8000/call-backend-raw?method=GET&path=/budget/read'" 2>/dev/null || true)
    TEST_STATUS=$(echo "$TEST_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('http_status','?'))" 2>/dev/null || echo "?")

    if [ "$TEST_STATUS" = "200" ]; then
        echo "   ✅ google-budget-reader → GET /budget/read → 200"
    else
        echo "   ⚠️  google-budget-reader test: status=$TEST_STATUS (may need token propagation time)"
    fi

    echo ""
    echo "============================================="
    echo "  Google Cross-Cloud Agent: DEPLOYED"
    echo "============================================="
    echo "  GCE VM: $GCE_IP"
    echo "  Agent health: http://${GCE_IP}:8000/health"
    echo "  Cloud identity: http://${GCE_IP}:8000/cloud-identity"
    echo "  SPIFFE ID: $GOOGLE_SPIFFE"
    echo ""
fi

# =============================================================================
# GitHub Actions Agent (optional, --github flag)
# =============================================================================

if [ "$GITHUB_AGENT" = true ]; then
    echo ""
    echo "============================================="
    echo "  GitHub Actions Self-Hosted Runner Setup"
    echo "============================================="
    echo ""

    GITHUB_ORG="${GITHUB_ORG:-microsoft}"
    GITHUB_REPO="${GITHUB_REPO:-identity-spiffe}"

    # --- GH1: Ensure Bicep params are set ---
    echo "🏗️  GH1 — Ensuring deployGitHubRunner=true in Bicep params..."
    azd env set DEPLOY_GITHUB_RUNNER true
    azd env set GITHUB_ORG "$GITHUB_ORG"
    azd env set GITHUB_REPO "$GITHUB_REPO"

    # If Step 1 already ran azd provision (no --skip-provision), the runner VM
    # was created in that cycle. Only run a second provision if Step 1 was skipped.
    if [ "$SKIP_PROVISION" = true ]; then
        echo "   Step 1 was skipped — running azd provision now for runner VM..."
        azd provision --no-prompt
    else
        echo "   ✅ Runner VM was provisioned in Step 1 (no second cycle needed)"
    fi

    # --- GH2: Get runner VM IP ---
    echo ""
    echo "🔍 GH2 — Getting runner VM IP..."
    RUNNER_VM_IP=$(az vm show -g "$RESOURCE_GROUP" -n "github-runner" -d --query publicIps -o tsv 2>/dev/null || true)
    if [ -z "$RUNNER_VM_IP" ]; then
        echo "ERROR: Runner VM not found. Run without --skip-provision first." >&2
        exit 1
    fi
    echo "   Runner VM IP: $RUNNER_VM_IP"

    # --- GH3: Get GitHub runner registration token ---
    echo ""
    echo "🎟️  GH3 — Getting runner registration token..."
    RUNNER_TOKEN=$(gh api -X POST "repos/${GITHUB_ORG}/${GITHUB_REPO}/actions/runners/registration-token" --jq '.token' 2>/dev/null || true)
    if [ -z "$RUNNER_TOKEN" ]; then
        echo "ERROR: Could not get runner registration token. Check gh auth and repo permissions." >&2
        exit 1
    fi
    echo "   ✅ Runner registration token acquired"

    # --- GH4: Entra provisioning ---
    echo ""
    echo "🤖 GH4 — Running Entra provisioning..."
    RUNNER_SPIFFE_ID="spiffe://aim.microsoft.com/agent/github-budget-reader"
    "${SCRIPT_DIR}/scripts/add-github-agent.sh" \
        --github-org "$GITHUB_ORG" \
        --name "github-budget-reader" \
        --runner-spiffe-id "$RUNNER_SPIFFE_ID" \
        --portal-url "${_EARLY_PORTAL_URL:-http://localhost:8550}" \
        --mgmt-key "${MGMT_API_KEY:-}"

    # --- GH5: Prepare SPIRE artifacts + run setup script on VM ---
    echo ""
    echo "⚙️  GH5 — Preparing SPIRE artifacts for runner..."

    GITHUB_AGENT_ID=$(azd_env_get_from_blob "$(azd_env_load)" "ENTRA_AGENT_ID_GITHUB_BUDGET_READER" || true)
    SPIRE_VM_IP=$(az vm show -g "$RESOURCE_GROUP" -n "spire-server" -d --query privateIps -o tsv 2>/dev/null || true)

    # Look up budget-backend ingress FQDN (for spiffe-proxy egress target)
    BUDGET_BACKEND_FQDN=$(az containerapp show -g "$RESOURCE_GROUP" -n budget-backend \
        --query 'properties.configuration.ingress.fqdn' -o tsv 2>/dev/null || true)
    BUDGET_BACKEND_SPIFFE_ID="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${ENTRA_AGENT_OID_BUDGET_BACKEND}"

    # Extract current Azure SPIRE trust bundle (PEM)
    echo "   Extracting SPIRE trust bundle..."
    SPIRE_BUNDLE_PEM=$(vm_run "gh-bundle" "sudo docker exec spire-server /opt/spire/bin/spire-server bundle show -format pem" 90 2>/dev/null | awk '/BEGIN CERT/,/END CERT/')
    if [ -z "$SPIRE_BUNDLE_PEM" ]; then
        echo "ERROR: Could not extract SPIRE trust bundle from spire-server VM." >&2
        exit 1
    fi
    SPIRE_BUNDLE_B64=$(echo "$SPIRE_BUNDLE_PEM" | base64 | tr -d '\n')

    # Generate a fresh join token for the runner node
    echo "   Generating SPIRE join token..."
    RUNNER_NODE_SPIFFE="spiffe://aim.microsoft.com/agent/github-runner"
    JOIN_TOKEN_OUT=$(vm_run "gh-token" "sudo docker exec spire-server /opt/spire/bin/spire-server token generate -spiffeID ${RUNNER_NODE_SPIFFE}" 90 2>/dev/null || true)
    SPIRE_JOIN_TOKEN=$(echo "$JOIN_TOKEN_OUT" | grep -oE 'Token: [a-f0-9-]+' | awk '{print $2}' | head -1)
    if [ -z "$SPIRE_JOIN_TOKEN" ]; then
        echo "ERROR: Could not generate SPIRE join token." >&2
        exit 1
    fi
    echo "   ✅ Join token generated: ${SPIRE_JOIN_TOKEN:0:8}..."

    # Register workload entry: parent=github-runner agent, SPIFFE=bp/aid for Entra Agent Identity
    if [ -n "$GITHUB_AGENT_ID" ]; then
        GITHUB_WORKLOAD_SPIFFE="spiffe://aim.microsoft.com/ests/bp/${ENTRA_BP_OID}/aid/${GITHUB_AGENT_ID}"
        echo "   Registering SPIRE workload entry: ${GITHUB_WORKLOAD_SPIFFE}"
        vm_run "gh-workload-entry" "sudo docker exec spire-server /opt/spire/bin/spire-server entry create \
            -parentID '${RUNNER_NODE_SPIFFE}' \
            -spiffeID '${GITHUB_WORKLOAD_SPIFFE}' \
            -selector unix:uid:0 \
            -ttl 3600 2>&1 | grep -E 'Entry ID|already exists' || true" 60 2>&1 | tail -5 || true
    else
        echo "   ⚠️  GITHUB_AGENT_ID empty — skipping workload entry (fix GH4 persistence)"
    fi

    echo ""
    echo "⚙️  GH5.1 — Running setup-github-runner.sh on VM..."

    az vm run-command create \
        --resource-group "$RESOURCE_GROUP" \
        --vm-name "github-runner" \
        --name "setup-github-runner" \
        --timeout-in-seconds 600 \
        --script @"${SCRIPT_DIR}/scripts/setup-github-runner.sh" \
        --parameters \
            "SPIRE_SERVER_IP=${SPIRE_VM_IP}" \
            "SPIRE_TRUST_BUNDLE=${SPIRE_BUNDLE_B64}" \
            "SPIRE_JOIN_TOKEN=${SPIRE_JOIN_TOKEN}" \
            "GITHUB_RUNNER_TOKEN=${RUNNER_TOKEN}" \
            "GITHUB_ORG=${GITHUB_ORG}" \
            "GITHUB_REPO=${GITHUB_REPO}" \
            "AGENT_NAME=github-budget-reader" \
            "BLUEPRINT_APP_ID=${ENTRA_BP_OID:-}" \
            "AGENT_IDENTITY_ID=${GITHUB_AGENT_ID:-}" \
            "AZURE_TENANT_ID=${AZURE_TENANT_ID_VAL:-}" \
            "ACR_LOGIN_SERVER=${ACR_SERVER:-}" \
            "SPIFFE_PROXY_IMAGE=spiffe-proxy:${IMAGE_TAG}" \
            "BUDGET_BACKEND_FQDN=${BUDGET_BACKEND_FQDN:-}" \
            "BUDGET_BACKEND_SPIFFE_ID=${BUDGET_BACKEND_SPIFFE_ID}" \
        --no-wait 2>/dev/null || {
            echo "WARNING: VM run-command may have failed. Check Azure portal." >&2
        }

    echo "   ✅ Setup script dispatched to runner VM"

    # --- GH6: Patch RBAC policy ---
    echo ""
    echo "📋 GH6 — Patching RBAC policy with GitHub agent ID..."
    if [ -n "$GITHUB_AGENT_ID" ]; then
        RBAC_FILE="${SCRIPT_DIR}/src/spiffe-proxy/config/spiffe-rbac-policy.yaml"
        # Patch both the placeholder token (fresh checkout) and any existing UUID
        # under the github-budget-reader stanza (previous deploy left a real OID).
        python3 - "$RBAC_FILE" "$GITHUB_AGENT_ID" << 'PYEOF'
import sys, re, pathlib
path = pathlib.Path(sys.argv[1])
new_oid = sys.argv[2]
text = path.read_text()
# Match entra_agent_id line that follows (within the same YAML list item) the
# `name: "github-budget-reader"` line. A new list item (`- ` at indent) terminates
# the window.
pattern = re.compile(
    r'(name:\s*["\']?github-budget-reader["\']?[^\n]*(?:\n(?!\s*-\s)[^\n]*)*?'
    r'entra_agent_id:\s*["\']?)[A-Za-z0-9_\-]+(["\']?)',
    re.MULTILINE
)
new_text, n = pattern.subn(rf'\g<1>{new_oid}\g<2>', text)
if n == 0:
    new_text = text.replace('PLACEHOLDER_GITHUB_AGENT_OID', new_oid)
    n = text.count('PLACEHOLDER_GITHUB_AGENT_OID')
path.write_text(new_text)
print(f'patched {n} occurrence(s)')
PYEOF
        echo "   ✅ RBAC policy patched with OID: ${GITHUB_AGENT_ID}"
    else
        echo "   ⚠️  Agent ID not available — RBAC policy still has placeholder"
    fi

    echo ""
    echo "============================================="
    echo "  ✅ GitHub Actions Runner Setup Complete"
    echo "============================================="
    echo "  Runner VM:    $RUNNER_VM_IP"
    echo "  SPIFFE ID:    $RUNNER_SPIFFE_ID"
    echo "  GitHub org:   $GITHUB_ORG"
    echo "  GitHub repo:  $GITHUB_REPO"
    echo ""
fi
