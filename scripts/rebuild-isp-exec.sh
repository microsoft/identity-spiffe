#!/usr/bin/env bash
# Rebuild only the isp-exec-20260901 deployment.
set -euo pipefail

cd "$(dirname "$0")/.."

ENV_NAME=isp-exec-20260901
RG=rg-isp-exec-20260901
SUBSCRIPTION=66ab9e9e-da1b-4b2d-bdfa-344efeaf5b5d
TENANT=cff56d8f-f602-4afd-94e4-c95b76f1c81e

for tool in az azd python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing $tool. Install it before running this script; nothing was deleted." >&2
        exit 1
    fi
done

if [ "$(git branch --show-current)" != main ]; then
    echo "Switch to the main checkout first; nothing was deleted." >&2
    exit 1
fi
git fetch --quiet origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    echo "Local main is not up to date. Fast-forward it before running this script." >&2
    exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
    echo "The checkout is dirty. Commit or stash changes before rebuilding; nothing was deleted." >&2
    exit 1
fi

echo "Signing in with the MFA claim required by the Azure management API..."
az login --tenant "$TENANT" \
    --scope 'https://management.core.windows.net//.default' \
    --claims-challenge 'eyJhY2Nlc3NfdG9rZW4iOnsiYWNycyI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlcyI6WyJwMSJdfX19' \
    -o none
az account set --subscription "$SUBSCRIPTION"
echo "Signing Azure Developer CLI into the same tenant..."
azd auth login --tenant-id "$TENANT"
if [ "$(az account show --query tenantId -o tsv)" != "$TENANT" ]; then
    echo "Wrong Azure tenant; nothing was deleted." >&2
    exit 1
fi

if [ ! -f ".azure/$ENV_NAME/.env" ]; then
    echo "Creating local azd environment $ENV_NAME..."
    azd env new "$ENV_NAME" --subscription "$SUBSCRIPTION" --location westus
else
    azd env select "$ENV_NAME"
fi
azd env set AZURE_SUBSCRIPTION_ID "$SUBSCRIPTION"
azd env set AZURE_TENANT_ID "$TENANT"
azd env set AZURE_LOCATION westus
azd env set ISP_ENV_SCOPE_MODE scoped
azd env set ISP_ENV_SCOPE_KEY "$ENV_NAME"
azd env set CA_RISK_PROVIDER sidecar
azd env config set infra.parameters.environmentName "$ENV_NAME"

if [ "$(azd env get-values | grep -E '^AZURE_ENV_NAME=' | cut -d= -f2- | tr -d '\"')" != "$ENV_NAME" ]; then
    echo "Could not select azd environment $ENV_NAME; nothing was deleted." >&2
    exit 1
fi
if [ "$(azd env get-values | grep -E '^AZURE_SUBSCRIPTION_ID=' | cut -d= -f2- | tr -d '\"')" != "$SUBSCRIPTION" ]; then
    echo "The azd environment targets a different subscription; nothing was deleted." >&2
    exit 1
fi
if [ "$(az group show -n "$RG" --query 'tags."azd-env-name"' -o tsv)" != "$ENV_NAME" ]; then
    echo "Resource group tag does not match $ENV_NAME; nothing was deleted." >&2
    exit 1
fi

# Pin every target to a known object ID as well as its expected display name.
# Do not delete the tenant-wide provisioner, CA policy, or Admin/Viewer groups.
agent_ids=(
    07b015b8-899d-4a69-b60b-8a4b339637db
    511b5b73-0170-4606-a7a2-fa0abc6f47d1
    806e39b1-2ffb-4b46-b8db-37945e3b8cc8
    9593214e-9f38-4cfc-8212-06b6bf7c75a0
    e1b47062-06d0-45b8-a2c3-06265e666453
)
agent_names=(
    isp-exec-20260901-budget-approval
    isp-exec-20260901-budget-report
    isp-exec-20260901-budget-backend
    isp-exec-20260901-employee-menus
    isp-exec-20260901-admin-control-plane
)
app_ids=(
    20cee185-6d71-48de-885c-c2ea79651610
    36245915-e046-4831-a856-97733741615a
    ea98651a-f0e4-4602-8bc1-e7943a90c869
)
app_names=(
    "Agent Management Portal - Management [$ENV_NAME]"
    "Agent Management Portal - Security Portal Mock [$ENV_NAME]"
    "Agent Management Budget Backend Agents [$ENV_NAME]"
)

for i in "${!agent_ids[@]}"; do
    name=$(az ad sp show --id "${agent_ids[$i]}" --query displayName -o tsv)
    [ "$name" = "${agent_names[$i]}" ] || { echo "Agent Identity mismatch: ${agent_ids[$i]}" >&2; exit 1; }
done
for i in "${!app_ids[@]}"; do
    name=$(az ad app show --id "${app_ids[$i]}" --query displayName -o tsv)
    [ "$name" = "${app_names[$i]}" ] || { echo "App registration mismatch: ${app_ids[$i]}" >&2; exit 1; }
done

echo "Target: $RG, 5 scoped Agent Identities and 3 scoped app registrations."
echo "Shared Entra groups, provisioner, and CA policy will remain."
echo "WARNING: all data in $RG, including the SPIRE CA and datastore, will be lost."
echo "The deployment's verification phase will initialize and validate its test risk state."
confirmation="${CONFIRM_REBUILD:-}"
if [ "$confirmation" != "$RG" ]; then
    read -r -p "Type $RG to delete it and redeploy: " confirmation
fi
if [ "$confirmation" != "$RG" ]; then
    echo "Cancelled; nothing was deleted."
    exit 1
fi

az group delete -n "$RG" --yes
if [ "$(az group exists -n "$RG")" != false ]; then
    echo "Resource group still exists; stop before deleting Entra objects." >&2
    exit 1
fi

for i in "${!agent_ids[@]}"; do
    echo "Deleting ${agent_names[$i]}"
    az rest --method DELETE --url "https://graph.microsoft.com/beta/servicePrincipals/${agent_ids[$i]}" -o none
done
for i in "${!app_ids[@]}"; do
    # Delete the associated service principal first, if one exists.
    sp_id=$(az ad sp list --filter "appId eq '${app_ids[$i]}'" --query '[0].id' -o tsv)
    if [ -n "$sp_id" ] && [ "$sp_id" != None ]; then
        echo "Deleting service principal for ${app_names[$i]}"
        az rest --method DELETE --url "https://graph.microsoft.com/v1.0/servicePrincipals/$sp_id" -o none
    fi
    echo "Deleting ${app_names[$i]}"
    az ad app delete --id "${app_ids[$i]}"
done

for key in ENTRA_BLUEPRINT_APP_ID ENTRA_BLUEPRINT_OBJECT_ID \
    ENTRA_AGENT_ID_BUDGET_REPORT ENTRA_AGENT_ID_BUDGET_BACKEND \
    ENTRA_AGENT_ID_EMPLOYEE_MENUS ENTRA_AGENT_ID_BUDGET_APPROVAL \
    ENTRA_AGENT_ID_ADMIN_CONTROL_PLANE ENTRA_FIC_CREATED_BUDGET_REPORT \
    ENTRA_FIC_CREATED_BUDGET_APPROVAL ENTRA_FIC_CREATED_EMPLOYEE_MENUS \
    ENTRA_OAUTH2_APP_ROLES_READY ENTRA_OAUTH2_AUDIENCE \
    PORTAL_AUTH_CLIENT_ID SECURITYPORTAL_AUTH_CLIENT_ID \
    SPIRE_SERVER_FQDN AZURE_RESOURCE_GROUP \
    PORTAL_RUNTIME_SETTINGS_CONTAINER PORTAL_RUNTIME_SETTINGS_BLOB_NAME; do
    azd env set "$key" ""
done
azd env set ISP_ENV_SCOPE_MODE scoped
azd env set ISP_ENV_SCOPE_KEY "$ENV_NAME"

echo "Starting a fresh deployment in $ENV_NAME..."
./deploy.sh --new

echo "Checking live management readiness..."
portal_host=$(az containerapp show -g "$RG" -n isp-portal --query properties.configuration.ingress.fqdn -o tsv)
curl --fail --silent --show-error --max-time 20 "https://$portal_host/healthz/ready" -o /dev/null || {
    echo "Deployment finished, but the portal is not ready; investigate risk evidence before release testing." >&2
    exit 1
}
echo "Deployment and portal readiness succeeded: https://$portal_host/"
