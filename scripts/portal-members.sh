#!/bin/bash
# =============================================================================
# scripts/portal-members.sh
# Manage portal Administrators / Viewers group membership post-deploy.
#
# Usage:
#   ./scripts/portal-members.sh add-admin <upn|oid> [<upn|oid> ...]
#   ./scripts/portal-members.sh add-viewer <upn|oid> [<upn|oid> ...]
#   ./scripts/portal-members.sh remove-admin <upn|oid> [<upn|oid> ...]
#   ./scripts/portal-members.sh remove-viewer <upn|oid> [<upn|oid> ...]
#   ./scripts/portal-members.sh list
#
# Reads ISP_ADMIN_GROUP_ID / ISP_VIEWER_GROUP_ID from the current azd env
# (populated by deploy.sh). Users are resolved as UPN/email or object ID.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# shellcheck source=scripts/lib/azure-helpers.sh
source "${SCRIPT_DIR}/lib/azure-helpers.sh"

usage() {
    sed -n '3,14p' "${BASH_SOURCE[0]}" | sed 's|^# \{0,1\}||'
    exit "${1:-0}"
}

[ $# -ge 1 ] || usage 1
ACTION="$1"
shift || true

require_command az >/dev/null

AZD_VALUES="$(azd_env_load)"
ADMIN_GROUP_ID="$(azd_env_get_from_blob "$AZD_VALUES" "ISP_ADMIN_GROUP_ID")"
VIEWER_GROUP_ID="$(azd_env_get_from_blob "$AZD_VALUES" "ISP_VIEWER_GROUP_ID")"

if [ -z "$ADMIN_GROUP_ID" ] || [ -z "$VIEWER_GROUP_ID" ]; then
    echo "ERROR: ISP_ADMIN_GROUP_ID / ISP_VIEWER_GROUP_ID not found in azd env." >&2
    echo "       Run ./deploy.sh first so the portal groups are provisioned." >&2
    exit 1
fi

resolve_user_oid() {
    local value="$1"
    if [[ "$value" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        printf '%s\n' "$value"
        return 0
    fi
    az ad user show --id "$value" --query "id" -o tsv 2>/dev/null
}

group_name_for() {
    case "$1" in
        admin) printf '%s\n' "Administrators ($ADMIN_GROUP_ID)" ;;
        viewer) printf '%s\n' "Viewers ($VIEWER_GROUP_ID)" ;;
    esac
}

group_id_for() {
    case "$1" in
        admin) printf '%s\n' "$ADMIN_GROUP_ID" ;;
        viewer) printf '%s\n' "$VIEWER_GROUP_ID" ;;
    esac
}

add_member() {
    local role="$1"; shift
    local group_id; group_id="$(group_id_for "$role")"
    local group_label; group_label="$(group_name_for "$role")"
    [ $# -ge 1 ] || { echo "ERROR: no users supplied" >&2; exit 1; }
    local rc=0
    for raw in "$@"; do
        local oid
        oid="$(resolve_user_oid "$raw")"
        if [ -z "$oid" ]; then
            echo "⚠  Could not resolve '$raw'; skipped" >&2; rc=1; continue
        fi
        if az ad group member add --group "$group_id" --member-id "$oid" 2>/dev/null; then
            echo "✅ Added '$raw' ($oid) to $group_label"
        elif az ad group member check --group "$group_id" --member-id "$oid" --query "value" -o tsv 2>/dev/null | grep -qi true; then
            echo "ℹ  '$raw' ($oid) already in $group_label"
        else
            echo "⚠  Failed to add '$raw' ($oid) to $group_label" >&2; rc=1
        fi
    done
    return $rc
}

remove_member() {
    local role="$1"; shift
    local group_id; group_id="$(group_id_for "$role")"
    local group_label; group_label="$(group_name_for "$role")"
    [ $# -ge 1 ] || { echo "ERROR: no users supplied" >&2; exit 1; }
    local rc=0
    for raw in "$@"; do
        local oid
        oid="$(resolve_user_oid "$raw")"
        if [ -z "$oid" ]; then
            echo "⚠  Could not resolve '$raw'; skipped" >&2; rc=1; continue
        fi
        if az ad group member remove --group "$group_id" --member-id "$oid" 2>/dev/null; then
            echo "✅ Removed '$raw' ($oid) from $group_label"
        else
            echo "⚠  Failed to remove '$raw' ($oid) from $group_label (may not be a member)" >&2; rc=1
        fi
    done
    return $rc
}

list_members() {
    for role in admin viewer; do
        local group_id; group_id="$(group_id_for "$role")"
        local group_label; group_label="$(group_name_for "$role")"
        echo "── $group_label ─────────────────────────────────────"
        az ad group member list --group "$group_id" \
            --query "[].{displayName:displayName, upn:userPrincipalName, id:id}" \
            -o table 2>/dev/null || echo "(failed to list)"
        echo ""
    done
}

case "$ACTION" in
    add-admin)     add_member admin "$@" ;;
    add-viewer)    add_member viewer "$@" ;;
    remove-admin)  remove_member admin "$@" ;;
    remove-viewer) remove_member viewer "$@" ;;
    list)          list_members ;;
    -h|--help|help) usage 0 ;;
    *) echo "ERROR: Unknown action: $ACTION" >&2; usage 1 ;;
esac
