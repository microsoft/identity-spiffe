#!/bin/bash

if [ -n "${ZSH_VERSION:-}" ]; then
    _ENTRA_SCOPE_SOURCE_FILE="${(%):-%N}"
elif [ -n "${BASH_SOURCE[0]:-}" ]; then
    _ENTRA_SCOPE_SOURCE_FILE="${BASH_SOURCE[0]}"
else
    _ENTRA_SCOPE_SOURCE_FILE="$0"
fi

SCRIPT_DIR_ENTRA_SCOPE="$(cd "$(dirname "${_ENTRA_SCOPE_SOURCE_FILE}")" && pwd)"
REPO_ROOT_ENTRA_SCOPE="$(cd "${SCRIPT_DIR_ENTRA_SCOPE}/../.." && pwd)"

_entra_scope_python() {
    python3 "${REPO_ROOT_ENTRA_SCOPE}/scripts/entra_scope.py" "$@"
}

entra_scope_init() {
    local exports
    exports="$(_entra_scope_python shell-exports)" || return 1
    eval "$exports"
}

resolve_scope_mode() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ISP_ENV_SCOPE_MODE}"
}

resolve_scope_key() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ISP_ENV_SCOPE_KEY}"
}

blueprint_display_name() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ENTRA_SCOPE_BLUEPRINT_DISPLAY_NAME}"
}

agent_identity_display_name() {
    entra_scope_init >/dev/null || return 1
    _entra_scope_python name agent "$1"
}

fic_name() {
    entra_scope_init >/dev/null || return 1
    _entra_scope_python name fic "$1"
}

portal_management_app_display_name() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ENTRA_SCOPE_PORTAL_MANAGEMENT_APP_DISPLAY_NAME}"
}

portal_securityportal_app_display_name() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ENTRA_SCOPE_PORTAL_SECURITYPORTAL_APP_DISPLAY_NAME}"
}

portal_admin_group_display_name() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ENTRA_SCOPE_PORTAL_ADMIN_GROUP_DISPLAY_NAME}"
}

portal_viewer_group_display_name() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ENTRA_SCOPE_PORTAL_VIEWER_GROUP_DISPLAY_NAME}"
}

portal_admin_group_mail_nickname() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ENTRA_SCOPE_PORTAL_ADMIN_GROUP_MAIL_NICKNAME}"
}

portal_viewer_group_mail_nickname() {
    entra_scope_init >/dev/null || return 1
    printf '%s\n' "${ENTRA_SCOPE_PORTAL_VIEWER_GROUP_MAIL_NICKNAME}"
}

validate_entra_scope() {
    entra_scope_init >/dev/null || return 1
    if [ "${ISP_ENV_SCOPE_MODE}" = "scoped" ] && [ -z "${ISP_ENV_SCOPE_ENV_NAME:-}" ]; then
        echo "ERROR: Scoped Entra naming requires AZURE_ENV_NAME." >&2
        return 1
    fi
    if [ ${#ENTRA_SCOPE_PORTAL_ADMIN_GROUP_MAIL_NICKNAME} -gt 64 ]; then
        echo "ERROR: Portal admin mail nickname exceeds 64 characters: ${ENTRA_SCOPE_PORTAL_ADMIN_GROUP_MAIL_NICKNAME}" >&2
        return 1
    fi
    if [ ${#ENTRA_SCOPE_PORTAL_VIEWER_GROUP_MAIL_NICKNAME} -gt 64 ]; then
        echo "ERROR: Portal viewer mail nickname exceeds 64 characters: ${ENTRA_SCOPE_PORTAL_VIEWER_GROUP_MAIL_NICKNAME}" >&2
        return 1
    fi
}

print_entra_scope_summary() {
    entra_scope_init >/dev/null || return 1
    local calling_agents=("budget-report" "budget-approval" "employee-menus")
    echo "   ISP_ENV_SCOPE_MODE: ${ISP_ENV_SCOPE_MODE} (${ISP_ENV_SCOPE_MODE_SOURCE})"
    echo "   ISP_ENV_SCOPE_KEY: ${ISP_ENV_SCOPE_KEY} (${ISP_ENV_SCOPE_KEY_SOURCE})"
    echo "   Blueprint: ${ENTRA_SCOPE_BLUEPRINT_DISPLAY_NAME}"
    local agent
    for agent in "$@"; do
        echo "   Agent Identity [${agent}]: $(agent_identity_display_name "${agent}")"
    done
    for agent in "${calling_agents[@]}"; do
        echo "   FIC [${agent}]: $(fic_name "${agent}")"
    done
    echo "   Portal admin group: ${ENTRA_SCOPE_PORTAL_ADMIN_GROUP_DISPLAY_NAME} (${ENTRA_SCOPE_PORTAL_ADMIN_GROUP_MAIL_NICKNAME})"
    echo "   Portal viewer group: ${ENTRA_SCOPE_PORTAL_VIEWER_GROUP_DISPLAY_NAME} (${ENTRA_SCOPE_PORTAL_VIEWER_GROUP_MAIL_NICKNAME})"
    echo "   Portal management app: ${ENTRA_SCOPE_PORTAL_MANAGEMENT_APP_DISPLAY_NAME}"
    echo "   Security portal app: ${ENTRA_SCOPE_PORTAL_SECURITYPORTAL_APP_DISPLAY_NAME}"
}
