#!/bin/bash

# Shared deployment defaults and agent metadata.

TRUST_DOMAIN="${TRUST_DOMAIN:-aim.microsoft.com}"
IMAGE_TAG="${IMAGE_TAG:-v22}"
SPIRE_SERVER_VM_NAME="${SPIRE_SERVER_VM_NAME:-spire-server}"

AGENTS=(
    "budget-report"
    "budget-backend"
    "employee-menus"
    "budget-approval"
    "admin-control-plane"
)

agent_proxy_mode() {
    case "$1" in
        budget-backend) echo "ingress" ;;
        *) echo "egress" ;;
    esac
}

agent_oid_var_name() {
    case "$1" in
        budget-report) echo "ENTRA_AGENT_OID_BUDGET_REPORT" ;;
        budget-backend) echo "ENTRA_AGENT_OID_BUDGET_BACKEND" ;;
        employee-menus) echo "ENTRA_AGENT_OID_EMPLOYEE_MENUS" ;;
        budget-approval) echo "ENTRA_AGENT_OID_BUDGET_APPROVAL" ;;
        admin-control-plane) echo "ENTRA_AGENT_OID_ADMIN_CONTROL_PLANE" ;;
        *) return 1 ;;
    esac
}

agent_entra_id_var_name() {
    case "$1" in
        budget-report) echo "ENTRA_ID_BUDGET_REPORT" ;;
        budget-backend) echo "ENTRA_ID_BUDGET_BACKEND" ;;
        employee-menus) echo "ENTRA_ID_EMPLOYEE_MENUS" ;;
        budget-approval) echo "ENTRA_ID_BUDGET_APPROVAL" ;;
        admin-control-plane) echo "ENTRA_ID_ADMIN_CONTROL_PLANE" ;;
        *) return 1 ;;
    esac
}

agent_service_url_var_name() {
    case "$1" in
        budget-report) echo "SERVICE_BUDGET_REPORT_ENDPOINT_URL" ;;
        budget-backend) echo "SERVICE_BUDGET_BACKEND_ENDPOINT_URL" ;;
        employee-menus) echo "SERVICE_EMPLOYEE_MENUS_ENDPOINT_URL" ;;
        budget-approval) echo "SERVICE_BUDGET_APPROVAL_ENDPOINT_URL" ;;
        admin-control-plane) echo "SERVICE_ADMIN_CONTROL_PLANE_ENDPOINT_URL" ;;
        *) return 1 ;;
    esac
}
