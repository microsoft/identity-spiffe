#!/usr/bin/env bash
# =============================================================================
# flush-tokens.sh — Clear cached Entra tokens on caller agents
# =============================================================================
# Use after changing app role assignments so agents acquire fresh tokens
# with updated roles claims. No redeployment needed.
#
# Usage:
#   ./scripts/flush-tokens.sh              # Flush all callers
#   ./scripts/flush-tokens.sh budget-report  # Flush one agent
# =============================================================================
set -euo pipefail

# Read endpoints from azd env
AZD_VALUES=$(azd env get-values 2>/dev/null || true)
get_val() { echo "$AZD_VALUES" | grep -E "^$1=" | cut -d= -f2 | tr -d '"'; }

REPORT_URL=$(get_val SERVICE_BUDGET_REPORT_ENDPOINT_URL)
APPROVAL_URL=$(get_val SERVICE_BUDGET_APPROVAL_ENDPOINT_URL)
MGMT_API_KEY=$(get_val MGMT_API_KEY)

flush_agent() {
    local name="$1"
    local url="$2"
    if [ -z "$url" ]; then
        echo "  ⚠️  $name: no endpoint URL (not deployed?)"
        return
    fi
    if [ -z "$MGMT_API_KEY" ]; then
        echo "  ❌ $name: MGMT_API_KEY missing from azd env"
        return
    fi
    local resp
    resp=$(curl -s -X POST \
        -H "X-Spiffe-Admin-Key: ${MGMT_API_KEY}" \
        "${url}/flush-token" 2>&1) || true
    if echo "$resp" | grep -q '"flushed"'; then
        echo "  ✅ $name: token cache cleared"
    else
        echo "  ❌ $name: flush failed — $resp"
    fi
}

echo ""
echo "Flushing Entra token caches..."
echo ""

TARGET="${1:-all}"

if [ "$TARGET" = "all" ] || [ "$TARGET" = "budget-report" ]; then
    flush_agent "BudgetReport" "$REPORT_URL"
fi
if [ "$TARGET" = "all" ] || [ "$TARGET" = "budget-approval" ]; then
    flush_agent "BudgetApproval" "$APPROVAL_URL"
fi

echo ""
echo "Next request from each agent will acquire a fresh token with current role assignments."
echo ""
