#!/usr/bin/env bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Cross-Cloud Connectivity Validation
# =============================================================================
# Validates Phase 0 exit criteria for cross-cloud (Azure ↔ GCP) connectivity:
#   1. VPN tunnel status (Azure side)
#   2. VPN tunnel status (GCP side)
#   3. TCP connectivity to budget-backend:8443 from GCE
#   4. TCP connectivity to SPIRE server:8081 from GCE
#   5. TLS handshake to budget-backend:8443 from GCE
#   6. Existing Azure agent regression check
#
# Requires SSH access to the GCE VM. Tests 3–5 run remotely via SSH.
# No special tools needed beyond standard Linux utilities (nc, openssl).
#
# Usage:
#   GCE_VM_IP=34.x.x.x BUDGET_BACKEND_PRIVATE_IP=10.200.x.x \
#     SPIRE_SERVER_PRIVATE_IP=10.200.x.x ./scripts/test-crosscloud-connectivity.sh
#
# Configuration (env vars):
#   GCE_VM_IP                  — required, public IP of GCE VM (SSH target)
#   GCE_VM_USER                — default: $(whoami)
#   BUDGET_BACKEND_PRIVATE_IP  — required, private IP of budget-backend in VNet
#   SPIRE_SERVER_PRIVATE_IP    — required, private IP of SPIRE server VM
#   GCP_PROJECT                — optional, for gcloud tunnel status check
#   GCP_REGION                 — default: us-west1
# =============================================================================
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────

GCE_IP="${GCE_VM_IP:-}"
GCE_USER="${GCE_VM_USER:-$(whoami)}"
BACKEND_IP="${BUDGET_BACKEND_PRIVATE_IP:-}"
SPIRE_IP="${SPIRE_SERVER_PRIVATE_IP:-}"
PROJECT="${GCP_PROJECT:-}"
REGION="${GCP_REGION:-us-west1}"

# Validate required variables
missing=()
[[ -z "$GCE_IP" ]] && missing+=("GCE_VM_IP")
[[ -z "$BACKEND_IP" ]] && missing+=("BUDGET_BACKEND_PRIVATE_IP")
[[ -z "$SPIRE_IP" ]] && missing+=("SPIRE_SERVER_PRIVATE_IP")

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "❌ ERROR: Missing required environment variables: ${missing[*]}" >&2
    echo "" >&2
    echo "   Usage:" >&2
    echo "     GCE_VM_IP=34.x.x.x BUDGET_BACKEND_PRIVATE_IP=10.200.x.x \\" >&2
    echo "       SPIRE_SERVER_PRIVATE_IP=10.200.x.x ./scripts/test-crosscloud-connectivity.sh" >&2
    exit 1
fi

validate_ip() {
    local ip="$1" name="$2"
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "❌ ERROR: ${name} ('${ip}') is not a valid IPv4 address" >&2
        exit 1
    fi
}

validate_ip "$GCE_IP" "GCE_VM_IP"
validate_ip "$BACKEND_IP" "BUDGET_BACKEND_PRIVATE_IP"
validate_ip "$SPIRE_IP" "SPIRE_SERVER_PRIVATE_IP"

# ─── Test tracking ───────────────────────────────────────────────────────────

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
RESULTS=()

pass_test() {
    local num="$1" name="$2" detail="$3"
    PASS_COUNT=$((PASS_COUNT + 1))
    RESULTS+=("  [PASS] Test ${num}: ${name} — ${detail}")
}

fail_test() {
    local num="$1" name="$2" detail="$3"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    RESULTS+=("  [FAIL] Test ${num}: ${name} — ${detail}")
}

skip_test() {
    local num="$1" name="$2" detail="$3"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    RESULTS+=("  [SKIP] Test ${num}: ${name} — ${detail}")
}

# SSH helper — runs a command on the GCE VM
gce_ssh() {
    ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o LogLevel=ERROR \
        "${GCE_USER}@${GCE_IP}" "$@"
}

# ─── Banner ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Phase 0: Cross-Cloud Connectivity Validation"
echo "============================================================"
echo ""
echo "  GCE VM:          ${GCE_USER}@${GCE_IP}"
echo "  Budget Backend:  ${BACKEND_IP}:8443"
echo "  SPIRE Server:    ${SPIRE_IP}:8081"
echo "  GCP Project:     ${PROJECT:-<not set>}"
echo "  GCP Region:      ${REGION}"
echo ""

# ─── Pre-flight: SSH access ─────────────────────────────────────────────────

echo "🔍 Pre-flight: checking SSH access to GCE VM..."

if ! gce_ssh "echo ok" &>/dev/null; then
    echo "❌ Cannot SSH to ${GCE_USER}@${GCE_IP}. Check:" >&2
    echo "   - GCE VM is running" >&2
    echo "   - SSH key is authorized" >&2
    echo "   - Firewall allows TCP 22" >&2
    exit 1
fi
echo "✅ SSH access confirmed"

echo "🔍 Checking remote tools on GCE VM..."
if missing_tools=$(gce_ssh "for cmd in nc openssl; do command -v \$cmd >/dev/null 2>&1 || echo \$cmd; done" 2>/dev/null); then
    if [[ -n "$missing_tools" ]]; then
        echo "⚠️  Missing on GCE VM: ${missing_tools}" >&2
        echo "   Install with: gce_ssh 'sudo apt-get install -y netcat-openbsd openssl'" >&2
    fi
fi

echo ""

# ─── Test 1: Azure VPN tunnel status ────────────────────────────────────────

echo "🔍 Test 1/6 — Azure VPN tunnel status"

if command -v az &>/dev/null; then
    # Discover VPN connection name from the resource group
    vpn_status=$(az network vpn-connection list \
        --query "[0].connectionStatus" -o tsv 2>/dev/null || echo "")

    if [[ -z "$vpn_status" ]]; then
        skip_test 1 "Azure VPN tunnel status" "no VPN connections found or az query failed"
    elif [[ "$vpn_status" == "Connected" ]]; then
        pass_test 1 "Azure VPN tunnel status" "Connected"
    else
        fail_test 1 "Azure VPN tunnel status" "status is '${vpn_status}' (expected Connected)"
    fi
else
    skip_test 1 "Azure VPN tunnel status" "az CLI not available"
fi

# ─── Test 2: GCP VPN tunnel status ──────────────────────────────────────────

echo "🔍 Test 2/6 — GCP VPN tunnel status"

if command -v gcloud &>/dev/null && [[ -n "$PROJECT" ]]; then
    # Find the first VPN tunnel in the project
    tunnel_name=$(gcloud compute vpn-tunnels list \
        --project="$PROJECT" \
        --region="$REGION" \
        --format="value(name)" \
        --limit=1 2>/dev/null || echo "")

    if [[ -z "$tunnel_name" ]]; then
        skip_test 2 "GCP VPN tunnel status" "no VPN tunnels found in ${PROJECT}/${REGION}"
    else
        tunnel_status=$(gcloud compute vpn-tunnels describe "$tunnel_name" \
            --project="$PROJECT" \
            --region="$REGION" \
            --format="value(status)" 2>/dev/null || echo "")

        if [[ "$tunnel_status" == "ESTABLISHED" ]]; then
            pass_test 2 "GCP VPN tunnel status" "ESTABLISHED"
        else
            fail_test 2 "GCP VPN tunnel status" "status is '${tunnel_status}' (expected ESTABLISHED)"
        fi
    fi
else
    if ! command -v gcloud &>/dev/null; then
        skip_test 2 "GCP VPN tunnel status" "gcloud CLI not available"
    else
        skip_test 2 "GCP VPN tunnel status" "GCP_PROJECT not set"
    fi
fi

# ─── Test 3: TCP to budget-backend:8443 from GCE ────────────────────────────

echo "🔍 Test 3/6 — TCP connectivity to budget-backend:8443 from GCE"

tcp_backend=$(gce_ssh "nc -z -w5 ${BACKEND_IP} 8443 && echo PASS || echo FAIL" 2>/dev/null || echo "FAIL")

if [[ "$tcp_backend" == *"PASS"* ]]; then
    pass_test 3 "TCP to budget-backend:8443" "reachable"
else
    fail_test 3 "TCP to budget-backend:8443" "connection refused or timeout"
fi

# ─── Test 4: TCP to SPIRE server:8081 from GCE ──────────────────────────────

echo "🔍 Test 4/6 — TCP connectivity to SPIRE server:8081 from GCE"

tcp_spire=$(gce_ssh "nc -z -w5 ${SPIRE_IP} 8081 && echo PASS || echo FAIL" 2>/dev/null || echo "FAIL")

if [[ "$tcp_spire" == *"PASS"* ]]; then
    pass_test 4 "TCP to SPIRE server:8081" "reachable"
else
    fail_test 4 "TCP to SPIRE server:8081" "connection refused or timeout"
fi

# ─── Test 5: TLS handshake to budget-backend:8443 from GCE ──────────────────

echo "🔍 Test 5/6 — TLS handshake to budget-backend:8443 from GCE"

tls_result=$(gce_ssh \
    "echo | timeout 5 openssl s_client -connect ${BACKEND_IP}:8443 2>&1 | grep -q 'SSL handshake has read' && echo PASS || echo FAIL" \
    2>/dev/null || echo "FAIL")

if [[ "$tls_result" == *"PASS"* ]]; then
    pass_test 5 "TLS handshake to budget-backend:8443" "connected"
else
    fail_test 5 "TLS handshake to budget-backend:8443" "no TLS response or connection refused"
fi

# ─── Test 6: Existing Azure agent tests ─────────────────────────────────────

echo "🔍 Test 6/6 — Existing Azure agent tests"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/test_agents.py" ]]; then
    skip_test 6 "Azure agent tests" "test_agents.py not found"
else
    agent_output=$(python3 "${SCRIPT_DIR}/test_agents.py" 2>&1) && agent_rc=0 || agent_rc=$?
    if [[ $agent_rc -eq 0 ]]; then
        pass_test 6 "Azure agent tests" "all scenarios passed"
    else
        fail_test 6 "Azure agent tests" "one or more scenarios failed"
        echo ""
        echo "--- test_agents.py output ---"
        echo "$agent_output" | tail -20
        echo "---"
    fi
fi

# ─── Summary ─────────────────────────────────────────────────────────────────

TESTED=$((PASS_COUNT + FAIL_COUNT))

echo ""
echo "============================================================"
echo "  Phase 0: Cross-Cloud Connectivity Validation"
echo "============================================================"
echo ""

for result in "${RESULTS[@]}"; do
    echo "$result"
done

echo ""
echo "  Result: ${PASS_COUNT}/${TESTED} passed, ${FAIL_COUNT} failed, ${SKIP_COUNT} skipped"
echo "============================================================"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
