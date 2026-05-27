#!/bin/bash

SCRIPT_DIR_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT_LIB="$(cd "${SCRIPT_DIR_LIB}/../.." && pwd)"

# Validate REPO_ROOT_LIB. If path-with-spaces resolution failed, fall back to
# finding the repo root by looking for azure.yaml upward from the current directory.
if [ ! -f "${REPO_ROOT_LIB}/azure.yaml" ]; then
    _candidate="$(pwd)"
    while [ "$_candidate" != "/" ]; do
        if [ -f "${_candidate}/azure.yaml" ]; then
            REPO_ROOT_LIB="$_candidate"
            break
        fi
        _candidate="$(dirname "$_candidate")"
    done
    unset _candidate
fi

azd_env_load() {
    (
        cd "$REPO_ROOT_LIB" &&
        azd env get-values 2>/dev/null
    ) || true
}

azd_env_get_from_blob() {
    local blob="$1"
    local key="$2"
    echo "$blob" | grep -E "^${key}=" | cut -d'=' -f2- | tr -d '"' || true
}

azd_env_set_repo() {
    local key="$1"
    local value="$2"
    (
        cd "$REPO_ROOT_LIB" &&
        azd env set "$key" "$value" 2>/dev/null
    ) || true
}

require_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd" >&2
        return 1
    fi
}

is_tty_stdin() {
    [ -t 0 ]
}

# ---------------------------------------------------------------------------
# SSH-based VM command execution (replaces azure_vm_run)
# ---------------------------------------------------------------------------
# Direct SSH eliminates the entire class of az vm run-command failures:
#   - Single-slot guest agent bottleneck
#   - ARM provisioningState/executionState race conditions
#   - Orphaned run-command resources that wedge the VM
#
# Usage: ssh_run <vm_ip> <script> [timeout_secs]
# ---------------------------------------------------------------------------
ssh_run() {
    local vm_ip="$1"
    local script="$2"
    local timeout_secs="${3:-120}"

    # macOS doesn't have 'timeout' — use gtimeout (brew install coreutils) if
    # available, otherwise rely on SSH's own keepalive/connect timeouts.
    local timeout_cmd=""
    if command -v gtimeout >/dev/null 2>&1; then
        timeout_cmd="gtimeout ${timeout_secs}"
    elif command -v timeout >/dev/null 2>&1; then
        timeout_cmd="timeout ${timeout_secs}"
    fi

    $timeout_cmd ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=3 \
        -o LogLevel=ERROR \
        "azureuser@${vm_ip}" \
        bash -s <<SSHEOF
${script}
SSHEOF

    return $?
}

# Legacy az vm run-command wrapper (kept for backward compatibility)
# DEPRECATED: Use ssh_run instead. This function has fatal reliability issues
# with the Azure guest agent on B1s VMs (see hard-won-learnings.md #17-20).
VM_RUN_COUNTER=0
VM_RUN_EPOCH=$(date +%s)

azure_vm_run() {
    local resource_group="$1"
    local vm_name="$2"
    local cmd_name="$3"
    local script="$4"
    local timeout_secs="${5:-300}"
    local output_var="${6:-}"

    VM_RUN_COUNTER=$((VM_RUN_COUNTER + 1))
    local run_name="deploy-${cmd_name}-${VM_RUN_EPOCH}-${VM_RUN_COUNTER}"
    local create_err
    create_err=$(az vm run-command create \
        --resource-group "$resource_group" \
        --vm-name "$vm_name" \
        --name "$run_name" \
        --timeout-in-seconds "$timeout_secs" \
        --script "$script" \
        --no-wait 2>&1) || {
        echo "[vm_run] Failed to create run-command '$run_name': $create_err" >&2
        return 1
    }

    local state="Running"
    local poll_count=0
    local max_polls=$(( (timeout_secs + 30) / 5 ))
    local not_found_count=0
    while [ "$state" = "Running" ] || [ "$state" = "Pending" ]; do
        sleep 5
        poll_count=$((poll_count + 1))
        state=$(az vm run-command show \
            --resource-group "$resource_group" \
            --vm-name "$vm_name" \
            --name "$run_name" \
            --instance-view \
            --query "instanceView.executionState" -o tsv 2>/dev/null)
        if [ -z "$state" ]; then
            not_found_count=$((not_found_count + 1))
            if [ "$not_found_count" -ge 3 ]; then
                echo "[vm_run] Run-command '$run_name' not found after $not_found_count polls" >&2
                return 1
            fi
            state="Pending"
        else
            not_found_count=0
        fi
        if [ "$poll_count" -ge "$max_polls" ]; then
            echo "[vm_run] Timed out waiting for '$cmd_name' after ${timeout_secs}s" >&2
            az vm run-command delete \
                --resource-group "$resource_group" \
                --vm-name "$vm_name" \
                --name "$run_name" \
                --yes --no-wait 2>/dev/null || true
            sleep 10
            return 1
        fi
    done

    local output
    output=$(az vm run-command show \
        --resource-group "$resource_group" \
        --vm-name "$vm_name" \
        --name "$run_name" \
        --instance-view \
        --query "instanceView.output" -o tsv 2>/dev/null || true)

    # Wait for ARM provisioningState to reach a terminal state before deleting.
    # The executionState (guest-level) can show "Succeeded" while the ARM resource
    # is still "Running" or "Provisioning". Deleting in that window wedges the
    # guest agent and blocks ALL subsequent VM operations (run-commands, password
    # resets, stop/restart).
    local prov_state="Running"
    local prov_polls=0
    while [ "$prov_state" = "Running" ] || [ "$prov_state" = "Creating" ] || [ "$prov_state" = "Updating" ]; do
        prov_state=$(az vm run-command show \
            --resource-group "$resource_group" \
            --vm-name "$vm_name" \
            --name "$run_name" \
            --query "provisioningState" -o tsv 2>/dev/null || echo "Unknown")
        prov_polls=$((prov_polls + 1))
        if [ "$prov_polls" -ge 24 ]; then
            echo "[vm_run] provisioningState still '$prov_state' after 2min, deleting anyway" >&2
            break
        fi
        [ "$prov_state" = "Succeeded" ] || [ "$prov_state" = "Failed" ] || [ "$prov_state" = "Canceled" ] && break
        sleep 5
    done

    # Fire-and-forget delete: --no-wait prevents blocking on the guest agent's
    # slow RunCommandHandler extension cleanup. Without --no-wait, the delete
    # call itself hangs for 30-60s on B1s VMs, and deploy.sh appears stuck.
    az vm run-command delete \
        --resource-group "$resource_group" \
        --vm-name "$vm_name" \
        --name "$run_name" \
        --yes --no-wait 2>/dev/null || true

    # Cooldown: the guest agent (waagent) processes operations serially on B1s
    # VMs. Without a pause after delete, the next create arrives while the agent
    # is still cleaning up the RunCommandHandler extension, causing empty output,
    # silent failures, or a permanently wedged agent queue.
    # See hard-won-learnings #20 and the 2026-04-03 isp-crosscloud deploy stall.
    sleep 10

    if [ "$state" != "Succeeded" ]; then
        echo "[vm_run] Command '$cmd_name' finished with state: $state" >&2
        echo "$output"
        return 1
    fi

    if [ -n "$output_var" ]; then
        printf -v "$output_var" '%s' "$output"
    else
        echo "$output"
    fi
}
