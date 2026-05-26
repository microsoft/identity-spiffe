#!/bin/bash
# =============================================================================
# Update SSH Key on SPIRE Server VM
# =============================================================================
# Pushes your local SSH public key to the SPIRE Server VM so you can deploy
# from a different machine. Uses az vm user update (Azure RBAC auth) to add
# the key without needing existing SSH access.
#
# Usage:
#   ./scripts/update-ssh-key.sh                    # auto-detect key
#   ./scripts/update-ssh-key.sh ~/.ssh/id_rsa.pub  # specific key file
#
# After running, deploy.sh will use SSH for all VM operations from this machine.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/lib/deploy-config.sh"
source "${SCRIPT_DIR}/lib/azure-helpers.sh"

AZD_VALUES=$(azd_env_load)
RG=$(azd_env_get_from_blob "$AZD_VALUES" "AZURE_RESOURCE_GROUP")
VM_NAME="${SPIRE_SERVER_VM_NAME}"

if [ -z "$RG" ]; then
    echo "ERROR: No active azd environment found. Run deploy.sh first." >&2
    exit 1
fi

# Resolve SSH public key
KEY_FILE="${1:-}"
if [ -z "$KEY_FILE" ]; then
    for candidate in ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub ~/.ssh/id_ecdsa.pub; do
        if [ -f "$candidate" ]; then
            KEY_FILE="$candidate"
            break
        fi
    done
fi

if [ -z "$KEY_FILE" ] || [ ! -f "$KEY_FILE" ]; then
    echo "ERROR: No SSH public key found." >&2
    echo "  Provide a path:  ./scripts/update-ssh-key.sh ~/.ssh/id_rsa.pub" >&2
    echo "  Or generate one: ssh-keygen -t ed25519" >&2
    exit 1
fi

SSH_PUB_KEY=$(cat "$KEY_FILE")
echo "🔑 Updating SSH key on SPIRE Server VM..."
echo "   Resource group: ${RG}"
echo "   VM:             ${VM_NAME}"
echo "   Key file:       ${KEY_FILE}"

# az vm user update replaces/adds the SSH key for the specified user.
# This uses Azure RBAC (your az login) — no existing SSH access needed.
az vm user update \
    --resource-group "$RG" \
    --name "$VM_NAME" \
    --username azureuser \
    --ssh-key-value "$SSH_PUB_KEY" \
    --no-wait

echo "✅ SSH key updated. You can now deploy from this machine."
echo ""

# Also update azd env so future provisions use this key
export adminSshPublicKey="$SSH_PUB_KEY"
azd_env_set_repo "adminSshPublicKey" "$SSH_PUB_KEY"
echo "   Key also saved to azd env for future provisions."

# Quick verification
SPIRE_FQDN=$(azd_env_get_from_blob "$AZD_VALUES" "SPIRE_SERVER_FQDN")
if [ -n "$SPIRE_FQDN" ]; then
    echo ""
    echo "   Verify SSH access (may take ~30s for key to propagate):"
    echo "   ssh azureuser@${SPIRE_FQDN} 'echo SSH OK'"
fi
