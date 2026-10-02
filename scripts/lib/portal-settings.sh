#!/usr/bin/env bash

# Initialize environment-owned settings without overwriting operator choices.
ensure_portal_settings_blob() {
    local account="$1" container="$2" blob="$3" defaults="$4"
    az storage container create --account-name "$account" --name "$container" \
        --auth-mode key --only-show-errors --output none || return 1
    local exists
    exists=$(az storage blob exists --account-name "$account" \
        --container-name "$container" --name "$blob" \
        --auth-mode key --only-show-errors --query exists -o tsv) || return 1
    case "$exists" in
        true)
            echo "   Preserving existing portal settings: ${container}/${blob}"
            ;;
        false)
            az storage blob upload --account-name "$account" \
                --container-name "$container" --name "$blob" --file "$defaults" \
                --auth-mode key --overwrite false --only-show-errors --output none || return 1
            echo "   Initialized portal settings: ${container}/${blob}"
            ;;
        *)
            echo "ERROR: Could not determine whether portal settings exist." >&2
            return 1
            ;;
    esac
}
