#!/bin/sh

# Set shell options based on shell type
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Global variables with defaults
APP_NAME=${APP_NAME:-"wazuh-cert-oauth2-client"}
WOPS_VERSION=${WOPS_VERSION:-"0.4.2"}
WAZUH_CERT_OAUTH2_REPO_REF=${WAZUH_CERT_OAUTH2_REPO_REF:-"refs/tags/v${WOPS_VERSION}"}
WAZUH_CERT_OAUTH2_REPO_URL="https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/${WAZUH_CERT_OAUTH2_REPO_REF}"

# Create a secure temporary directory for utilities
UTILS_TMP=$(mktemp -d)
trap 'rm -rf "$UTILS_TMP"' EXIT
if ! curl "${WAZUH_CERT_OAUTH2_REPO_URL}/scripts/shared/utils.sh" -o "$UTILS_TMP/utils.sh"; then
    echo "Failed to download utils.sh"
    exit 1
fi

# Function to calculate SHA256 (cross-platform bootstrap)
calculate_sha256_bootstrap() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# Download checksums and verify utils.sh integrity BEFORE sourcing it
if ! curl "${WAZUH_CERT_OAUTH2_REPO_URL}/checksums.sha256" -o "$UTILS_TMP/checksums.sha256"; then
    echo "Failed to download checksums.sha256"
    exit 1
fi


EXPECTED_HASH=$(grep "scripts/shared/utils.sh" "$UTILS_TMP/checksums.sha256" | awk '{print $1}')
ACTUAL_HASH=$(calculate_sha256_bootstrap "$UTILS_TMP/utils.sh")

if [ -z "$EXPECTED_HASH" ] || [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
    echo "Error: Checksum verification failed for utils.sh" >&2
    echo "Expected hash: $EXPECTED_HASH" >&2
    echo "Actual hash: $ACTUAL_HASH" >&2
    exit 1
fi

# Source utils.sh only after verification
. "$UTILS_TMP/utils.sh"

# OS guard early in the script
if [ "$(uname -s)" != "Darwin" ]; then
    printf "%s\n" "[ERROR] This uninstallation script is intended for macOS systems. Please use the appropriate script for your operating system." >&2
    exit 1
fi


# Uninstall binary
uninstall_binary() {
    info_message "Removing binary from $BIN_DIR..."
    if maybe_sudo [ -f "$BIN_DIR/$APP_NAME" ]; then
        maybe_sudo rm -f "$BIN_DIR/$APP_NAME" || error_message "Failed to remove binary"
        info_message "Binary removed successfully."
    else
        warn_message "Binary not found in $BIN_DIR. Skipping."
    fi
}

# Clean up configuration
cleanup_configuration() {
    if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
        info_message "Removing agent certificate and key configurations from $OSSEC_CONF_PATH..."
        sed_alternative -i '/<agent_certificate_path>.*<\/agent_certificate_path>/d' "$OSSEC_CONF_PATH"
        sed_alternative -i '/<agent_key_path>.*<\/agent_key_path>/d' "$OSSEC_CONF_PATH"
        info_message "Configuration cleaned successfully."
    else
        warn_message "Configuration file not found at $OSSEC_CONF_PATH. Skipping configuration cleanup."
    fi
}

# Main script execution
uninstall_binary
cleanup_configuration

success_message "Uninstallation of $APP_NAME completed successfully."
