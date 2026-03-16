#!/bin/bash

# Set shell options based on shell type
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi


COMMON="/tmp/common.sh"

if [[ ! -f "$COMMON" ]]; then
  curl -fsSL https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/refs/heads/refactor/split-linux-macos-scripts/scripts/shared/common.sh -o "$COMMON"
fi

source "$COMMON"

# Default application details
APP_NAME=${APP_NAME:-"wazuh-cert-oauth2-client"}
BIN_DIR="/var/ossec/bin"
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"

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
