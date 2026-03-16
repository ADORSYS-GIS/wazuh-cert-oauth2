#!/bin/sh

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

# Global variables with defaults
APP_NAME=${APP_NAME:-"wazuh-cert-oauth2-client"}
WOPS_VERSION=${WOPS_VERSION:-"0.4.2"}

# Linux-specific configuration
OS="unknown-linux-musl"
BIN_DIR=${BIN_DIR:-"/var/ossec/bin"}
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"

# Determine architecture
ARCH=$(uname -m)
case "$ARCH" in
    "x86_64") ARCH="x86_64" ;;
    "arm64"|"aarch64") ARCH="aarch64" ;;
    *) error_exit "Unsupported architecture: $ARCH" ;;
esac


check_enrollment() {
    if ! maybe_sudo grep -q "<enrollment>" "$OSSEC_CONF_PATH"; then
        ENROLLMENT_BLOCK="\t\t\n<enrollment>\n <agent_name></agent_name>\n </enrollment>\n"
        # Add the file_limit block after the <syscheck> line
        sed_alternative -i "/<\/server=*/ a\ $ENROLLMENT_BLOCK" "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during the addition of the enrollment block."
            exit 1
        }
        info_message "The enrollment block was added successfully."
    fi

    info_message "Configuring agent certificates..."

    # Check and insert agent certificate path if it doesn't exist
    if ! maybe_sudo grep -q '<agent_certificate_path>etc/sslagent.cert</agent_certificate_path>' "$OSSEC_CONF_PATH"; then
        sed_alternative -i '/<agent_name=*/ a\
        <agent_certificate_path>etc/sslagent.cert</agent_certificate_path>' "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during Wazuh agent certificate configuration."
            exit 1
        }
    fi

    # Check and insert agent key path if it doesn't exist
    if ! maybe_sudo grep -q '<agent_key_path>etc/sslagent.key</agent_key_path>' "$OSSEC_CONF_PATH"; then
        sed_alternative -i '/<agent_name=*/ a\
        <agent_key_path>etc/sslagent.key</agent_key_path>' "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during Wazuh agent key configuration."
            exit 1
        }
    fi

    # Check and delete auth pass path if it exists
    if maybe_sudo grep -q '<authorization_pass_path>etc/authd.pass</authorization_pass_path>' "$OSSEC_CONF_PATH"; then
        sed_alternative -i '/<authorization_pass_path>.*<\/authorization_pass_path>/d' "$OSSEC_CONF_PATH" || {
            error_message "Error occurred during Wazuh agent auth pass removal."
            exit 1
        }
    fi

    info_message "Agent certificates path configured successfully."
}

# Function to validate installation and configuration
validate_installation() {
    # Check if the binary exists and has the correct permissions
    if maybe_sudo [ -x "$BIN_DIR/$APP_NAME" ]; then
        info_message "Binary exists and is executable at $BIN_DIR/$APP_NAME."
    else
        warn_message "Binary is missing or not executable at $BIN_DIR/$APP_NAME."
    fi

    # Verify the configuration file contains the required updates
    if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
        if maybe_sudo grep -q "<enrollment>" "$OSSEC_CONF_PATH"; then
            info_message "Enrollment block is present in the configuration file."
        else
            warn_message "Enrollment block is missing in the configuration file."
        fi

        if maybe_sudo grep -q '<agent_certificate_path>etc/sslagent.cert</agent_certificate_path>' "$OSSEC_CONF_PATH"; then
            info_message "Agent certificate path is configured correctly."
        else
            warn_message "Agent certificate path is missing in the configuration file."
        fi

        if maybe_sudo grep -q '<agent_key_path>etc/sslagent.key</agent_key_path>' "$OSSEC_CONF_PATH"; then
            info_message "Agent key path is configured correctly."
        else
            warn_message "Agent key path is missing in the configuration file."
        fi

        if ! maybe_sudo grep -q '<authorization_pass_path>etc/authd.pass</authorization_pass_path>' "$OSSEC_CONF_PATH"; then
            info_message "Authorization pass path has been correctly removed."
        else
            warn_message "Authorization pass path is still present in the configuration file."
        fi
    else
        warn_message "Configuration file not found at $OSSEC_CONF_PATH."
    fi

    success_message "Validation of installation and configuration completed successfully."
}

# Construct binary name and URL for download
BIN_NAME="$APP_NAME-${ARCH}-${OS}"
BASE_URL="https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
URL="$BASE_URL/$BIN_NAME"

# Create a temporary directory and ensure it is cleaned up
TEMP_DIR=$(mktemp -d) || error_exit "Failed to create temporary directory"
trap 'rm -rf "$TEMP_DIR"' EXIT

# Step 1: Download the binary file
print_step 1 "Downloading $BIN_NAME from $URL..."
curl -SL --progress-bar -o "$TEMP_DIR/$BIN_NAME" "$URL" || error_exit "Failed to download $BIN_NAME"

# Step 2: Install the binary
print_step 2 "Installing binary to $BIN_DIR..."
maybe_sudo mkdir -p "$BIN_DIR" || error_exit "Failed to create directory $BIN_DIR"
maybe_sudo mv "$TEMP_DIR/$BIN_NAME" "$BIN_DIR/$APP_NAME" || error_exit "Failed to move binary to $BIN_DIR"
maybe_sudo chmod 750 "$BIN_DIR/$APP_NAME" || error_exit "Failed to set executable permissions on the binary"

# Step 3: Configure agent certificates
print_step 3 "Configuring Wazuh agent certificates..."

## If OSSEC_CONF_PATH exist, then configure agent
if maybe_sudo [ -f "$OSSEC_CONF_PATH" ]; then
    check_enrollment
else
    warn_message "Wazuh agent configuration file not found at $OSSEC_CONF_PATH. Skipping agent certificate configuration."
fi

# Step 4: Validate installation and configuration
print_step 4 "Validating installation and configuration..."
validate_installation

success_message "Installation and configuration complete! You can now use '$BIN_DIR/$APP_NAME' from your terminal."
info_message "Run \n\n\t${GREEN}${BOLD}sudo $BIN_DIR/$APP_NAME o-auth2${NORMAL}\n\n to start configuring. If you don't have sudo on your machine, you can run the command without sudo."
