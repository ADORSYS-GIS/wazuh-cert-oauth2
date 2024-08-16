#!/bin/sh

# Set shell options based on shell type
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Default log level and application details
LOG_LEVEL=${LOG_LEVEL:-INFO}
APP_NAME=${APP_NAME:-"wazuh-cert-oauth2-client"}
WOPS_VERSION=${WOPS_VERSION:-"0.1.5"}
OSSEC_CONF_PATH=${OSSEC_CONF_PATH:-"/var/ossec/etc/ossec.conf"}
USER="root"
GROUP="wazuh"

# Function for logging with timestamp
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    if [ "$LEVEL" = "ERROR" ] || { [ "$LEVEL" = "WARNING" ] && [ "$LOG_LEVEL" != "ERROR" ]; } || { [ "$LEVEL" = "INFO" ] && [ "$LOG_LEVEL" = "INFO" ]; }; then
        echo "$TIMESTAMP [$LEVEL] $MESSAGE"
    fi
}

# Print step details
print_step() {
    local step="$1"
    local message="$2"
    log INFO "------ Step $step: $message ------"
}

# Exit script with an error message
error_exit() {
    log ERROR "$1"
    exit 1
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Ensure root privileges, either directly or through sudo
maybe_sudo() {
    if [ "$(id -u)" -ne 0 ]; then
        if command_exists sudo; then
            sudo "$@"
        else
            log ERROR "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

# Create user and group if they do not exist
ensure_user_group() {
    log INFO "Ensuring that the $USER:$GROUP user and group exist..."

    if ! id -u "$USER" >/dev/null 2>&1; then
        log INFO "Creating user $USER..."
        if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo useradd -m "$USER"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo adduser -D "$USER"
        else
            log ERROR "Unsupported OS for creating user."
            exit 1
        fi
    fi

    if ! getent group "$GROUP" >/dev/null 2>&1; then
        log INFO "Creating group $GROUP..."
        if [ "$(uname -o)" = "GNU/Linux" ] && command -v groupadd >/dev/null 2>&1; then
            maybe_sudo groupadd "$GROUP"
        elif [ "$(which apk)" = "/sbin/apk" ]; then
            maybe_sudo addgroup "$GROUP"
        else
            log ERROR "Unsupported OS for creating group."
            exit 1
        fi
    fi
}

# Change ownership of a file or directory
change_owner() {
    local path="$1"
    ensure_user_group
    maybe_sudo chown "$USER:$GROUP" "$path"
}

# Function to configure agent certificates in ossec.conf
configure_agent_certificates() {
    log INFO "Configuring agent certificates..."

    # Check and insert agent certificate path if it doesn't exist
    if ! maybe_sudo grep -q '<agent_certificate_path>etc/sslagent.cert</agent_certificate_path>' "$OSSEC_CONF_PATH"; then
        maybe_sudo sed -i '/<agent_name=*/ a\
        <agent_certificate_path>etc/sslagent.cert</agent_certificate_path>' "$OSSEC_CONF_PATH" || {
            log ERROR "Error occurred during Wazuh agent certificate configuration."
            exit 1
        }
    fi

    # Check and insert agent key path if it doesn't exist
    if ! maybe_sudo grep -q '<agent_key_path>etc/sslagent.key</agent_key_path>' "$OSSEC_CONF_PATH"; then
        maybe_sudo sed -i '/<agent_name=*/ a\
        <agent_key_path>etc/sslagent.key</agent_key_path>' "$OSSEC_CONF_PATH" || {
            log ERROR "Error occurred during Wazuh agent key configuration."
            exit 1
        }
    fi

    log INFO "Agent certificates path configured successfully."
}

# Determine the OS and architecture
case "$(uname)" in
    "Linux") OS="unknown-linux-gnu"; BIN_DIR="$HOME/.local/bin" ;;
    "Darwin") OS="apple-darwin"; BIN_DIR="/usr/local/bin" ;;
    *) error_exit "Unsupported operating system: $(uname)" ;;
esac

ARCH=$(uname -m)
case "$ARCH" in
    "x86_64") ARCH="x86_64" ;;
    "arm64"|"aarch64") ARCH="aarch64" ;;
    *) error_exit "Unsupported architecture: $ARCH" ;;
esac

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
change_owner "$BIN_DIR/$APP_NAME"
maybe_sudo chmod 750 "$BIN_DIR/$APP_NAME" || error_exit "Failed to set executable permissions on the binary"

# Step 3: Update shell configuration
print_step 3 "Updating shell configuration..."

# Determine the appropriate shell configuration file
if command_exists zsh; then
    SHELL_RC="$HOME/.zshrc"
else
    SHELL_RC="$HOME/.bashrc"
fi

# Add binary directory to PATH and set RUST_LOG environment variable
echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
if ! grep -q "export PATH=\"$BIN_DIR:\$PATH\"" "$SHELL_RC"; then
    log INFO "Updated PATH in $SHELL_RC"
fi

echo "export RUST_LOG=info" >> "$SHELL_RC"
if ! grep -q "export RUST_LOG=info" "$SHELL_RC"; then
    log INFO "Set RUST_LOG=info in $SHELL_RC"
fi

# Source the shell configuration in interactive mode
if command_exists source && ! source "$SHELL_RC"; then
    log INFO "Please run 'source $SHELL_RC' or open a new terminal to apply changes."
fi

# Step 4: Configure agent certificates
print_step 4 "Configuring Wazuh agent certificates..."

## If OSSEC_CONF_PATH exist, then configure agent
if [ -f "$OSSEC_CONF_PATH" ]; then
    configure_agent_certificates
else
    log WARNING "Wazuh agent configuration file not found at $OSSEC_CONF_PATH. Skipping agent certificate configuration."
fi

log INFO "Installation and configuration complete! You can now use '$APP_NAME' from your terminal."
