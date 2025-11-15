#!/bin/sh

# Set shell options based on shell type
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

# Default application details
APP_NAME=${APP_NAME:-"wazuh-cert-oauth2-client"}
BIN_DIR=""
OSSEC_CONF_PATH=""
USER="root"
GROUP="wazuh"

# Determine the OS and architecture
case "$(uname)" in
    "Linux") OS="unknown-linux-musl"; BIN_DIR="/var/ossec/bin"; OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf" ;;
    "Darwin") OS="apple-darwin"; BIN_DIR="/Library/Ossec/bin"; OSSEC_CONF_PATH="/Library/Ossec/etc/ossec.conf" ;;
    *) error_exit "Unsupported operating system: $(uname)" ;;
esac

# Define text formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NORMAL='\033[0m'

# Function for logging with timestamp
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    echo -e "${TIMESTAMP} ${LEVEL} ${MESSAGE}"
}

# Logging helpers
info_message() {
    log "${BLUE}${BOLD}[INFO]${NORMAL}" "$*"
}

warn_message() {
    log "${YELLOW}${BOLD}[WARNING]${NORMAL}" "$*"
}

error_message() {
    log "${RED}${BOLD}[ERROR]${NORMAL}" "$*"
}

success_message() {
    log "${GREEN}${BOLD}[SUCCESS]${NORMAL}" "$*"
}

# Exit script with an error message
error_exit() {
    error_message "$1"
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
            error_message "This script requires root privileges. Please run with sudo or as root."
            exit 1
        fi
    else
        "$@"
    fi
}

sed_alternative() {
    if command_exists gsed; then
        maybe_sudo gsed "$@"
    else
        maybe_sudo sed "$@"
    fi
}

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
