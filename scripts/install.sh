#!/bin/sh

# Check if we're running in bash; if not, adjust behavior
if [ -n "$BASH_VERSION" ]; then
    set -euo pipefail
else
    set -eu
fi

LOG_LEVEL=${LOG_LEVEL:-INFO}
APP_NAME="wazuh-cert-oauth2-client"
WOPS_VERSION=${WOPS_VERSION:-"0.1.5"}

# Function to handle logging
log() {
    local LEVEL="$1"
    shift
    local MESSAGE="$*"
    local TIMESTAMP
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

    if [ "$LEVEL" = "ERROR" ] || { [ "$LEVEL" = "WARNING" ] && [ "$LOG_LEVEL" != "ERROR" ]; } || { [ "$LEVEL" = "INFO" ] && [ "$LOG_LEVEL" = "INFO" ]; }; then
        echo "$TIMESTAMP [$LEVEL] $MESSAGE"
    fi
}

# Function to print steps
print_step() {
    local step="$1"
    local message="$2"
    log INFO "------ Step $step : $message ------"
}

# Function to print an error message and exit
error_exit() {
    log ERROR "$1"
    exit 1
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Determine the OS and set paths accordingly
case "$(uname)" in
    "Linux")
        OS="unknown-linux-gnu"
        BIN_DIR="$HOME/.local/bin"
        ;;
    "Darwin")
        OS="apple-darwin"
        BIN_DIR="/usr/local/bin"
        ;;
    *)
        error_exit "Unsupported operating system: $(uname)"
        ;;
esac

# Determine the architecture
ARCH=$(uname -m)
case "$ARCH" in
    "x86_64")
        ARCH="x86_64"
        ;;
    "arm64"|"aarch64")
        ARCH="aarch64"
        ;;
    *)
        error_exit "Unsupported architecture: $ARCH"
        ;;
esac

# Construct the full binary name
BIN_NAME="$APP_NAME-${ARCH}-${OS}"

# URL for downloading the binary
BASE_URL="https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
URL="$BASE_URL/$BIN_NAME"

# Create a temporary directory for the download
TEMP_DIR=$(mktemp -d) || error_exit "Failed to create temporary directory"

# Ensure the temporary directory is removed on exit
trap 'rm -rf "$TEMP_DIR"' EXIT

# Step 1: Download the binary file
print_step 1 "Downloading $BIN_NAME from $URL..."
curl -SL --progress-bar -o "$TEMP_DIR/$BIN_NAME" "$URL" || error_exit "Failed to download $BIN_NAME"

# Step 2: Install the binary
print_step 2 "Installing binary to $BIN_DIR..."
mkdir -p "$BIN_DIR" || error_exit "Failed to create directory $BIN_DIR"
mv "$TEMP_DIR/$BIN_NAME" "$BIN_DIR/$APP_NAME" || error_exit "Failed to move binary to $BIN_DIR"
chown root:wazuh "$BIN_DIR/$APP_NAME" || error_exit "Failed to set ownership on the binary"
chmod 750 "$BIN_DIR/$APP_NAME" || error_exit "Failed to set executable permissions on the binary"

# Step 3: Update shell configuration
print_step 3 "Updating shell configuration..."

# Determine whether to source .zshrc or .bashrc
if command_exists zsh; then
    SHELL_RC="$HOME/.zshrc"
else
    SHELL_RC="$HOME/.bashrc"
fi

# Update the PATH and set RUST_LOG in the appropriate shell configuration file
if ! grep -q "export PATH=\"$BIN_DIR:\$PATH\"" "$SHELL_RC"; then
    echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
    log INFO "Updated PATH in $SHELL_RC"
fi

# Set RUST_LOG environment variable
if ! grep -q "export RUST_LOG=info" "$SHELL_RC"; then
    echo "export RUST_LOG=info" >> "$SHELL_RC"
    log INFO "Set RUST_LOG=info in $SHELL_RC"
fi

# Source the shell configuration if in an interactive shell
if [[ $- == *i* ]]; then
    source "$SHELL_RC"
    log INFO "Shell configuration sourced successfully!"
else
    log INFO "Please run 'source $SHELL_RC' or open a new terminal to apply changes."
fi

log INFO "Installation complete! You can now use '$APP_NAME' from your terminal."
