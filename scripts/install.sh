#!/bin/bash

set -euo pipefail

# Function to print an error message and exit
error_exit() {
  echo "Error: $1" >&2
  exit 1
}

# Default WOPS_VERSION to the latest if not provided
WOPS_VERSION=${WOPS_VERSION:-"0.1.5"}

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
BIN_NAME="wazuh-cert-oauth2-client-${ARCH}-${OS}"

# URL for downloading the binary
BASE_URL="https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
URL="$BASE_URL/$BIN_NAME"

# Download the binary file
echo "Downloading $BIN_NAME from $URL..."
curl -L -o "/tmp/$BIN_NAME" "$URL" || error_exit "Failed to download $BIN_NAME"

# Move the binary to the BIN_DIR
echo "Installing binary to $BIN_DIR..."
mkdir -p "$BIN_DIR"
mv "/tmp/$BIN_NAME" "$BIN_DIR/wazuh-cert-oauth2-client" || error_exit "Failed to move binary to $BIN_DIR"
chmod +x "$BIN_DIR/wazuh-cert-oauth2-client" || error_exit "Failed to set executable permissions on the binary"

# Cleanup
rm -rf "/tmp/$BIN_NAME"

echo "Installation complete! You can now use 'wazuh-cert-oauth2-client' from your terminal."
