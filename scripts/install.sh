#!/bin/bash

set -euo pipefail

# Function to print an error message and exit
error_exit() {
  echo "Error: $1" >&2
  exit 1
}

# Default WOPS_VERSION to the latest if not provided
WOPS_VERSION=${WOPS_VERSION:-"latest"}

# Determine the OS and set paths accordingly
case "$(uname)" in
  "Linux")
    CONFIG_DIR="$HOME/.config/wazuh-cert-oauth2-client"
    BIN_DIR="$HOME/.local/bin"
    OS="linux"
    ;;
  "Darwin")
    CONFIG_DIR="$HOME/Library/Application Support/wazuh-cert-oauth2-client"
    BIN_DIR="/usr/local/bin"
    OS="macos"
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

# URL for downloading the zip file
BASE_URL="https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
ZIP_FILE="wazuh-cert-oauth2-client-${ARCH}-${OS}.zip"
URL="$BASE_URL/$ZIP_FILE"

# Download the zip file
echo "Downloading $ZIP_FILE from $URL..."
curl -L -o "/tmp/$ZIP_FILE" "$URL" || error_exit "Failed to download $ZIP_FILE"

# Unzip the file
echo "Unzipping $ZIP_FILE..."
unzip -o "/tmp/$ZIP_FILE" -d "/tmp/wazuh-cert-oauth2-client" || error_exit "Failed to unzip $ZIP_FILE"

# Move the binary to the BIN_DIR
echo "Installing binary to $BIN_DIR..."
mkdir -p "$BIN_DIR"
mv "/tmp/wazuh-cert-oauth2-client/wazuh-cert-oauth2-client" "$BIN_DIR/" || error_exit "Failed to move binary to $BIN_DIR"
chmod +x "$BIN_DIR/wazuh-cert-oauth2-client" || error_exit "Failed to set executable permissions on the binary"

# Cleanup
rm -rf "/tmp/$ZIP_FILE" "/tmp/wazuh-cert-oauth2-client"

echo "Installation complete! You can now use 'wazuh-cert-oauth2-client' from your terminal."
