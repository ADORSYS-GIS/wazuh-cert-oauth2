#!/bin/bash

# Set the app configuration folder based on the OS
case "$OSTYPE" in
  linux-gnu*)
    CONFIG_DIR="$HOME/.config/wazuh-cert-oauth2-client"
    OS="linux"
    ;;
  darwin*)
    CONFIG_DIR="$HOME/Library/Application Support/wazuh-cert-oauth2-client"
    OS="macos"
    ;;
  msys*|cygwin*|win32)
    CONFIG_DIR="$APPDATA\\wazuh-cert-oauth2-client"
    OS="windows"
    ;;
  *)
    echo "Unsupported OS: $OSTYPE"
    exit 1
    ;;
esac

# Set the architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)
    ARCH="x86_64"
    ;;
  arm64|aarch64)
    ARCH="aarch64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

WOPS_VERSION="0.1.1"  # Replace with your actual version
# URL for downloading the zip file
BASE_URL="https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"  # Replace with your actual URL
ZIP_FILE="wazuh-cert-oauth2-client-${ARCH}-${OS}.zip"
URL="$BASE_URL/$ZIP_FILE"

# Download the zip file
echo "Downloading $ZIP_FILE from $URL..."
curl -L -o "/tmp/$ZIP_FILE" "$URL"
if [ $? -ne 0 ]; then
  echo "Failed to download $ZIP_FILE"
  exit 1
fi

# Unzip the file
echo "Unzipping $ZIP_FILE..."
unzip -o "/tmp/$ZIP_FILE" -d "/tmp/wazuh-cert-oauth2-client"
if [ $? -ne 0 ]; then
  echo "Failed to unzip $ZIP_FILE"
  exit 1
fi

# Move the binary to the configuration folder
echo "Installing binary to $CONFIG_DIR..."
mkdir -p "$CONFIG_DIR"
if [ "$OS" == "windows" ]; then
  mv "/tmp/wazuh-cert-oauth2-client/wazuh-cert-oauth2-client.exe" "$CONFIG_DIR/"
else
  mv "/tmp/wazuh-cert-oauth2-client/wazuh-cert-oauth2-client" "$CONFIG_DIR/"
  chmod +x "$CONFIG_DIR/wazuh-cert-oauth2-client"
fi

# Cleanup
rm -rf "/tmp/$ZIP_FILE" "/tmp/wazuh-cert-oauth2-client"

echo "Installation complete!"
