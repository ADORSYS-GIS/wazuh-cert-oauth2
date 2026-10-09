# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default log level and application details
$APP_NAME = if ($null -ne $env:APP_NAME) { $env:APP_NAME } else { "wazuh-cert-oauth2-client" }
$DEFAULT_WOPS_VERSION = "0.5.0"
$WOPS_VERSION = if ($null -ne $env:WOPS_VERSION) { $env:WOPS_VERSION } else { $DEFAULT_WOPS_VERSION }
$OSSEC_CONF_PATH = if ($null -ne $env:OSSEC_CONF_PATH) { $env:OSSEC_CONF_PATH } else { "C:\Program Files (x86)\ossec-agent\ossec.conf" }

# Variables
if (-not $env:WAZUH_CERT_OAUTH2_REPO_REF) {
    $env:WAZUH_CERT_OAUTH2_REPO_REF = "refs/tags/v$WOPS_VERSION"
}
$WAZUH_CERT_OAUTH2_REPO_REF = $env:WAZUH_CERT_OAUTH2_REPO_REF
$WAZUH_CERT_OAUTH2_REPO_URL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/$WAZUH_CERT_OAUTH2_REPO_REF"

# Download the shared utils and verify their checksum before sourcing them.
$UtilsTmp = Join-Path $env:TEMP "wazuh-cert-oauth2-utils-$(Get-Random)"
New-Item -ItemType Directory -Path $UtilsTmp -Force | Out-Null
$script:ChecksumsPath = Join-Path $UtilsTmp "checksums.sha256"
$UtilsPath = Join-Path $UtilsTmp "utils.ps1"
Invoke-WebRequest -Uri "$WAZUH_CERT_OAUTH2_REPO_URL/checksums.sha256" -OutFile $script:ChecksumsPath -ErrorAction Stop
Invoke-WebRequest -Uri "$WAZUH_CERT_OAUTH2_REPO_URL/scripts/shared/utils.ps1" -OutFile $UtilsPath -ErrorAction Stop
$expectedHash = (Select-String -Path $script:ChecksumsPath -Pattern "scripts/shared/utils.ps1").Line.Split(" ")[0]
if ([string]::IsNullOrWhiteSpace($expectedHash) -or ((Get-FileHash -Path $UtilsPath -Algorithm SHA256).Hash.ToLower() -ne $expectedHash.ToLower())) { Write-Error "Checksum verification failed for utils.ps1"; exit 1 }
. $UtilsPath

# Uninstall binary
function UninstallBinary {
    param ([string]$BinDir)
    InfoMessage "Removing binary from $BinDir..."
    $binaryPath = "$BinDir\$APP_NAME.exe"

    if (Test-Path $binaryPath) {
        try {
            Remove-Item -Path $binaryPath -Force
            InfoMessage "Binary removed successfully."
        } catch {
            ErrorMessage "Failed to remove binary: $_"
        }
    } else {
        WarnMessage "Binary not found at $binaryPath. Skipping."
    }
}

# Clean up configuration
function CleanupConfiguration {
    if (Test-Path $OSSEC_CONF_PATH) {
        InfoMessage "Removing agent certificate and key configurations from $OSSEC_CONF_PATH..."

        try {
            # Read the configuration file
            $configContent = Get-Content -Path $OSSEC_CONF_PATH -Raw

            # Remove certificate and key path configurations
            $configContent = $configContent -replace '(?s)<agent_certificate_path>.*?</agent_certificate_path>\s*', ''
            $configContent = $configContent -replace '(?s)<agent_key_path>.*?</agent_key_path>\s*', ''

            # Save the updated configuration
            Set-Content -Path $OSSEC_CONF_PATH -Value $configContent -NoNewline
            InfoMessage "Configuration cleaned successfully."
        } catch {
            ErrorMessage "Failed to clean configuration: $_"
        }
    } else {
        WarnMessage "Configuration file not found at $OSSEC_CONF_PATH. Skipping configuration cleanup."
    }
}

# Main script execution
EnsureAdmin
$BIN_DIR = Get-BinDirectory

UninstallBinary -BinDir $BIN_DIR
CleanupConfiguration

SuccessMessage "Uninstallation of $APP_NAME completed successfully."
