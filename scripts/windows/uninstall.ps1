# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default application details
$APP_NAME = if ($env:APP_NAME -ne $null) { $env:APP_NAME } else { "wazuh-cert-oauth2-client" }
$OSSEC_CONF_PATH = if ($env:OSSEC_CONF_PATH -ne $null) { $env:OSSEC_CONF_PATH } else { "C:\Program Files (x86)\ossec-agent\ossec.conf" }

# Download and source common helper functions
$commonUrl = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/refs/heads/refactor/split-linux-macos-scripts/scripts/shared/common.ps1"
$commonPath = "C:\Temp\common.ps1"

if (-not (Test-Path $commonPath)) {
    try {
        if (-not (Test-Path "C:\Temp")) {
            New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null
            Write-Host "Created directory: C:\Temp"
        }
        Invoke-WebRequest -Uri $commonUrl -OutFile $commonPath -Headers @{"User-Agent"="Mozilla/5.0"} -ErrorAction Stop
        Write-Host "Downloaded common helper functions"
    }
    catch {
        Write-Host "Failed to download common helper functions: $_" -ForegroundColor Red
        exit 1
    }
}

try {
    . "$commonPath"
    InfoMessage "Loaded common helper functions"
}
catch {
    Write-Host "Failed to load common helper functions: $_" -ForegroundColor Red
    exit 1
}

# Determine binary directory based on architecture
function GetBinDirectory {
    if ([Environment]::Is64BitOperatingSystem) {
        return "C:\Program Files (x86)\ossec-agent"
    } else {
        return "C:\Program Files\ossec-agent"
    }
}

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
$BIN_DIR = GetBinDirectory

UninstallBinary -BinDir $BIN_DIR
CleanupConfiguration

SuccessMessage "Uninstallation of $APP_NAME completed successfully."
