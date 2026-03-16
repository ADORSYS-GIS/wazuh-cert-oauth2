# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default log level and application details
$LOG_LEVEL = if ($env:LOG_LEVEL -ne $null) { $env:LOG_LEVEL } else { "INFO" }
$APP_NAME = if ($env:APP_NAME -ne $null) { $env:APP_NAME } else { "wazuh-cert-oauth2-client" }
$DEFAULT_WOPS_VERSION = "0.4.2"
$WOPS_VERSION = if ($env:WOPS_VERSION -ne $null) { $env:WOPS_VERSION } else { $DEFAULT_WOPS_VERSION }
$OSSEC_CONF_PATH = if ($env:OSSEC_CONF_PATH -ne $null) { $env:OSSEC_CONF_PATH } else { "C:\Program Files (x86)\ossec-agent\ossec.conf" }
$USER = "root"
$GROUP = "wazuh"


# Function for logging with timestamp
function Log {
    param (
        [string]$Level,
        [string]$Message,
        [string]$Color = "White"  # Default color
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Timestamp $Level $Message" -ForegroundColor $Color
}

# Logging helpers with colors
function InfoMessage {
    param ([string]$Message)
    Log "[INFO]" $Message "White"
}

function WarnMessage {
    param ([string]$Message)
    Log "[WARNING]" $Message "Yellow"
}

function ErrorMessage {
    param ([string]$Message)
    Log "[ERROR]" $Message "Red"
}

function SuccessMessage {
    param ([string]$Message)
    Log "[SUCCESS]" $Message "Green"
}

function PrintStep {
    param (
        [int]$StepNumber,
        [string]$Message
    )
    Log "[STEP]" "Step ${StepNumber}: $Message" "White"
}

# Section Separator
function SectionSeparator {
    param (
        [string]$SectionName
    )
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Magenta
    Write-Host "  $SectionName" -ForegroundColor Magenta
    Write-Host "==================================================" -ForegroundColor Magenta
    Write-Host ""
}


# Exit script with an error message
function ErrorExit {
    param ([string]$Message)
    ErrorMessage $Message
    exit 1
}

# Check if a command exists (in PowerShell, we check if a command is available in PATH)
function CommandExists {
    param ([string]$Command)
    return Get-Command $Command -ErrorAction SilentlyContinue
}

# Ensure the script is running with administrator privileges
function EnsureAdmin {
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        ErrorExit "This script requires administrative privileges. Please run it as Administrator."
    }
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
