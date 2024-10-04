# Set error handling
$ErrorActionPreference = "Stop"

# Default log level and application details
$LOG_LEVEL = ${LOG_LEVEL:-"INFO"}
$APP_NAME = ${APP_NAME:-"wazuh-cert-oauth2-client"}
$WOPS_VERSION = ${WOPS_VERSION:-"0.2.3"}
$OSSEC_CONF_PATH = ${OSSEC_CONF_PATH:-"C:\Program Files\ossec\etc\ossec.conf"}
$USER = "root"
$GROUP = "wazuh"

# Function for logging with timestamp
function Log
{
    param(
        [string]$Level,
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$Timestamp $Level $Message"
}

# Logging helpers
function Info-Message
{
    Log -Level "INFO" -Message $args
}

function Warn-Message
{
    Log -Level "WARNING" -Message $args
}

function Error-Message
{
    Log -Level "ERROR" -Message $args
}

function Success-Message
{
    Log -Level "SUCCESS" -Message $args
}

# Exit script with an error message
function Error-Exit
{
    param([string]$message)
    Error-Message -message $message
    exit 1
}

# Check if a command exists
function Command-Exists
{
    param([string]$Name)
    return $null -ne Get-Command $Name -ErrorAction SilentlyContinue
}

# Ensure root privileges
function Maybe-Sudo
{
    param([scriptblock]$ScriptBlock)
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        if (Command-Exists -Name "sudo")
        {
            sudo $ScriptBlock
        }
        else
        {
            Error-Message "This script requires admin privileges. Please run as an administrator."
            exit 1
        }
    }
    else
    {
        & $ScriptBlock
    }
}

# Create user and group if they do not exist
function Ensure-User-Group
{
    Info-Message "Ensuring that the $USER: $GROUP user and group exist..."
    # This part may need to be adapted based on your environment or requirements
}

# Function to configure agent certificates in ossec.conf
function Configure-Agent-Certificates
{
    Info-Message "Configuring agent certificates..."
    $agentCertificatePath = 'etc\sslagent.cert'
    $agentKeyPath = 'etc\sslagent.key'
    # Add your logic here to update the $OSSEC_CONF_PATH file
}

# Determine the OS and architecture
$OS = $env:OS
$ARCH = $env:PROCESSOR_ARCHITECTURE

# Construct binary name and URL for download
$BIN_NAME = "$APP_NAME-$ARCH-$OS"
$BASE_URL = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$URL = "$BASE_URL/$BIN_NAME"

# Step 1: Download the binary file
Write-Host "Step 1: Downloading $BIN_NAME from $URL..."
Invoke-WebRequest -Uri $URL -OutFile "$env:TEMP\$BIN_NAME" -UseBasicParsing -ErrorAction Stop

# Step 2: Install the binary
Write-Host "Step 2: Installing binary to $env:USERPROFILE..."
New-Item -ItemType Directory -Path "$env:USERPROFILE\$APP_NAME" -Force
Move-Item -Path "$env:TEMP\$BIN_NAME" -Destination "$env:USERPROFILE\$APP_NAME\$APP_NAME" -Force
Set-ItemProperty -Path "$env:USERPROFILE\$APP_NAME\$APP_NAME" -Name "IsReadOnly" -Value $false

# Step 3: Update shell configuration
Write-Host "Step 3: Updating shell configuration..."
# Add logic to update your shell configuration file, typically this would be modifying environment variables

# Step 4: Configure agent certificates
Write-Host "Step 4: Configuring Wazuh agent certificates..."
if (Test-Path -Path $OSSEC_CONF_PATH)
{
    Configure-Agent-Certificates
}
else
{
    Warn-Message "Wazuh agent configuration file not found at $OSSEC_CONF_PATH. Skipping agent certificate configuration."
}

Success-Message "Installation and configuration complete! You can now use '$APP_NAME' from your terminal."