# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default log level and application details
$LOG_LEVEL = if ($env:LOG_LEVEL -ne $null) { $env:LOG_LEVEL } else { "INFO" }
$APP_NAME = if ($env:APP_NAME -ne $null) { $env:APP_NAME } else { "wazuh-cert-oauth2-client" }
$DEFAULT_WOPS_VERSION = "0.2.5"
$WOPS_VERSION = if ($env:WOPS_VERSION -ne $null) { $env:WOPS_VERSION } else { $DEFAULT_WOPS_VERSION }
$OSSEC_CONF_PATH = if ($env:OSSEC_CONF_PATH -ne $null) { $env:OSSEC_CONF_PATH } else { "C:\Program Files\ossec-agent\ossec.conf" }
$USER = "root"
$GROUP = "wazuh"

# Define text formatting (Windows doesn't support color in native console, this is a placeholder)
$RED = "RED"
$GREEN = "GREEN"
$YELLOW = "YELLOW"
$BLUE = "BLUE"
$BOLD = ""
$NORMAL = ""

# Function for logging with timestamp
function Log {
    param (
        [string]$Level,
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Timestamp $Level $Message"
}

# Logging helpers
function InfoMessage {
    param ([string]$Message)
    Log "[INFO]" $Message
}

function WarnMessage {
    param ([string]$Message)
    Log "[WARNING]" $Message
}

function ErrorMessage {
    param ([string]$Message)
    Log "[ERROR]" $Message
}

function SuccessMessage {
    param ([string]$Message)
    Log "[SUCCESS]" $Message
}

function PrintStep {
    param (
        [int]$StepNumber,
        [string]$Message
    )
    Log "[STEP]" "Step ${StepNumber}: $Message"
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

# Ensure user and group (Windows equivalent is ensuring local user or group exists)
function EnsureUserGroup {
    InfoMessage "Ensuring that the ${USER}:${GROUP} user and group exist..."

    if (-Not (Get-LocalUser -Name $USER -ErrorAction SilentlyContinue)) {
        InfoMessage "Creating user $USER..."
        New-LocalUser -Name $USER -NoPassword
    }

    if (-Not (Get-LocalGroup -Name $GROUP -ErrorAction SilentlyContinue)) {
        InfoMessage "Creating group $GROUP..."
        New-LocalGroup -Name $GROUP
    }
}

# Configure agent certificates in ossec.conf
function ConfigureAgentCertificates {
    InfoMessage "Configuring agent certificates..."

    # Determine certificate paths based on architecture
    $baseDir = Split-Path -Parent $OSSEC_CONF_PATH
    $certPath = "$baseDir\sslagent.cert"
    $keyPath = "$baseDir\sslagent.key"

    if (-Not (Select-String -Path $OSSEC_CONF_PATH -Pattern '<agent_certificate_path>sslagent.cert</agent_certificate_path>' -Quiet)) {
        [xml]$config = Get-Content $OSSEC_CONF_PATH
        $certPathNode = $config.CreateElement("agent_certificate_path")
        $certPathNode.InnerText = $certPath
        $config.ossec.server.InsertAfter($certPathNode, $config.ossec.server.agent_name)
        $config.Save($OSSEC_CONF_PATH)
    }

    if (-Not (Select-String -Path $OSSEC_CONF_PATH -Pattern '<agent_key_path>sslagent.key</agent_key_path>' -Quiet)) {
        [xml]$config = Get-Content $OSSEC_CONF_PATH
        $keyPathNode = $config.CreateElement("agent_key_path")
        $keyPathNode.InnerText = $keyPath
        $config.ossec.server.InsertAfter($keyPathNode, $config.ossec.server.agent_name)
        $config.Save($OSSEC_CONF_PATH)
    }

    InfoMessage "Agent certificates path configured successfully."
}

# Check for enrollment block and insert if missing
function CheckEnrollment {
    if (-Not (Select-String -Path $OSSEC_CONF_PATH -Pattern "<enrollment>" -Quiet)) {
        $enrollmentBlock = @"
<enrollment>
    <agent_name></agent_name>
    <agent_certificate_path>$certPath</agent_certificate_path>
    <agent_key_path>$keyPath</agent_key_path>
</enrollment>
"@
        Add-Content -Path $OSSEC_CONF_PATH -Value $enrollmentBlock
        InfoMessage "The enrollment block was added successfully."
    } else {
        ConfigureAgentCertificates
        InfoMessage "Enrollment block already exists. Agent certificates configured."
    }
}

# Determine architecture and operating system
$OS = if ($PSVersionTable.PSEdition -eq "Core") { "linux" } else { "windows" }
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }

if ($OS -ne "windows") {
    ErrorExit "Unsupported operating system: $OS"
}

if ($ARCH -ne "x86_64" -and $ARCH -ne "x86") {
    ErrorExit "Unsupported architecture: $ARCH"
}

# Construct binary name and URL for download
$BIN_NAME = "$APP_NAME-$ARCH-$OS"
$BASE_URL = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$URL = "$BASE_URL/$BIN_NAME"

# Fallback URL if the constructed URL fails
$FALLBACK_URL = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$DEFAULT_WOPS_VERSION/wazuh-cert-oauth2-client-x86_64-pc-windows-msvc.exe"

# Step 1: Download the binary file
$TEMP_FILE = New-TemporaryFile
PrintStep 1 "Downloading $BIN_NAME from $URL..."
try {
    Invoke-WebRequest -Uri $URL -OutFile $TEMP_FILE -UseBasicParsing -ErrorAction Stop
} catch {
    WarnMessage "Failed to download from $URL. Trying fallback URL..."
    Invoke-WebRequest -Uri $FALLBACK_URL -OutFile $TEMP_FILE -UseBasicParsing -ErrorAction Stop
}

# Step 2: Install the binary based on architecture
if ($ARCH -eq "x86_64") {
    $BIN_DIR = "C:\Program Files (x86)\ossec-agent"
} else {
    $BIN_DIR = "C:\Program Files\ossec-agent"
}

PrintStep 2 "Installing binary to $BIN_DIR..."
New-Item -ItemType Directory -Path $BIN_DIR -Force
Move-Item -Path $TEMP_FILE -Destination "$BIN_DIR\$APP_NAME.exe"
icacls "$BIN_DIR\$APP_NAME.exe" /grant Users:RX

# Step 3: Configure agent certificates
PrintStep 3 "Configuring Wazuh agent certificates..."
if (Test-Path $OSSEC_CONF_PATH) {
    CheckEnrollment
} else {
    WarnMessage "Wazuh agent configuration file not found at $OSSEC_CONF_PATH. Skipping agent certificate configuration."
}

SuccessMessage "Installation and configuration complete! You can now use '$BIN_DIR\$APP_NAME.exe' from your terminal."
InfoMessage "Run ` ./$BIN_DIR\$APP_NAME.exe o-auth2` to start configuring."