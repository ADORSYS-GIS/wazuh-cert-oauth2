# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default log level and application details
$LOG_LEVEL = if ($env:LOG_LEVEL -ne $null) { $env:LOG_LEVEL } else { "INFO" }
$APP_NAME = if ($env:APP_NAME -ne $null) { $env:APP_NAME } else { "wazuh-cert-oauth2-client" }
$DEFAULT_WOPS_VERSION = "0.2.7"
$WOPS_VERSION = if ($env:WOPS_VERSION -ne $null) { $env:WOPS_VERSION } else { $DEFAULT_WOPS_VERSION }
$OSSEC_CONF_PATH = if ($env:OSSEC_CONF_PATH -ne $null) { $env:OSSEC_CONF_PATH } else { "C:\Program Files (x86)\ossec-agent\ossec.conf" }
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

# Check for enrollment block and insert if missing
function CheckEnrollment {

    # Check if <enrollment> block exists
    if (-not (Get-Content $OSSEC_CONF_PATH | Select-String -Pattern "<enrollment>")) {
        $ENROLLMENT_BLOCK = "`t`t`n<enrollment>`n <agent_name></agent_name>`n </enrollment>`n"

        # Add the enrollment block after the </server> line
        (Get-Content $OSSEC_CONF_PATH) -replace "(</server.*)", "`$1$ENROLLMENT_BLOCK" | Set-Content $OSSEC_CONF_PATH -ErrorAction Stop

        Write-Host "The enrollment block was added successfully."
    }

    Write-Host "Configuring agent certificates..."

    # Check and insert agent certificate path if it doesn't exist
    if (-not (Get-Content $OSSEC_CONF_PATH | Select-String -Pattern '<agent_certificate_path>etc/sslagent.cert</agent_certificate_path>')) {
        $certPathBlock = "<agent_certificate_path>etc/sslagent.cert</agent_certificate_path>"
        (Get-Content $OSSEC_CONF_PATH) -replace "(<agent_name.*)", "`$1`n$certPathBlock" | Set-Content $OSSEC_CONF_PATH -ErrorAction Stop
        Write-Host "Agent certificates path configured successfully."
    }

    # Check and insert agent key path if it doesn't exist
    if (-not (Get-Content $OSSEC_CONF_PATH | Select-String -Pattern '<agent_key_path>etc/sslagent.key</agent_key_path>')) {
        $keyPathBlock = "<agent_key_path>etc/sslagent.key</agent_key_path>"
        (Get-Content $OSSEC_CONF_PATH) -replace "(<agent_name.*)", "`$1`n$keyPathBlock" | Set-Content $OSSEC_CONF_PATH -ErrorAction Stop
        Write-Host "Agent key path configured successfully."
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
$BIN_NAME = "$APP_NAME-$ARCH-pc-$OS-msvc.exe"
$BASE_URL = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$URL = "$BASE_URL/$BIN_NAME"

# Fallback URL if the constructed URL fails
$FALLBACK_URL = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$DEFAULT_WOPS_VERSION/wazuh-cert-oauth2-client-x86_64-pc-windows-msvc.exe"

# Step 1: Download the binary file
$TEMP_FILE = New-TemporaryFile
PrintStep 1 "Downloading $BIN_NAME from $URL..."-client-x86_64-pc-windows-msvc.exe
try {
    Invoke-WebRequest -Uri $URL -OutFile $TEMP_FILE -UseBasicParsing -ErrorAction Stop
} catch {
    WarnMessage "Failed to download from $URL. Trying fallback URL..."
    Invoke-WebRequest -Uri $FALLBACK_URL -OutFile $TEMP_FILE -UseBasicParsing -ErrorAction Stop
}

# Step 2: Install the binary based on architecture
$BIN_DIR = "C:\Program Files (x86)\ossec-agent"
$ETC_DIR = "C:\Program Files (x86)\ossec-agent\etc"

PrintStep 2 "Installing binary to $BIN_DIR..."
New-Item -ItemType Directory -Path $BIN_DIR -Force
Move-Item -Path $TEMP_FILE -Destination "$BIN_DIR\$APP_NAME.exe"
icacls "$BIN_DIR\$APP_NAME.exe" /grant Users:RX
New-Item -ItemType Directory -Path $ETC_DIR -Force

# Step 3: Configure agent certificates
PrintStep 3 "Configuring Wazuh agent certificates..."
if (Test-Path $OSSEC_CONF_PATH) {
    CheckEnrollment
} else {
    WarnMessage "Wazuh agent configuration file not found at $OSSEC_CONF_PATH. Skipping agent certificate configuration."
}

SuccessMessage "Installation and configuration complete! You can now use '$BIN_DIR\$APP_NAME.exe' from your terminal."
InfoMessage "Run ``& '$BIN_DIR\$APP_NAME.exe' o-auth2`` to start configuring."
