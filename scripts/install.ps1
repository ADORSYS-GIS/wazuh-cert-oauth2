# Ensure the script stops on any error
$ErrorActionPreference = "Stop"

# Configuration variables
$LOG_LEVEL = "INFO"
$APP_NAME = "wazuh-cert-oauth2-client"
$WOPS_VERSION = $env:WOPS_VERSION -or "0.1.5"

# Function to handle logging
function Log {
    param (
        [string]$Level,
        [string]$Message
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ($Level -eq "ERROR" -or ($Level -eq "WARNING" -and $LOG_LEVEL -ne "ERROR") -or ($Level -eq "INFO" -and $LOG_LEVEL -eq "INFO")) {
        Write-Host "$Timestamp [$Level] $Message"
    }
}

# Function to print steps
function Print-Step {
    param (
        [string]$Step,
        [string]$Message
    )
    Log "INFO" "------ Step $Step : $Message ------"
}

# Function to handle errors
function Error-Exit {
    param (
        [string]$Message
    )
    Log "ERROR" $Message
    exit 1
}

# Determine the architecture
$ARCH = $env:PROCESSOR_ARCHITECTURE
switch ($ARCH) {
    "AMD64" { $ARCH = "x86_64" }
    "ARM64" { $ARCH = "aarch64" }
    default { Error-Exit "Unsupported architecture: $ARCH" }
}

# Set paths based on OS
$OS = "windows"
$BinDir = "$env:USERPROFILE\bin"
$BinName = "$APP_NAME-$ARCH-$OS.exe"

# URL for downloading the binary
$BaseUrl = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$Url = "$BaseUrl/$BinName"

# Create a temporary directory for the download
$TempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()) -Force
if (-not $TempDir) {
    Error-Exit "Failed to create temporary directory"
}

# Ensure the temporary directory is removed on exit
function Cleanup {
    if (Test-Path $TempDir) {
        Remove-Item -Force -Recurse $TempDir
    }
}
trap { Cleanup; exit 1 }

# Step 1: Download the binary file
Print-Step 1 "Downloading $BinName from $Url..."
Invoke-WebRequest -Uri $Url -OutFile "$TempDir\$BinName" -ErrorAction Stop

# Step 2: Install the binary
Print-Step 2 "Installing binary to $BinDir..."
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}
Move-Item -Force "$TempDir\$BinName" "$BinDir\$APP_NAME.exe" -ErrorAction Stop

# Set permissions on the binary
$acl = Get-Acl "$BinDir\$APP_NAME.exe"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$env:USERNAME", "ReadAndExecute", "Allow")
$acl.SetAccessRule($rule)
Set-Acl -Path "$BinDir\$APP_NAME.exe" -AclObject $acl

# Step 3: Update environment variables
Print-Step 3 "Updating environment variables..."

# Update PATH if necessary
$Path = [System.Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
if ($Path -notlike "*$BinDir*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$BinDir;$Path", [System.EnvironmentVariableTarget]::User)
    Log "INFO" "Updated PATH to include $BinDir"
}

# Set RUST_LOG environment variable
if (-not [System.Environment]::GetEnvironmentVariable("RUST_LOG", [System.EnvironmentVariableTarget]::User)) {
    [System.Environment]::SetEnvironmentVariable("RUST_LOG", "info", [System.EnvironmentVariableTarget]::User)
    Log "INFO" "Set RUST_LOG=info"
}

# Notify the user to restart their shell or apply changes
Log "INFO" "Installation complete! You can now use '$APP_NAME' from your PowerShell session."
Log "INFO" "Please restart your PowerShell session or run 'refreshenv' to apply the changes."

# Cleanup temporary files
Cleanup
