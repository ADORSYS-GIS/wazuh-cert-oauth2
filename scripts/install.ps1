# Ensure that the script stops on the first error
$ErrorActionPreference = "Stop"

# Function to print an error message and exit
function Error-Exit {
    param (
        [string]$Message
    )
    Write-Error $Message
    exit 1
}

# Default WOPS_VERSION to the latest if not provided
$WOPS_VERSION = $env:WOPS_VERSION -or "0.1.5"

# Determine the OS and set paths accordingly
$OS = ""
$BinDir = "$HOME\AppData\Local\bin"
if ($IsWindows) {
    $OS = "windows"
} else {
    Error-Exit "This script is intended for Windows systems."
}

# Determine the architecture
$Arch = ""
switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { $Arch = "x86_64" }
    "ARM64" { $Arch = "aarch64" }
    default { Error-Exit "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

# Construct the full binary name
$BinName = "wazuh-cert-oauth2-client-$Arch-$OS.exe"

# URL for downloading the binary
$BaseUrl = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$Url = "$BaseUrl/$BinName"

# Create a temporary directory for the download
$TempDir = New-TemporaryFile | Remove-Item -Force -Confirm:$false -PassThru | New-Item -ItemType Directory

# Ensure the temporary directory is removed on exit
$Cleanup = {
    Remove-Item -Recurse -Force $TempDir
}
Register-EngineEvent PowerShell.Exiting -Action $Cleanup | Out-Null

# Download the binary file
Write-Host "Downloading $BinName from $Url..."
Invoke-WebRequest -Uri $Url -OutFile "$TempDir\$BinName" -ErrorAction Stop

# Move the binary to the BinDir
Write-Host "Installing binary to $BinDir..."
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
Move-Item "$TempDir\$BinName" "$BinDir\wazuh-cert-oauth2-client.exe" -Force

# Set RUST_LOG environment variable
$Env:RUST_LOG = "info"
[System.Environment]::SetEnvironmentVariable("RUST_LOG", "info", [System.EnvironmentVariableTarget]::User)

Write-Host "RUST_LOG environment variable set to 'info'."

Write-Host "Installation complete! You can now use 'wazuh-cert-oauth2-client' from your terminal."
