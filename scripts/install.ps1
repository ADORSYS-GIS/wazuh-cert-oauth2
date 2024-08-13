# Enable strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Function to print an error message and exit
function ErrorExit {
    Write-Host "Error: $($_)" -ForegroundColor Red
    exit 1
}

# Default WOPS_VERSION to the latest if not provided
$WOPS_VERSION = $env:WOPS_VERSION
if (-not $WOPS_VERSION) {
    $WOPS_VERSION = "latest"
}

# Set the app configuration folder and bin directory
$ConfigDir = Join-Path -Path $env:APPDATA -ChildPath "wazuh-cert-oauth2-client"
$BinDir = Join-Path -Path $env:USERPROFILE -ChildPath "AppData\Local\Microsoft\WindowsApps"

# Determine the architecture
$Arch = (Get-WmiObject -Class Win32_Processor).Architecture
switch ($Arch) {
    9 { $Arch = "x86_64" }
    12 { $Arch = "aarch64" }
    default { ErrorExit "Unsupported architecture: $Arch" }
}

# URL for downloading the zip file
$BaseUrl = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$ZipFile = "wazuh-cert-oauth2-client-$Arch-windows.zip"
$Url = "$BaseUrl/$ZipFile"

# Download the zip file
$TempZipPath = Join-Path -Path $env:TEMP -ChildPath $ZipFile
Write-Host "Downloading $ZipFile from $Url..."
try {
    Invoke-WebRequest -Uri $Url -OutFile $TempZipPath -ErrorAction Stop
} catch {
    ErrorExit "Failed to download $ZipFile"
}

# Unzip the file
$TempExtractDir = Join-Path -Path $env:TEMP -ChildPath "wazuh-cert-oauth2-client"
Write-Host "Unzipping $ZipFile..."
try {
    Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractDir -Force
} catch {
    ErrorExit "Failed to unzip $ZipFile"
}

# Move the binary to the BinDir
Write-Host "Installing binary to $BinDir..."
try {
    Move-Item -Path (Join-Path -Path $TempExtractDir -ChildPath "wazuh-cert-oauth2-client.exe") -Destination (Join-Path -Path $BinDir -ChildPath "wazuh-cert-oauth2-client.exe") -Force
} catch {
    ErrorExit "Failed to move binary to $BinDir"
}

# Cleanup
Remove-Item -Path $TempZipPath -Force
Remove-Item -Path $TempExtractDir -Recurse -Force

Write-Host "Installation complete! You can now use 'wazuh-cert-oauth2-client' from your terminal."
