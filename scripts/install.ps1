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
$BinDir = Join-Path -Path $env:USERPROFILE -ChildPath "AppData\Local\Microsoft\WindowsApps"

# Determine the architecture
$Arch = (Get-WmiObject -Class Win32_Processor).Architecture
switch ($Arch) {
    9 { $Arch = "x86_64" }
    12 { $Arch = "aarch64" }
    default { ErrorExit "Unsupported architecture: $Arch" }
}

# Construct the full binary name
$BinName = "wazuh-cert-oauth2-client-$Arch-pc-windows-msvc"

# URL for downloading the binary
$BaseUrl = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$Url = "$BaseUrl/$BinName"

# Download the binary file
$TempBinPath = Join-Path -Path $env:TEMP -ChildPath $BinName
Write-Host "Downloading $BinName from $Url..."
try {
    Invoke-WebRequest -Uri $Url -OutFile $TempBinPath -ErrorAction Stop
} catch {
    ErrorExit "Failed to download $BinName"
}

# Move the binary to the BinDir
Write-Host "Installing binary to $BinDir..."
try {
    Move-Item -Path $TempBinPath -Destination (Join-Path -Path $BinDir -ChildPath "wazuh-cert-oauth2-client.exe") -Force
} catch {
    ErrorExit "Failed to move binary to $BinDir"
}

# Cleanup
Remove-Item -Path $TempBinPath -Force

Write-Host "Installation complete! You can now use 'wazuh-cert-oauth2-client' from your terminal."
