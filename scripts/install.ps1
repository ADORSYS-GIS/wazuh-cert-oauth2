# Default WOPS_VERSION to the latest if not provided
$WOPS_VERSION = $env:WOPS_VERSION
if (-not $WOPS_VERSION) {
    $WOPS_VERSION = "latest"
}

# Set the app configuration folder and bin directory
$ConfigDir = "$env:APPDATA\wazuh-cert-oauth2-client"
$BinDir = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps"

# Determine the architecture
$Arch = (Get-WmiObject -Class Win32_Processor).Architecture
switch ($Arch) {
    9 { $Arch = "x86_64" }
    12 { $Arch = "aarch64" }
    default { Write-Host "Unsupported architecture: $Arch"; exit 1 }
}

# URL for downloading the zip file
$BaseUrl = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$ZipFile = "wazuh-cert-oauth2-client-$Arch-windows.zip"
$Url = "$BaseUrl/$ZipFile"

# Download the zip file
$TempZipPath = "$env:TEMP\$ZipFile"
Write-Host "Downloading $ZipFile from $Url..."
Invoke-WebRequest -Uri $Url -OutFile $TempZipPath
if (!$?) {
    Write-Host "Failed to download $ZipFile"
    exit 1
}

# Unzip the file
$TempExtractDir = "$env:TEMP\wazuh-cert-oauth2-client"
Write-Host "Unzipping $ZipFile..."
Expand-Archive -Path $TempZipPath -DestinationPath $TempExtractDir -Force
if (!$?) {
    Write-Host "Failed to unzip $ZipFile"
    exit 1
}

# Move the binary to the BinDir
Write-Host "Installing binary to $BinDir..."
Move-Item -Path "$TempExtractDir\wazuh-cert-oauth2-client.exe" -Destination "$BinDir\wazuh-cert-oauth2-client.exe" -Force

# Cleanup
Remove-Item -Path $TempZipPath -Force
Remove-Item -Path $TempExtractDir -Recurse -Force

Write-Host "Installation complete! You can now use 'wazuh-cert-oauth2-client' from your terminal."
