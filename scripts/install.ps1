# Set the app configuration folder
$ConfigDir = "$env:APPDATA\wazuh-cert-oauth2-client"

# Determine the architecture
$Arch = (Get-WmiObject -Class Win32_Processor).Architecture
switch ($Arch) {
    9 { $Arch = "x86_64" }
    12 { $Arch = "aarch64" }
    default { Write-Host "Unsupported architecture: $Arch"; exit 1 }
}

$WopsVersion = "0.1.1"  # Replace with the actual version
# URL for downloading the zip file
$BaseUrl = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"  # Replace with your actual URL
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

# Move the binary to the configuration folder
Write-Host "Installing binary to $ConfigDir..."
New-Item -ItemType Directory -Force -Path $ConfigDir
Move-Item -Path "$TempExtractDir\wazuh-cert-oauth2-client.exe" -Destination "$ConfigDir\wazuh-cert-oauth2-client.exe" -Force

# Cleanup
Remove-Item -Path $TempZipPath -Force
Remove-Item -Path $TempExtractDir -Recurse -Force

Write-Host "Installation complete!"
