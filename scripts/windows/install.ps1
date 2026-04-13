# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default log level and application details
$APP_NAME = if ($env:APP_NAME -ne $null) { $env:APP_NAME } else { "wazuh-cert-oauth2-client" }
$DEFAULT_WOPS_VERSION = "0.4.2"
$WOPS_VERSION = if ($env:WOPS_VERSION -ne $null) { $env:WOPS_VERSION } else { $DEFAULT_WOPS_VERSION }
$OSSEC_CONF_PATH = if ($env:OSSEC_CONF_PATH -ne $null) { $env:OSSEC_CONF_PATH } else { "C:\Program Files (x86)\ossec-agent\ossec.conf" }
$USER = "root"
$GROUP = "wazuh"

# Variables
if (-not $env:WAZUH_CERT_OAUTH2_REPO_REF) { 
    $env:WAZUH_CERT_OAUTH2_REPO_REF = "refs/tags/v$WOPS_VERSION"
}
$WAZUH_CERT_OAUTH2_REPO_REF = $env:WAZUH_CERT_OAUTH2_REPO_REF
$WAZUH_CERT_OAUTH2_REPO_URL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/$WAZUH_CERT_OAUTH2_REPO_REF"

# Create a secure temporary directory for utilities
$UtilsTmp = Join-Path $env:TEMP "wazuh-cert-oauth2-utils-$(Get-Random)"
New-Item -ItemType Directory -Path $UtilsTmp -Force | Out-Null

try {
    $ChecksumsURL = "$WAZUH_CERT_OAUTH2_REPO_URL/checksums.sha256"
    $UtilsURL = "$WAZUH_CERT_OAUTH2_REPO_URL/scripts/shared/utils.ps1"
    
    $global:ChecksumsPath = Join-Path $UtilsTmp "checksums.sha256"
    $UtilsPath = Join-Path $UtilsTmp "utils.ps1"

    Invoke-WebRequest -Uri $ChecksumsURL -OutFile $ChecksumsPath -ErrorAction Stop
    Invoke-WebRequest -Uri $UtilsURL -OutFile $UtilsPath -ErrorAction Stop

    # Verification function (bootstrap)
    function Get-FileChecksum-Bootstrap {
        param([string]$FilePath)
        return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
    }

    $ExpectedHash = (Select-String -Path $ChecksumsPath -Pattern "scripts/shared/utils.ps1").Line.Split(" ")[0]
    $ActualHash = Get-FileChecksum-Bootstrap -FilePath $UtilsPath

    if ([string]::IsNullOrWhiteSpace($ExpectedHash) -or ($ActualHash -ne $ExpectedHash.ToLower())) {
        Write-Error "Checksum verification failed for utils.ps1"
        exit 1
    }

    . $UtilsPath
}
catch {
    Write-Error "Failed to initialize utilities: $($_.Exception.Message)"
    exit 1
}

function ConfigureEnrollment {
    $certPath = "etc\sslagent.cert"  # Updated path to etc folder
    $keyPath = "etc\sslagent.key"    # Updated path to etc folder
    $agentName = "AGENT_NAME"

    if (-Not (Select-String -Path $OSSEC_CONF_PATH -Pattern "<enrollment>" -Quiet)) {

        # Read the OSSEC configuration file
        $configContent = Get-Content -Path $OSSEC_CONF_PATH -Raw

        $enrollmentBlock = @"
<enrollment>
    <agent_name>$agentName</agent_name>
    <agent_certificate_path>$certPath</agent_certificate_path>
    <agent_key_path>$keyPath</agent_key_path>
</enrollment>
"@

        # Define the pattern to locate the server block
        $serverPattern = "<server>[\s\S]*?</server>"

        # Find the end of the server block and insert the enrollment block afterward
        if ($configContent -match $serverPattern) {
            $updatedConfig = $configContent -replace "($serverPattern)", "`$1`n$enrollmentBlock"
            Set-Content -Path $OSSEC_CONF_PATH -Value $updatedConfig
            InfoMessage "Enrollment block with certificates configured successfully after the server block."
        } else {
            InfoMessage "Server block not found. Enrollment block not added."
        }
    } else {
        # Load the existing config
        [xml]$config = Get-Content $OSSEC_CONF_PATH

        # Check and add/update elements
        $enrollmentNode = $config.ossec_config.client.enrollment

        # Update or add certificate path
        $certPathNode = $enrollmentNode.SelectSingleNode("agent_certificate_path")
        if ($certPathNode) {
            $certPathNode.InnerText = $certPath
            InfoMessage "Updated agent_certificate_path"
        } else {
            $certPathNode = $config.CreateElement("agent_certificate_path")
            $certPathNode.InnerText = $certPath
            $enrollmentNode.AppendChild($certPathNode)
            InfoMessage "Added missing agent_certificate_path element"
        }

        # Update or add key path
        $keyPathNode = $enrollmentNode.SelectSingleNode("agent_key_path")
        if ($keyPathNode) {
            $keyPathNode.InnerText = $keyPath
            InfoMessage "Updated agent_key_path"
        } else {
            $keyPathNode = $config.CreateElement("agent_key_path")
            $keyPathNode.InnerText = $keyPath
            $enrollmentNode.AppendChild($keyPathNode)
            InfoMessage "Added missing agent_key_path element"
        }

        # Save changes
        $writerSettings = New-Object System.Xml.XmlWriterSettings
        $writerSettings.Indent = $true
        $writerSettings.OmitXmlDeclaration = $true
        $writerSettings.NewLineChars = "`n"
        $writerSettings.NewLineHandling = "Replace"

        $writer = [System.Xml.XmlWriter]::Create($OSSEC_CONF_PATH, $writerSettings)
        $config.Save($writer)
        $writer.Close()

        InfoMessage "Updated enrollment block configurations."
    }
}

function ValidateInstallation {
    # Check if the binary exists
    if (Test-Path "$BIN_DIR\$APP_NAME.exe") {
        InfoMessage "Binary exists at $BIN_DIR\$APP_NAME.exe."
    } else {
        WarnMessage "Binary is missing at $BIN_DIR\$APP_NAME.exe."
    }

    # Verify the configuration file contains the required updates
    if (Test-Path $OSSEC_CONF_PATH) {
        if (Select-String -Path $OSSEC_CONF_PATH -Pattern "<enrollment>" -Quiet) {
            InfoMessage "Enrollment block is present in the configuration file."
        } else {
            WarnMessage "Enrollment block is missing in the configuration file."
        }

        if (Select-String -Path $OSSEC_CONF_PATH -Pattern "<agent_certificate_path>etc\sslagent.cert</agent_certificate_path>" -SimpleMatch -Quiet) {
            InfoMessage "Agent certificate path is configured correctly."
        } else {
            WarnMessage "Agent certificate path is missing in the configuration file."
        }

        if (Select-String -Path $OSSEC_CONF_PATH -Pattern "<agent_key_path>etc\sslagent.key</agent_key_path>" -SimpleMatch -Quiet) {
            InfoMessage "Agent key path is configured correctly."
        } else {
            WarnMessage "Agent key path is missing in the configuration file."
        }

        if (-not (Select-String -Path $OSSEC_CONF_PATH -Pattern "<authorization_pass_path>etc\authd.pass</authorization_pass_path>" -SimpleMatch -Quiet)) {
            InfoMessage "Authorization pass path has been correctly removed."
        } else {
            WarnMessage "Authorization pass path is still present in the configuration file."
        }
    } else {
        WarnMessage "Configuration file not found at $OSSEC_CONF_PATH."
    }

    SuccessMessage "Validation of installation and configuration completed successfully."
}

# Determine architecture and operating system
if (-not $IsWindows) {
    ErrorExit "Unsupported operating system. This script is intended for Windows only."
}

$ARCH = if ([Environment]::Is64BitOperatingSystem) { "x86_64" } else { "x86" }

if ($ARCH -ne "x86_64" -and $ARCH -ne "x86") {
    ErrorExit "Unsupported architecture: $ARCH"
}

# Construct binary name and URL for download
$BIN_NAME = "$APP_NAME-$ARCH-pc-windows-msvc.exe"
$BASE_URL = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$WOPS_VERSION"
$URL = "$BASE_URL/$BIN_NAME"

# Fallback URL if the constructed URL fails
$FALLBACK_URL = "https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/releases/download/v$DEFAULT_WOPS_VERSION/wazuh-cert-oauth2-client-x86_64-pc-windows-msvc.exe"

# Step 1: Download the binary file with checksum verification
$TEMP_FILE = New-TemporaryFile
PrintStep 1 "Downloading $BIN_NAME from $URL..."
try {
    Download-And-VerifyFile -Url $URL -Destination $TEMP_FILE -ChecksumPattern $BIN_NAME -FileName $BIN_NAME -ChecksumUrl "$WAZUH_CERT_OAUTH2_REPO_URL/checksums.sha256"
} catch {
    WarnMessage "Failed to download from $URL. Trying fallback URL..."
    $fallbackBinName = "wazuh-cert-oauth2-client-x86_64-pc-windows-msvc.exe"
    Download-And-VerifyFile -Url $FALLBACK_URL -Destination $TEMP_FILE -ChecksumPattern $fallbackBinName -FileName $fallbackBinName -ChecksumUrl "$WAZUH_CERT_OAUTH2_REPO_URL/checksums.sha256"
}

# Step 2: Install the binary based on architecture
$BIN_DIR = Get-BinDirectory

PrintStep 2 "Installing binary to $BIN_DIR..."
New-Item -ItemType Directory -Path $BIN_DIR -Force

# Check if the file already exists and remove it if so
if (Test-Path $BIN_DIR\$APP_NAME.exe) {
    WarnMessage "File $BIN_DIR\$APP_NAME.exe already exists. Replacing it..."
    Remove-Item -Path $BIN_DIR\$APP_NAME.exe -Force
}

Move-Item -Path $TEMP_FILE -Destination "$BIN_DIR\$APP_NAME.exe"
icacls "$BIN_DIR\$APP_NAME.exe" /grant "*S-1-5-32-545:(RX)"

# Step 3: Configure agent certificates
PrintStep 3 "Configuring Wazuh agent certificates..."
if (Test-Path $OSSEC_CONF_PATH) {
    ConfigureEnrollment
} else {
    WarnMessage "Wazuh agent configuration file not found at $OSSEC_CONF_PATH. Skipping agent certificate configuration."
}

# Step 4: Validate installation and configuration
PrintStep 4 "Validating installation and configuration..."
ValidateInstallation

SuccessMessage "Installation and configuration complete! You can now use '$BIN_DIR\$APP_NAME.exe' from your terminal."
InfoMessage "Run ``& '$BIN_DIR\$APP_NAME.exe' o-auth2`` to start configuring."
