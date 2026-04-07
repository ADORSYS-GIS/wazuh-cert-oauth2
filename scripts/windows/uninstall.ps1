# Set strict mode for error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Default log level and application details
$APP_NAME = if ($env:APP_NAME -ne $null) { $env:APP_NAME } else { "wazuh-cert-oauth2-client" }
$DEFAULT_WOPS_VERSION = "0.4.2"
$WOPS_VERSION = if ($env:WOPS_VERSION -ne $null) { $env:WOPS_VERSION } else { $DEFAULT_WOPS_VERSION }
$OSSEC_CONF_PATH = if ($env:OSSEC_CONF_PATH -ne $null) { $env:OSSEC_CONF_PATH } else { "C:\Program Files (x86)\ossec-agent\ossec.conf" }

# Variables
if (-not $env:WAZUH_CERT_OAUTH2_REPO_REF) { 
    $env:WAZUH_CERT_OAUTH2_REPO_REF = "refs/tags/v$WOPS_VERSION"
}
$WAZUH_CERT_OAUTH2_REPO_REF = $env:WAZUH_CERT_OAUTH2_REPO_REF

# Create a secure temporary directory for utilities
$UtilsTmp = Join-Path $env:TEMP "wazuh-cert-oauth2-utils-$(Get-Random)"
New-Item -ItemType Directory -Path $UtilsTmp -Force | Out-Null

# Bootstrap download functions (minimal versions)
function Download-File-Bootstrap {
    param(
        [string]$Url,
        [string]$Destination
    )
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Get-FileChecksum-Bootstrap {
    param([string]$FilePath)
    return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLower()
}

function Test-Checksum-Bootstrap {
    param(
        [string]$FilePath,
        [string]$ExpectedHash
    )
    $actualHash = Get-FileChecksum-Bootstrap -FilePath $FilePath
    return $actualHash -eq $ExpectedHash.ToLower()
}

function Download-And-VerifyFile-Bootstrap {
    param(
        [string]$Url,
        [string]$Destination,
        [string]$ChecksumPattern,
        [string]$FileName = "Unknown file",
        [string]$ChecksumUrl = $null
    )
    
    if (-not (Download-File-Bootstrap -Url $Url -Destination $Destination)) {
        Write-Error "Failed to download $FileName"
        return $false
    }
    
    $checksumFile = $null
    if ($ChecksumUrl) {
        $tempChecksumFile = Join-Path ([System.IO.Path]::GetTempPath()) "checksums-$([System.Guid]::NewGuid().ToString()).sha256"
        if (-not (Download-File-Bootstrap -Url $ChecksumUrl -Destination $tempChecksumFile)) {
            Write-Error "Failed to download checksum file"
            return $false
        }
        $checksumFile = $tempChecksumFile
    }
    
    if ($checksumFile -and (Test-Path -Path $checksumFile)) {
        $expectedHash = (Select-String -Path $checksumFile -Pattern $ChecksumPattern).Line.Split(" ")[0]
        if ($expectedHash -and (Test-Checksum-Bootstrap -FilePath $Destination -ExpectedHash $expectedHash)) {
            Write-Host "$FileName verification passed"
        } else {
            Write-Error "$FileName checksum verification failed"
            return $false
        }
        
        if ($ChecksumUrl -and (Test-Path -Path $checksumFile)) {
            Remove-Item -Path $checksumFile -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Error "Checksum file not found"
        return $false
    }
    
    return $true
}

# Source shared utilities
try {
    $UtilsURL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/$WAZUH_CERT_OAUTH2_REPO_REF/scripts/shared/utils.ps1"
    $ChecksumsURL = "https://raw.githubusercontent.com/ADORSYS-GIS/wazuh-cert-oauth2/$WAZUH_CERT_OAUTH2_REPO_REF/checksums.sha256"
    $UtilsPath = Join-Path $UtilsTmp "utils.ps1"
    
    if (-not (Download-And-VerifyFile-Bootstrap -Url $UtilsURL -Destination $UtilsPath -ChecksumPattern "scripts/shared/utils.ps1" -FileName "utils.ps1" -ChecksumUrl $ChecksumsURL)) {
        Write-Error "Failed to download and verify utils.ps1"
        exit 1
    }

    . $UtilsPath
}
catch {
    Write-Error "Failed to initialize utilities: $($_.Exception.Message)"
    exit 1
}


# Uninstall binary
function UninstallBinary {
    param ([string]$BinDir)
    InfoMessage "Removing binary from $BinDir..."
    $binaryPath = "$BinDir\$APP_NAME.exe"
    
    if (Test-Path $binaryPath) {
        try {
            Remove-Item -Path $binaryPath -Force
            InfoMessage "Binary removed successfully."
        } catch {
            ErrorMessage "Failed to remove binary: $_"
        }
    } else {
        WarnMessage "Binary not found at $binaryPath. Skipping."
    }
}

# Clean up configuration
function CleanupConfiguration {
    if (Test-Path $OSSEC_CONF_PATH) {
        InfoMessage "Removing agent certificate and key configurations from $OSSEC_CONF_PATH..."
        
        try {
            # Read the configuration file
            $configContent = Get-Content -Path $OSSEC_CONF_PATH -Raw
            
            # Remove certificate and key path configurations
            $configContent = $configContent -replace '(?s)<agent_certificate_path>.*?</agent_certificate_path>\s*', ''
            $configContent = $configContent -replace '(?s)<agent_key_path>.*?</agent_key_path>\s*', ''
            
            # Save the updated configuration
            Set-Content -Path $OSSEC_CONF_PATH -Value $configContent -NoNewline
            InfoMessage "Configuration cleaned successfully."
        } catch {
            ErrorMessage "Failed to clean configuration: $_"
        }
    } else {
        WarnMessage "Configuration file not found at $OSSEC_CONF_PATH. Skipping configuration cleanup."
    }
}

# Main script execution
EnsureAdmin
$BIN_DIR = Get-BinDirectory

UninstallBinary -BinDir $BIN_DIR
CleanupConfiguration

SuccessMessage "Uninstallation of $APP_NAME completed successfully."
