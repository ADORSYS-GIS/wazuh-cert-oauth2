# C:\Program Files (x86)\ossec-agent\active-response\bin\delete-cert.ps1

$CERT = "C:\Program Files (x86)\ossec-agent\etc\sslagent.cert"
$KEY  = "C:\Program Files (x86)\ossec-agent\etc\sslagent.key"
$AR_LOG = "C:\Program Files (x86)\ossec-agent\logs\active-responses.log"
$TAG = "delete-cert"

function Write-ArLog {
    param([string]$Level, [string]$Msg)
    $ts = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    Add-Content -Path $AR_LOG -Value "$ts ${TAG}: [$Level] $Msg"
}

Write-ArLog "INFO" "Active response triggered via API"

# Read JSON input from stdin (required for AR)
$InputJson = [Console]::In.ReadLine()
$preview = if ($InputJson.Length -gt 200) { $InputJson.Substring(0, 200) } else { $InputJson }
Write-ArLog "DEBUG" "Received input: $preview..."

$deleted = 0
foreach ($file in @($CERT, $KEY)) {
    if (Test-Path $file) {
        try {
            Remove-Item -Force -Path $file
            Write-ArLog "INFO" "Successfully deleted $file"
            $deleted++
        } catch {
            Write-ArLog "ERROR" "Failed to delete ${file}: $_"
        }
    } else {
        Write-ArLog "WARN" "$file not found (already deleted?)"
    }
}

Write-ArLog "INFO" "Finished. Deleted $deleted certificate file(s)."
exit 0
