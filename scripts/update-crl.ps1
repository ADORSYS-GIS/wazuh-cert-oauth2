Param(
  [Parameter(Mandatory = $true)] [string] $CrlUrl,
  [Parameter(Mandatory = $true)] [string] $DestPath,
  [string] $ReloadCmd
)

$ErrorActionPreference = "Stop"

$tmp = "$DestPath.tmp.$PID"
Invoke-WebRequest -Uri $CrlUrl -OutFile $tmp -UseBasicParsing
Move-Item -Force -Path $tmp -Destination $DestPath

if ($ReloadCmd -and $ReloadCmd.Trim().Length -gt 0) {
  Write-Host "Reloading: $ReloadCmd"
  & powershell -NoProfile -Command $ReloadCmd
}

Write-Host "CRL updated at $DestPath from $CrlUrl"
