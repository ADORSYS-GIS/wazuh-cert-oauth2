<#
  Shared PowerShell helper functions for install/uninstall scripts
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Log {
    param (
        [string]$Level,
        [string]$Message,
        [System.ConsoleColor]$Color = 'White'
    )
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "$Timestamp $Level $Message" -ForegroundColor $Color
}

function InfoMessage { param([string]$Message) ; Log '[INFO]' $Message 'White' }
function WarnMessage { param([string]$Message) ; Log '[WARNING]' $Message 'Yellow' }
function ErrorMessage { param([string]$Message) ; Log '[ERROR]' $Message 'Red' }
function SuccessMessage { param([string]$Message) ; Log '[SUCCESS]' $Message 'Green' }

function PrintStep {
    param ([int]$StepNumber, [string]$Message)
    Log '[STEP]' "Step ${StepNumber}: $Message" 'White'
}

function SectionSeparator {
    param([string]$SectionName)
    Write-Host ""; Write-Host '==================================================' -ForegroundColor Magenta
    Write-Host "  $SectionName" -ForegroundColor Magenta
    Write-Host '==================================================' -ForegroundColor Magenta; Write-Host ""
}

function ErrorExit { param([string]$Message) ; ErrorMessage $Message ; exit 1 }

function CommandExists { param([string]$Command) ; return (Get-Command $Command -ErrorAction SilentlyContinue) }

function EnsureAdmin {
    if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        ErrorExit 'This script requires administrative privileges. Please run it as Administrator.'
    }
}

function EnsureUserGroup {
    param([string]$User = 'root', [string]$Group = 'wazuh')
    InfoMessage "Ensuring that the ${User}:${Group} user and group exist..."
    if (-Not (Get-LocalUser -Name $User -ErrorAction SilentlyContinue)) {
        InfoMessage "Creating user $User..."
        New-LocalUser -Name $User -NoPassword -ErrorAction SilentlyContinue
    }
    if (-Not (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue)) {
        InfoMessage "Creating group $Group..."
        New-LocalGroup -Name $Group -ErrorAction SilentlyContinue
    }
}

return $true
