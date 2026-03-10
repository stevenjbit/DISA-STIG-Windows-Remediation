<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000326: Enables PowerShell Script Block Logging.
    Sets 'EnableScriptBlockLogging' to 1 to record detailed logs of executed script blocks.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-CC-000326
    Vulnerability : V-253414
    Severity      : Medium (CAT II)
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    Value Name    : EnableScriptBlockLogging
    Value Required: 1 (Enabled)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000326.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$valueName = "EnableScriptBlockLogging"
$valueData = 1  # 1 = Enabled

try {
    # Check if the registry path exists; create it if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found. Creating path: $regPath" -ForegroundColor Cyan
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the EnableScriptBlockLogging value to 1
    Write-Host "Setting '$valueName' to '$valueData' in $regPath..." -ForegroundColor Cyan
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Verification Step
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.EnableScriptBlockLogging -eq $valueData) {
        Write-Host "SUCCESS: PowerShell Script Block Logging has been ENABLED (1)." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}
