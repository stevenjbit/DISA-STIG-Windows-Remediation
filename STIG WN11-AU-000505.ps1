<#
.SYNOPSIS
    Remediates STIG ID WN11-AU-000505: Configures the Security event log size to 1024000 KB or greater.
    Creates the registry path if it does not exist.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-14
    Last Modified   : 2026-02-14
    Version         : 1.0
    STIG ID       : WN11-AU-000505
    Vulnerability : V-253338
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security
    Value Name    : MaxSize
    Value Required: 1024000 (0xFA000)

.TESTED ON
    Date(s) Tested  : 14 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-au-000505.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
$valueName = "MaxSize"
$valueData = 1024000  # 1,024,000 KB (0xFA000)

try {
    # Check if the registry path exists; create it if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found. Creating path: $regPath" -ForegroundColor Cyan
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the MaxSize value
    Write-Host "Setting '$valueName' to '$valueData' in $regPath..." -ForegroundColor Cyan
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Verification Step
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.MaxSize -eq $valueData) {
        Write-Host "SUCCESS: Security event log size configured to $($currentValue.MaxSize) KB." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}
