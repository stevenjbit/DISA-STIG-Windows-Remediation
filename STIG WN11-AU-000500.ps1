<#
.SYNOPSIS
    Remediates STIG ID WN11-AU-000500: Configures the Application event log size to 32768 KB or greater.
    Creates the registry path if it does not exist.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-14
    Last Modified   : 2026-02-14
    STIG ID       : WN11-AU-000500
    Vulnerability : V-253337
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application
    Value Name    : MaxSize
    Value Required: 32768 (0x8000)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-au-000500.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
$valueName = "MaxSize"
$valueData = 32768  # 32,768 KB (0x8000)

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
        Write-Host "SUCCESS: Application event log size configured to $($currentValue.MaxSize) KB." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}
