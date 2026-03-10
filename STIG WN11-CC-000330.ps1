<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000330: Disables Basic authentication for the WinRM Client.
    Sets 'AllowBasic' to 0 to prevent plain text password transmission.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-CC-000330
    Vulnerability : V-253416
    Severity      : High (CAT I)
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client
    Value Name    : AllowBasic
    Value Required: 0 (Disabled)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000330.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
$valueName = "AllowBasic"
$valueData = 0  # 0 = Disabled (Secure)

try {
    # Check if the registry path exists; create it if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found. Creating path: $regPath" -ForegroundColor Cyan
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the AllowBasic value to 0
    Write-Host "Setting '$valueName' to '$valueData' in $regPath..." -ForegroundColor Cyan
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Verification Step
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.AllowBasic -eq $valueData) {
        Write-Host "SUCCESS: WinRM Client Basic Authentication has been DISABLED (0)." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}
