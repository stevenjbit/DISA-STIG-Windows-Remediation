<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000039: Removes "Run as different user" from context menus.
    Sets 'SuppressionPolicy' to 4096 for bat, cmd, exe, and msc file types.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-CC-000039
    Vulnerability : V-253359
    Severity      : Medium (CAT II)
    Value Name    : SuppressionPolicy
    Value Required: 4096 (0x1000)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000039.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define the four registry paths required by the STIG
$regPaths = @(
    "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser",
    "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser"
)

$valueName = "SuppressionPolicy"
$valueData = 4096  # 0x1000

try {
    foreach ($path in $regPaths) {
        # Check if the registry path exists; create it if missing
        if (-not (Test-Path $path)) {
            Write-Host "Registry path not found. Creating path: $path" -ForegroundColor Cyan
            New-Item -Path $path -Force | Out-Null
        }

        # Set the SuppressionPolicy value
        Write-Host "Setting '$valueName' to '$valueData' in $path..." -ForegroundColor Cyan
        New-ItemProperty -Path $path -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

        # Verification Step
        $currentValue = Get-ItemProperty -Path $path -Name $valueName -ErrorAction SilentlyContinue
        if ($currentValue.SuppressionPolicy -eq $valueData) {
            Write-Host "SUCCESS: Configured correctly for $($path.Split('\')[-3])." -ForegroundColor Green
        } else {
            Write-Error "FAILURE: Value could not be verified for $path."
        }
    }
} catch {
    Write-Error "An error occurred: $_"
}
