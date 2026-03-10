<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000327: Enables PowerShell Transcription.
    Sets 'EnableTranscripting' to 1 to record detailed audit logs of PowerShell activity.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-CC-000327
    Vulnerability : V-253415
    Severity      : Medium (CAT II)
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    Value Name    : EnableTranscripting
    Value Required: 1 (Enabled)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000327.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$valueName = "EnableTranscripting"
$valueData = 1  # 1 = Enabled

# Optional: Define Output Directory (Uncomment and edit the line below to set a secure path)
# $outputDirectory = "C:\Windows\Logs\PowerShellTranscript" 

try {
    # Check if the registry path exists; create it if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found. Creating path: $regPath" -ForegroundColor Cyan
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the EnableTranscripting value to 1
    Write-Host "Setting '$valueName' to '$valueData' in $regPath..." -ForegroundColor Cyan
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Optional: Set the OutputDirectory if defined
    if ($Variable:outputDirectory) {
        Write-Host "Setting OutputDirectory to '$outputDirectory'..." -ForegroundColor Cyan
        New-ItemProperty -Path $regPath -Name "OutputDirectory" -Value $outputDirectory -PropertyType String -Force | Out-Null
    }

    # Verification Step
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.EnableTranscripting -eq $valueData) {
        Write-Host "SUCCESS: PowerShell Transcription has been ENABLED (1)." -ForegroundColor Green
        if ($Variable:outputDirectory) {
             Write-Host "       Output Directory set to: $outputDirectory" -ForegroundColor Green
        }
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}
