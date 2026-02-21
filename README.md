# Windows 11 DISA STIG Automation & Remediation

## Project Overview
This project demonstrates the automated hardening of a Windows 11 Virtual Machine to meet the rigorous security standards of the **Defense Information Systems Agency (DISA) Security Technical Implementation Guides (STIGs)**.

Using **Tenable Nessus** for vulnerability scanning and **PowerShell** for remediation, I identified critical configuration vulnerabilities and developed scripts to automatically correct them, significantly reducing the system's attack surface.

### 🔍 What are DISA STIGs?
DISA STIGs are the "gold standard" for secure configuration. They are a set of technical cybersecurity requirements for specific software and hardware, developed by the Department of Defense (DoD). Compliance with STIGs is mandatory for any system connecting to DoD networks.

**Why this matters:**
* **Compliance:** Demonstrates the ability to adhere to strict government and industry regulations (NIST, DoD).
* **Hardening:** Removes default settings that prioritize convenience over security (e.g., Guest accounts, weak ciphers).
* **Automation:** Shows proficiency in using code (PowerShell) to solve infrastructure problems at scale.

---

## 🛠️ The Remediation Scripts
Below is the repository of PowerShell scripts developed to resolve specific findings from the initial vulnerability scan.

#### 1. The System event log size must be configured to 32768 KB or greater.
STIG ID: WN11-AU-000510

<details>
<summary><strong>PowerShell: Remediate STIG WN11-AU-000510 (System Log Size)</strong></summary>

```powershell
<#
.SYNOPSIS
    Remediates STIG ID WN11-AU-000510: Configures the System event log size to 32768 KB or greater.
    Creates the registry path if it does not exist.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-AU-000510
    Vulnerability : V-253339
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System
    Value Name    : MaxSize
    Value Required: 32768 (0x8000)

.TESTED ON
    Date(s) Tested  : 13 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-au-000510.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
$valueName = "MaxSize"
$valueData = 32768  # 32768 KB (0x8000)

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
        Write-Host "SUCCESS: System event log size configured to $($currentValue.MaxSize) KB." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}

```

</details>

#### 2. The Security event log size must be configured to 1024000 KB or greater.
STIG ID: WN11-AU-000505

<details>
<summary><strong>PowerShell: Remediate STIG WN11-AU-000505 (Security Log Size)</strong></summary>

```powershell
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

```

</details>

#### 3. The Application event log size must be configured to 32768 KB or greater.
STIG ID: WN11-AU-000500

<details>
<summary><strong>PowerShell: Remediate STIG WN11-AU-000500 (Application Log Size)</strong></summary>

```powershell
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

```

</details>

#### 4. The Windows Installer feature "Always install with elevated privileges" must be disabled.
STIG ID: WN11-CC-000315

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000315 (Always Install Elevated)</strong></summary>

```powershell
<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000315: Disables "Always install with elevated privileges".
    Sets the registry value to 0 to prevent standard users from installing with elevated rights.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-15
    Last Modified   : 2026-02-15
    Version         : 1.0
    STIG ID       : WN11-CC-000315
    Vulnerability : V-253411
    Severity      : High (CAT I)
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    Value Name    : AlwaysInstallElevated
    Value Required: 0 (Disabled)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000315.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "AlwaysInstallElevated"
$valueData = 0  # 0 = Disabled (Secure)

try {
    # Check if the registry path exists; create it if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found. Creating path: $regPath" -ForegroundColor Cyan
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the AlwaysInstallElevated value to 0
    Write-Host "Setting '$valueName' to '$valueData' in $regPath..." -ForegroundColor Cyan
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Verification Step
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.AlwaysInstallElevated -eq $valueData) {
        Write-Host "SUCCESS: 'Always install with elevated privileges' has been DISABLED (0)." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}

```

</details>

#### 5. Users must be prevented from changing installation options.
STIG ID: WN11-CC-000310

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000310 (User Control Over Installs)</strong></summary>

```powershell
<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000310: Prevents users from changing installation options.
    Sets 'EnableUserControl' to 0 (Disabled).
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-CC-000310
    Vulnerability : V-253410
    Severity      : Medium (CAT II)
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    Value Name    : EnableUserControl
    Value Required: 0 (Disabled)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000310.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
$valueName = "EnableUserControl"
$valueData = 0  # 0 = Disabled (Secure)

try {
    # Check if the registry path exists; create it if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found. Creating path: $regPath" -ForegroundColor Cyan
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the EnableUserControl value to 0
    Write-Host "Setting '$valueName' to '$valueData' in $regPath..." -ForegroundColor Cyan
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Verification Step
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.EnableUserControl -eq $valueData) {
        Write-Host "SUCCESS: 'Allow user control over installs' has been DISABLED (0)." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}

```

</details>

#### 6. The Windows Remote Management (WinRM) client must not use Basic authentication.
STIG ID: WN11-CC-000330 

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000330 (WinRM Client Basic Auth)</strong></summary>

```powershell
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

```
</details>

#### 7. The Windows Remote Management (WinRM) service must not use Basic authentication.
STIG ID: WN11-CC-000345

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000345 (WinRM Service Basic Auth)</strong></summary>

```powershell
<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000345: Disables Basic authentication for the WinRM Service.
    Sets 'AllowBasic' to 0 to prevent the service from accepting plain text credentials.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-CC-000345
    Vulnerability : V-253418
    Severity      : High (CAT I)
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service
    Value Name    : AllowBasic
    Value Required: 0 (Disabled)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000345.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
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
        Write-Host "SUCCESS: WinRM Service Basic Authentication has been DISABLED (0)." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}

```

</details>

#### 8. PowerShell script block logging must be enabled on Windows 11
STIG ID: WN11-CC-000326

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000326 (Script Block Logging)</strong></summary>

```powershell
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

```

</details>

#### 9. PowerShell Transcription must be enabled on Windows 11
STIG ID: WN11-CC-000327

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000327 (PowerShell Transcription)</strong></summary>

```powershell
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

```

</details>

#### 10. Solicited Remote Assistance must not be allowed
STIG ID: WN11-CC-000155

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000155 (Solicited Remote Assistance)</strong></summary>

```powershell
<#
.SYNOPSIS
    Remediates STIG ID WN11-CC-000155: Disables Solicited Remote Assistance.
    Sets 'fAllowToGetHelp' to 0 to prevent users from requesting remote help.
    Run as Administrator.

.NOTES
    Author          : Steven Bealle
    LinkedIn        : linkedin.com/in/steven-bealle/
    GitHub          : github.com/stevenbcyber
    Date Created    : 2026-02-13
    Last Modified   : 2026-02-13
    Version         : 1.0
    STIG ID       : WN11-CC-000155
    Vulnerability : V-253382
    Severity      : High (CAT I)
    Registry Path : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
    Value Name    : fAllowToGetHelp
    Value Required: 0 (Disabled)

.TESTED ON
    Date(s) Tested  : 15 February 2026
    Tested By       : Steven Bealle
    Systems Tested  : Microsoft Windows 11 Version 25H2 (OS Build 26200.7840)
    PowerShell Ver. : 5.1.26100.7705

.USAGE
    PS C:\> .\remediate-stig-wn11-cc-000155.ps1 
#>

# Ensure the script is run as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run as Administrator."
    Exit
}

# Define Registry Path and Value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$valueName = "fAllowToGetHelp"
$valueData = 0  # 0 = Disabled (Secure)

try {
    # Check if the registry path exists; create it if missing
    if (-not (Test-Path $regPath)) {
        Write-Host "Registry path not found. Creating path: $regPath" -ForegroundColor Cyan
        New-Item -Path $regPath -Force | Out-Null
    }

    # Set the fAllowToGetHelp value to 0
    Write-Host "Setting '$valueName' to '$valueData' in $regPath..." -ForegroundColor Cyan
    New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null

    # Verification Step
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue
    if ($currentValue.fAllowToGetHelp -eq $valueData) {
        Write-Host "SUCCESS: Solicited Remote Assistance has been DISABLED (0)." -ForegroundColor Green
    } else {
        Write-Error "FAILURE: Value could not be verified."
    }

} catch {
    Write-Error "An error occurred: $_"
}

```

</details>

#### 11. Run as different user must be removed from context menus
STIG ID: WN11-CC-000039

<details>
<summary><strong>PowerShell: Remediate STIG WN11-CC-000039 (Remove Run as Different User)</strong></summary>

```powershell
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

```

</details>

---

# 📊 Verification & Results
To verify the effectiveness of the remediation scripts, a Tenable Nessus vulnerability scan was conducted before and after the script execution.

Phase 1: Initial Discovery

The initial scan revealed multiple high and medium severity vulnerabilities corresponding to the STIG checks listed above. Below is one example of a vulnerability which was remediated and passed on the final scan. 

Figure 1: Initial vulnerability scan results showing failed compliance checks.
<img src="https://i.imgur.com/VcwJLBh.png" height="80%" width="80%" />


Phase 2: Post-Remediation

After executing the PowerShell automation suite, a follow-up scan confirmed that all targeted vulnerabilities were successfully remediated. The system is now compliant with the specified DISA STIG controls.

Figure 2: Final vulnerability scan results showing successful remediation (Green/Passed).
<img src="https://i.imgur.com/VcwJLBh.png" height="80%" width="80%" />


# 🏁 Conclusion
This project highlights the critical role of automated policy enforcement in cybersecurity. By scripting the remediation of DISA STIG findings, I reduced the time required to secure the endpoint from hours of manual registry editing to seconds of script execution, ensuring a repeatable and auditable security baseline.

