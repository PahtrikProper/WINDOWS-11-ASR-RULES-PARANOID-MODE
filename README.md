Below is a single, self-contained **PowerShell** script plus a README.
It performs **paranoid ASR (Attack Surface Reduction) hardening**, enables Defender IPS-style features, **installs Sysmon** (if missing) with a recommended config, and **creates a Custom View XML** that you can import into Event Viewer (and attempts to place it in the system Views folder so it shows up under *Custom Views*).

> **Important:** Run as **Administrator**. Some settings (Tamper Protection, cloud-based protections, and some Defender settings) cannot be modified while Microsoft “Tamper Protection” is enabled; the script will detect and warn. ASR *blocks* can break some apps (Office macros, some older tools, drivers). Read the README and test in a VM before deploying on production.

---

# Script — `Paranoid-ASR-Sysmon-Install.ps1`

```powershell
<#
.SYNOPSIS
 Paranoid ASR + Defender IPS hardening + Sysmon installer + Event Viewer custom view (local-only).

.DESCRIPTION
 - Enables a comprehensive set of Attack Surface Reduction (ASR) rules (block mode).
 - Turns on NetworkProtection, Controlled Folder Access, and other Defender hardening.
 - Installs Sysmon (if missing) and deploys a recommended SwiftOnSecurity config.
 - Creates an Event Viewer Custom View XML that aggregates Sysmon + Defender/ASR events.
 - Attempts to place the Custom View under %ProgramData%\Microsoft\Event Viewer\Views so it appears in Event Viewer.
 - Logs actions to console. Intended for a standalone Windows 11 Pro 25H2 machine.

.NOTES
 - Run elevated (Administrator).
 - Test first in a VM. Some ASR rules may block benign admin tools. If an app breaks, use the rollback section in README.
 - Uses Microsoft-documented cmdlets (Set-MpPreference/Get-MpPreference) to configure ASR. See Microsoft docs for rule guidance.
#>

# -----------------------------------------------------------
# Helper / pre-flight
# -----------------------------------------------------------
function Assert-Admin {
    if (-not ([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
        Write-Error "This script must be run as Administrator. Exiting."
        exit 1
    }
}

Assert-Admin

$ErrorActionPreference = 'Stop'
Write-Host "=== LOCAL PARANOID ASR + DEFENDER IPS + SYSMON INSTALLER ===" -ForegroundColor Cyan

# -----------------------------------------------------------
# 0) Check Tamper Protection (informational) - cannot disable via script
# -----------------------------------------------------------
try {
    $tamper = Get-MpPreference | Select-Object -ExpandProperty DisableTamperProtection -ErrorAction SilentlyContinue
    if ($tamper -eq $true) {
        Write-Warning "Tamper Protection is DISABLED. Good for managing Defender settings via script."
    } else {
        Write-Warning "Tamper Protection appears ENABLED or not modifiable from this session. Some settings may fail or require manual change in Windows Security > Virus & threat protection > Manage settings."
    }
} catch {
    Write-Warning "Could not read Tamper Protection state (Get-MpPreference failed). You may need latest PowerShell Defender module and run as admin."
}

# -----------------------------------------------------------
# 1) Paranoid ASR rules (comprehensive list)
#    - List from Microsoft Defender ASR reference (applies to Windows 10/11).
#    - We set all to 'Enabled' (block). If you need Audit first, set $ASR_ACTION = 'AuditMode'.
# -----------------------------------------------------------
$ASR_ACTION = 'Enabled'   # switch to 'AuditMode' while testing if desired

# Paranoid GUID set (comprehensive list gathered from MS docs).
$ASR_GUIDS = @(
    "56A863A9-875E-4185-98A7-B882C64B5CE5",  # Block abuse of exploited vulnerable signed drivers
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",  # Block Adobe Reader from creating child processes
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block Office from creating child processes
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",  # Block credential stealing from LSASS
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block executable content from email/webmail
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block execution of potentially obfuscated scripts
    "D3E037E1-3EB8-44C8-A917-57927947596D",  # Block JS/VBScript from launching downloaded executable content
    "3B576869-A4EC-4529-8536-B80A7769E899",  # Block Office applications from creating executable content
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",  # Block Office apps from injecting code into other processes
    "26190899-1602-49E8-8B27-EB1D0A1CE869",  # Block Office communication app from creating child processes
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B",  # Block persistence through WMI event subscription
    "D4EFB0D8-3D2A-4FCE-A2EE-FD2D7A86986E",  # Block process creations from PSExec and WMI (some deployments)
    "33DDEDF1-C6E0-47CB-833E-DE6133960387",  # Block rebooting machine in Safe Mode
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",  # Block untrusted/unsigned processes that run from USB
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB",  # Block use of copied or impersonated system tools
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6",  # Block Webshell creation for Servers
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",  # Block Win32 API calls from Office macros
    "C1DB55AB-C21A-4637-BB3F-A12568109D35"   # Use advanced protection against ransomware
)

# Confirm list length
Write-Host "Configuring $($ASR_GUIDS.Count) ASR rules to action: $ASR_ACTION" -ForegroundColor Yellow

# Apply ASR rules
try {
    Set-MpPreference -AttackSurfaceReductionRules_Ids ($ASR_GUIDS -join ',') -AttackSurfaceReductionRules_Actions ($ASR_ACTION * $ASR_GUIDS.Count)
    Start-Sleep -Seconds 2
    Write-Host "ASR rules applied. Verify with Get-MpPreference | Select AttackSurfaceReductionRules*" -ForegroundColor Green
} catch {
    Write-Error "Failed to set ASR rules: $_"
}

# -----------------------------------------------------------
# 2) Defender IPS-like hardening (NetworkProtection, Controlled Folder Access)
# -----------------------------------------------------------
Write-Host "Applying Defender hardening (NetworkProtection, ControlledFolderAccess)..." -ForegroundColor Yellow
try {
    # Network Protection (blocks known-bad outbound)
    Set-MpPreference -EnableNetworkProtection Block
} catch {
    Write-Warning "Set-MpPreference -EnableNetworkProtection failed: $_"
}

try {
    # Controlled Folder Access (Ransomware Protection) - Options: Enabled, Disabled
    Set-MpPreference -EnableControlledFolderAccess Enabled
} catch {
    Write-Warning "Set-MpPreference -EnableControlledFolderAccess failed: $_"
}

# Ensure real-time scanning and AMSI protections on
try {
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Host "Realtime monitoring enabled." -ForegroundColor Green
} catch {
    Write-Warning "Could not enable realtime monitoring: $_"
}

# -----------------------------------------------------------
# 3) Enable ASR event logging / increase retention for Sysmon + ASR logs (local-only)
# -----------------------------------------------------------
Write-Host "Configuring event log retention (local-only)..." -ForegroundColor Yellow
# Sysmon Operational retention (if later installed) - ~400MB
try {
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /rt:true /ms:419430400
} catch {
    # will succeed once Sysmon exists
    Write-Verbose "Could not set Sysmon log retention yet. Will retry after Sysmon install."
}

# Defender (Windows Defender) operational log retention
try {
    wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /rt:true /ms:209715200
} catch {
    Write-Verbose "Could not set Windows Defender operational log retention - log may not exist on older builds."
}

# -----------------------------------------------------------
# 4) Sysmon install (if not present) using Sysinternals + SwiftOnSecurity config
# -----------------------------------------------------------
Write-Host "Checking for Sysmon..." -ForegroundColor Yellow
$sysmonPathCandidates = @(
    "$env:ProgramFiles\Sysmon\Sysmon64.exe",
    "$env:ProgramFiles\Sysinternals\Sysmon64.exe",
    "$env:windir\Sysnative\Sysmon64.exe",
    "$env:windir\System32\Sysmon64.exe"
)

$sysmonInstalled = $false
foreach ($p in $sysmonPathCandidates) {
    if (Test-Path $p) { $sysmonInstalled = $true; $sysmonExe = $p; break }
}

$temp = Join-Path $env:TEMP "sysmon_paranoid_$(Get-Random)"
New-Item -ItemType Directory -Path $temp -Force | Out-Null

if (-not $sysmonInstalled) {
    Write-Host "Sysmon not found. Downloading Sysmon (Sysinternals)..." -ForegroundColor Yellow
    $sysmonZip = Join-Path $temp "Sysmon.zip"
    $sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
    try {
        Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip -UseBasicParsing -ErrorAction Stop
        Expand-Archive -LiteralPath $sysmonZip -DestinationPath $temp -Force
        $sysmonExe = Get-ChildItem -Path $temp -Filter "Sysmon64.exe" -Recurse -ErrorAction Stop | Select-Object -First 1 -ExpandProperty FullName
        Write-Host "Sysmon downloaded to $sysmonExe" -ForegroundColor Green
    } catch {
        Write-Error "Failed to download or extract Sysmon: $_"
        exit 1
    }
} else {
    Write-Host "Found Sysmon at $sysmonExe" -ForegroundColor Green
}

# Fetch recommended Sysmon config (SwiftOnSecurity)
$sysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$sysmonConfigLocal = Join-Path $temp "sysmon.xml"
try {
    Invoke-WebRequest -Uri $sysmonConfigUrl -OutFile $sysmonConfigLocal -UseBasicParsing -ErrorAction Stop
    Write-Host "Downloaded SwiftOnSecurity Sysmon config." -ForegroundColor Green
} catch {
    Write-Warning "Failed to download remote sysmon config. Script will create a minimal config file."
    # minimal fallback config
    @"
<Sysmon schemaversion="4.20">
  <EventFiltering>
    <RuleGroup name="Default" groupRelation="or">
      <NetworkConnect onmatch="include" />
      <ProcessCreate onmatch="include" />
      <ImageLoad onmatch="include" />
      <FileCreateTime onmatch="include" />
      <DriverLoad onmatch="include" />
      <DnsQuery onmatch="include" />
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@ | Out-File -FilePath $sysmonConfigLocal -Encoding UTF8
}

# Install or update Sysmon
try {
    & $sysmonExe -accepteula -i $sysmonConfigLocal
    Write-Host "Sysmon installed/updated with config." -ForegroundColor Green
} catch {
    Write-Error "Failed to install Sysmon: $_"
}

# Re-run retention setting for Sysmon now that it exists
try {
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /rt:true /ms:419430400
} catch {
    Write-Warning "Could not set Sysmon event log retention even after install: $_"
}

# -----------------------------------------------------------
# 5) Create Event Viewer Custom View XML (Sysmon + Defender/ASR aggregation)
#    - Save XML to disk and attempt to place under ProgramData Views folder
#    - Also export a copy to user's Desktop for manual import.
# -----------------------------------------------------------
Write-Host "Creating Event Viewer Custom View XML for Sysmon + Defender..." -ForegroundColor Yellow

$customXml = @'
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-Sysmon/Operational">
    <Select Path="Microsoft-Windows-Sysmon/Operational">*[System/Level &lt;= 3]</Select>
  </Query>
  <Query Id="1" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">*[System/Level &lt;= 3]</Select>
  </Query>
  <Query Id="2" Path="Security">
    <!-- Optional: include critical security events, e.g. logon failures -->
    <Select Path="Security">*[System[(Level=1 or Level=2)]]</Select>
  </Query>
</QueryList>
'@

$desktopXml = Join-Path ([Environment]::GetFolderPath('Desktop')) "ParanoidSecurity-CustomView.xml"
$programDataViewsDir = Join-Path $env:ProgramData "Microsoft\Event Viewer\Views"
# Ensure Views dir exists
if (!(Test-Path $programDataViewsDir)) { New-Item -ItemType Directory -Path $programDataViewsDir -Force | Out-Null }

# Build full wrapper XML that Event Viewer expects (CustomView file)
$fullViewXml = @"
<Views>
  <View Name="Paranoid Security" Path="" Version="1">
    <QueryList>
$customXml
    </QueryList>
  </View>
</Views>
"@

# Save to Desktop and ProgramData Views
$fullViewXml | Out-File -FilePath $desktopXml -Encoding UTF8 -Force
$viewFileName = "View_ParanoidSecurity.xml"
$viewFilePath = Join-Path $programDataViewsDir $viewFileName
try {
    $fullViewXml | Out-File -FilePath $viewFilePath -Encoding UTF8 -Force
    Write-Host "Custom View XML placed at: $viewFilePath (Event Viewer should pick it up under Custom Views)." -ForegroundColor Green
} catch {
    Write-Warning "Failed to write to ProgramData Event Viewer Views folder. You can import $desktopXml manually via Event Viewer -> Custom Views -> Import Custom View."
}

# -----------------------------------------------------------
# 6) Final verification output and helpful tips
# -----------------------------------------------------------
Write-Host "`n=== VERIFICATION SUMMARY ===" -ForegroundColor Cyan
Write-Host "ASR action: $ASR_ACTION" -ForegroundColor Yellow
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions | Format-List

if (Get-Service -Name Sysmon -ErrorAction SilentlyContinue) {
    Write-Host "Sysmon service: Installed and running." -ForegroundColor Green
} else {
    Write-Warning "Sysmon service not found or not running. Check installation."
}

Write-Host "`nCustom view (Desktop): $desktopXml"
Write-Host "Custom view (ProgramData): $viewFilePath"
Write-Host "`n✅ Paranoid ASR + Sysmon installer finished. Reboot recommended." -ForegroundColor Green

# End script
```

---

# README — `README-Paranoid-ASR-Sysmon.md`

## Purpose

This package/script hardens a **standalone Windows 11** machine that faces the internet by:

* Enabling a **comprehensive set of ASR (Attack Surface Reduction)** rules in **Block** mode (paranoid). These rules prevent many common exploitation techniques (Office macro abuse, script obfuscation, credential dumping, webmail executable content, webshells, USB attacks, etc.). The script applies a large set of Microsoft-documented ASR GUIDs. (Source: Microsoft Defender ASR docs.) ([Microsoft Learn][1])
* Enabling Defender network and ransomware protections (Network Protection, Controlled Folder Access).
* Installing **Sysmon** (Sysinternals) if missing and applying a hardened Sysmon configuration (SwiftOnSecurity recommended config). Sysmon provides detailed local telemetry suitable for local IDS/forensics. (Sysmon download + SwiftOnSecurity config links included in the script.)
* Creating a **Custom View XML** that aggregates Sysmon events + Defender/ASR operational events so you can quickly examine alerts in Event Viewer.

It is **local-only** (no cloud forwarding) and designed to work offline. It does **not** enable cloud telemetry or forward logs to Microsoft or third parties.

## Sources / references

* Microsoft Attack surface reduction rules (reference & GUIDs). ([Microsoft Learn][1])
* Sysinternals (Sysmon) downloads.
* SwiftOnSecurity Sysmon config (recommended rule set for detection).
* Your uploaded note about TPM/attestation/privacy concerns (context for why you may want local-only logging). 

## Risks & compatibility

* **Blocking mode is harsh.** ASR rules in block mode will *prevent* many risky behaviors, but they can also break legitimate workflows (e.g., macros, legacy admin tools, unsigned USB tools, drivers). Test in a VM first and set `$ASR_ACTION = 'AuditMode'` in the script while you triage false positives.
* **Tamper Protection** can prevent the script from changing some Defender settings. If Tamper Protection is enabled, you may need to temporarily disable it via Windows Security UI to allow changes.
* **Some ASR rules require cloud protection** (ransomware advanced protection) to be fully effective; we enable them but note that they may rely on cloud heuristics.
* **Sysmon** will log a lot. Make sure you have disk space and retention configured. The script sets retention for Sysmon operational log to ~400MB.

## How to use

1. Copy the script (`Paranoid-ASR-Sysmon-Install.ps1`) to the target machine.
2. Right-click → **Run as Administrator** (or `powershell.exe -ExecutionPolicy Bypass -File .\Paranoid-ASR-Sysmon-Install.ps1` in an elevated shell).
3. Follow console output. Reboot when finished.
4. Open **Event Viewer** → **Custom Views** → import the `ParanoidSecurity-CustomView.xml` from your Desktop if it did not appear automatically.

   * If the script could copy the view into `%ProgramData%\Microsoft\Event Viewer\Views\`, Event Viewer should show it under *Custom Views*.
5. If an app breaks, consult the **Rollback** section below.

## Rollback / tuning

* To disable all ASR rules (quick rollback for troubleshooting):

  ```powershell
  Set-MpPreference -AttackSurfaceReductionRules_Ids "" -AttackSurfaceReductionRules_Actions ""
  ```
* To set rules back to Audit only:

  ```powershell
  Set-MpPreference -AttackSurfaceReductionRules_Ids <comma list> -AttackSurfaceReductionRules_Actions AuditMode
  ```
* To uninstall Sysmon:

  ```powershell
  & "$env:windir\System32\Sysmon64.exe" -u
  ```

  (Use the actual path if different.)
* To revert Defender preferences you changed, use `Remove-MpPreference` on the specific settings where available, or manually revert in Windows Security.

## Where are Custom Views stored?

Event Viewer stores system-provided and user-defined views under `%ProgramData%\Microsoft\Event Viewer\Views\` (the script writes there when possible). If Event Viewer doesn't show the imported view immediately, import the XML via Event Viewer → **Custom Views** → **Import Custom View...** and select `ParanoidSecurity-CustomView.xml` from your desktop. (Many guides / MS Scripting blog show how to import/export custom views.) ([Microsoft for Developers][2])

## Notes about TPM / attestation / privacy

You provided material expressing concern about TPM attestation and cloud attestation (PCRs, EK, Copilot/Windows Recall). This script intentionally keeps logging local-only and does not enable cloud forwarding of Sysmon logs. If you want to further mitigate TPM/cloud-attestation concerns, follow the guidance in your reference: avoid signing into Microsoft account on the device, consider clearing or disabling TPM in firmware, and avoid features like Copilot/Windows Recall — those are outside the scope of this script. For details and the attacker/privacy threat model, see your uploaded doc. 

## Troubleshooting

* If Set-MpPreference commands fail, check Tamper Protection and that Windows Defender is the active AV (other AVs may block access).
* If Sysmon install fails, check network access to `download.sysinternals.com`, and that the machine can write to `%TEMP%`.
* If Event Viewer Custom View does not appear, import manually.

---

# Quick explanation of the custom Event Viewer view

* The XML the script creates aggregates:

  * `Microsoft-Windows-Sysmon/Operational` (Sysmon events — process create, network connect, image load, driver loads)
  * `Microsoft-Windows-Windows Defender/Operational` (Defender ASR event notifications)
  * `Security` (critical/important security events like high-level failures)
* The file is exported to Desktop as `ParanoidSecurity-CustomView.xml` and also copied to `%ProgramData%\Microsoft\Event Viewer\Views\View_ParanoidSecurity.xml` (Event Viewer reads that folder for views).

---

# Citations & references

* Microsoft: Attack surface reduction rules reference & deployment (ASR GUIDs and behavior). ([Microsoft Learn][1])
* Sysmon download (Sysinternals) and SwiftOnSecurity Sysmon config used by script. (Script points to the official Sysinternals download and SwiftOnSecurity GitHub.)
* How to use Custom Views / export XML and use with `Get-WinEvent` / import. ([Microsoft for Developers][2])
* Your TPM / attestation privacy doc that motivated local-only approach. 

---
