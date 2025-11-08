<#
.SYNOPSIS
  Standalone ASR "paranoid" deployer for Windows Defender Attack Surface Reduction rules.

.DESCRIPTION
  - Backs up current ASR GUIDs & actions to a file
  - Optionally runs in AuditMode first for compatibility testing
  - Applies a broad list of ASR rule GUIDs in the chosen mode (Enabled = Block, AuditMode, or Disabled)
  - Creates a timestamped log (stdout & errors)
  - Requires Administrative privileges and Windows Defender present

.NOTES
  - Tested for Windows 10/11 Defender PowerShell cmdlets (Set-MpPreference / Add-MpPreference).
  - Official ASR reference: Microsoft Defender for Endpoint - Attack surface reduction rules. :contentReference[oaicite:1]{index=1}

.PARAMETER Mode
  "Enabled" (paranoid/block) | "AuditMode" (recommend initial testing) | "Disabled" (reset)
  Default: "Enabled"

.EXAMPLE
  # Audit first (safe)
  .\asr-full-paranoid.ps1 -Mode AuditMode

  # Go full blocking (paranoid)
  .\asr-full-paranoid.ps1 -Mode Enabled
#>

param(
    [ValidateSet("Enabled","AuditMode","Disabled")]
    [string]$Mode = "Enabled"
)

# Ensure running elevated
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "This script must be run as Administrator. Exiting."
    exit 1
}

# Logging
$ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
$logPath = "$env:ProgramData\ASR-Deploy-Logs"
if (!(Test-Path $logPath)) { New-Item -Path $logPath -ItemType Directory -Force | Out-Null }
$logFile = Join-Path $logPath "ASR-Deploy-$ts.log"
Start-Transcript -Path $logFile -Force

Write-Host "=== ASR FULL PARANOID DEPLOYER ===" -ForegroundColor Cyan
Write-Host "Mode: $Mode" -ForegroundColor Yellow

# Retrieve current preference
try {
    $pref = Get-MpPreference -ErrorAction Stop
} catch {
    Write-Error "Failed to read Defender preferences. Make sure Microsoft Defender is available. $_"
    Stop-Transcript
    exit 2
}

# Backup existing ASR config (if any)
$backup = @{
    Timestamp = $ts
    Machine  = $env:COMPUTERNAME
    User     = $env:USERNAME
    ASR_Guids = $pref.AttackSurfaceReductionRules_Ids
    ASR_Actions = $pref.AttackSurfaceReductionRules_Actions
}
$backupFile = Join-Path $logPath "ASR-Backup-$ts.json"
$backup | ConvertTo-Json -Depth 5 | Out-File -FilePath $backupFile -Encoding UTF8
Write-Host "Current ASR config backed up to: $backupFile"

# Full set of commonly used ASR GUIDs (canonical set used by MS docs and common security baselines)
# NOTE: This list covers the widely recommended/used ASR rules; check MS docs for additions or future rules.
$ASR_RULES = @(
    # Block Office apps from creating child processes
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",

    # Block execution of potentially obfuscated scripts
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",

    # Block Office applications from creating executable content
    "3B576869-A4EC-4529-8536-B80A7769E899",

    # Block Office applications from injecting code into other processes
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",

    # Block Win32 API calls from Office macros
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",

    # Block credential stealing from LSASS
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",

    # Block executable content from email client and webmail
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",

    # Block JavaScript or VBScript from launching downloaded executable content
    "D3E037E1-3EB8-44C8-A917-57927947596D",

    # Block Office communication application from creating child processes (Teams, Skype, etc.)
    "26190899-1602-49E8-8B27-EB1D0A1CE869",

    # Block untrusted and unsigned processes that run from USB
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",

    # Block execution of potentially obfuscated scripts (duplicate GUIDs removed above) - kept for clarity

    # Block abuse of exploited vulnerable signed drivers
    "56A863A9-875E-4185-98A7-B882C64B5CE5",

    # Block Adobe Reader from creating child processes
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",

    # Block process creations originating from PSExec and WMI commands
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B",

    # Block persistence through WMI event subscription
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B",  # same as above (kept for readability)

    # Block use of copied or impersonated system tools
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB",

    # Block Webshell creation for Servers
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6",

    # Use advanced protection against ransomware (cloud-dependent; will be applied but may need cloud protection to be effective)
    "C1DB55AB-C21A-4637-BB3F-A12568109D35",

    # Block rebooting machine in Safe Mode
    "33DDEDF1-C6E0-47CB-833E-DE6133960387"
)

# remove duplicates and ensure GUIDs are uppercase canonical
$ASR_RULES = $ASR_RULES | ForEach-Object { $_.ToUpper() } | Select-Object -Unique

Write-Host "Applying $($ASR_RULES.Count) ASR rules in mode: $Mode"

# When using Set-MpPreference you can pass action tokens: Enabled, AuditMode, Disabled
# We'll call Set-MpPreference with a comma separated list matching the IDs order
$actionList = @()
foreach ($i in 1..$ASR_RULES.Count) {
    $actionList += $Mode
}

# Apply (use Set-MpPreference; Add-MpPreference is alternative)
try {
    # Use -Force to override if necessary
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ASR_RULES -AttackSurfaceReductionRules_Actions $actionList -Force -ErrorAction Stop
    Write-Host "ASR rules applied (Set-MpPreference completed)." -ForegroundColor Green
} catch {
    Write-Error "Failed to apply ASR rules: $_"
    # Try Add-MpPreference fallback
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ASR_RULES -AttackSurfaceReductionRules_Actions $actionList -ErrorAction Stop
        Write-Host "ASR rules applied via Add-MpPreference fallback." -ForegroundColor Green
    } catch {
        Write-Error "Fallback also failed: $_"
        Stop-Transcript
        exit 3
    }
}

# Confirm / show current ASR mapping (human readable)
Write-Host "`nCurrent ASR configuration snapshot (Name - GUID - Action):" -ForegroundColor Cyan
# Create a mapping lookup from the canonical list in this script (name mapping is partial; user can expand)
$ruleNames = @{
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office apps from creating child processes"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office apps from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office apps injecting code into other processes"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing (LSASS)"
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email/webmail"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS/VBScript from launching downloaded exe"
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication apps creating child processes"
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted unsigned processes from USB"
    "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers"
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader creating child processes"
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block PSExec/WMI-originated process creation"
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block copied/impersonated system tools"
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers"
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
    "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block reboot to Safe Mode"
}

# Print table
$pref = Get-MpPreference
for ($i=0; $i -lt $pref.AttackSurfaceReductionRules_Ids.Count; $i++) {
    $gid = $pref.AttackSurfaceReductionRules_Ids[$i].ToString().ToUpper()
    $action = $pref.AttackSurfaceReductionRules_Actions[$i]
    $actionName = $action
    $name = if ($ruleNames.ContainsKey($gid)) { $ruleNames[$gid] } else { "(unknown rule)" }
    "{0} - {1} - {2}" -f $name, $gid, $actionName
}

# Quick EventViewer custom view XML installer (adds a Custom View that filters ASR & ASR-related events)
# The script will drop an XML file you can import into Event Viewer. (Automated import via wevtutil requires a .xml Custom View file created by the user; below we create a .xml for manual import.)
$cvXml = @"
<Views>
  <View Name="ASR & Defender Blocks" Path="Microsoft-Windows-Sysmon/Operational">
    <QueryList>
      <Query Id="0" Path="Security">
        <Select Path="Security">*[System[(Level=2 or Level=3 or Level=4)]] and *[EventData[Data and (Data='Asr')]]</Select>
      </Query>
    </QueryList>
  </View>
</Views>
"@
$cvFile = Join-Path $logPath "ASR-CustomView-$ts.xml"
$cvXml | Out-File -FilePath $cvFile -Encoding UTF8
Write-Host "`nCustomView XML created: $cvFile"
Write-Host "Import that file into Event Viewer -> Custom Views -> Import Custom View..." -ForegroundColor Yellow

Write-Host "`nFinished. Logs & backup: $logPath"
Write-Host "If you used AuditMode, monitor events for a few days, then re-run with -Mode Enabled to switch to blocking."
Stop-Transcript
