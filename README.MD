# Windows 11 Upgrade Script

This repository contains a PowerShell script that automates Windows feature upgrades using either ISO media or, when eligible, a Windows 11 enablement package.

## Features
- Supports target build upgrades for:
    - Windows 10 22H2 (19045, ESU use case)
    - Windows 11 24H2 (26100)
    - Windows 11 25H2 (26200)
- Supports in-place repair scenarios with matching build media.
- Supports custom ISO URLs when you want to bypass built-in media selection and validation.
- Optional enablement package path for eligible 24H2 to 25H2 upgrades.
- Optional download/extract-only mode for DISM or manual setup use.
- Writes logs to file and console (interactive) and supports progress monitoring helpers.

## Parameters
- **-InPlaceUpgrade**
    Forces an in-place repair/upgrade path using matching-build media.

- **-RebootAfterUpgrade**
    Reboots the machine after a successful upgrade check. If omitted, the script leaves rebooting to the operator.

- **-UnsupportedHardware**
    Adds the setup switch for unsupported hardware scenarios (experimental).

- **-TargetBuildNumber**
    Target build number. Allowed values: 19045, 26100, 26200. Default: 26200.

- **-CustomISOUrl**
    Uses a manually provided ISO URL and skips built-in compatibility/hash/size validation.

- **-ShowProgress**
    Shows transfer progress in console output. Not recommended for NinjaOne activity logs.

- **-MonitorProgress**
    Writes upgrade-progress telemetry to C:\Win11\ProgressResults.log while setup is running.

- **-EnablementPackage**
    Attempts enablement package upgrade when eligible.
    Current supported path is 24H2 (26100) to 25H2 (26200), with minimum CU requirements.
    If requirements are not met, the script falls back to ISO method.

- **-DisableSleepDuringUpgrade**
    Temporarily disables sleep during execution and restores original settings afterwards.

- **-DownloadAndExtractOnly**
    Downloads and extracts setup files to C:\Win11\SetupFolder, then exits without running setup.
    Creates C:\Win11\DO_NOT_AUTO_DELETE.txt as a marker.

- **-SkipValidation**
    For manually supplied ISO files already present on disk, skips hash/size checks.

- **-LogFilePath**
    Log path. Default: C:\Win11\Win11Upgrade.log.

## Usage

### Run Manually
1. Open PowerShell as Administrator.
2. Load the latest script into memory:

```powershell
wget -Uri 'https://raw.githubusercontent.com/intellicomp/Windows11Upgrade/refs/heads/main/Windows%2011%20Upgrade.ps1' -UseBasicParsing | iex
```

3. Run the function with desired options. Examples:

```powershell
Update-Win11 -TargetBuildNumber 26200 -RebootAfterUpgrade
```

```powershell
Update-Win11 -EnablementPackage -TargetBuildNumber 26200
```

```powershell
Update-Win11 -DownloadAndExtractOnly -TargetBuildNumber 26200
```

### Use a Custom ISO URL

```powershell
Update-Win11 -CustomISOUrl "https://software.download.prss.microsoft.com/dbazure/Win11_25H2_English_x64.iso?t=..." -TargetBuildNumber 26200
```

When -CustomISOUrl is used, validation checks are intentionally skipped. Verify architecture, language, and edition compatibility before use.

### Run via NinjaOne
1. Use the script with the environment-variable parsing section enabled (bottom of script).
2. Configure NinjaOne script variables (true/false and values) to map to the same switches.
3. Run automation.

## Logging and Monitoring
- Main log (default): C:\Win11\Win11Upgrade.log
- Setup log source: C:\$WINDOWS.~BT\Sources\Panther\setupact.log
- Copied setup logs: C:\Win11\Windows11SetupLogs\Panther\setupact.log

Real-time main log:

```powershell
Get-Content 'C:\Win11\Win11Upgrade.log' -Tail 1 -Wait
```

Real-time setup log:

```powershell
Get-Content 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log' -Tail 1 -Wait
```

Helper scripts generated in C:\Win11 during execution:
- Show-BitsProgress.ps1
- Show-UpgradeProgress.ps1
- Invoke-SpeedTest.ps1

These helper scripts are removed by the script after completion.

## Notes
- Run with administrative privileges.
- Ensure sufficient disk space for both media handling and upgrade staging.
- The script runs setup with /noreboot and then either:
    - reboots only when -RebootAfterUpgrade is specified, or
    - leaves reboot as a manual action.
- AllowAfter_4AM and SuppressReboot are currently not active parameters in this live script version.