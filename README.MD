## Windows 11 Upgrade Script

This PowerShell script automates Windows feature upgrades through ISO media or an eligible enablement package.
It can run interactively or through NinjaOne.

Built-in target builds:

- Windows 10 22H2 (19045, x64)
- Windows 11 24H2 (26100)
- Windows 11 25H2 (26200)
- Windows 11 26H2 (26300, default)

Available ISO editions, architectures, and languages vary by build. Windows 10 media is x64-only; ARM64 Home media
is not included. The script validates built-in media using its expected hash and size.

Other capabilities include same-build in-place repairs, custom ISO URLs, optional sleep prevention, download and
extract-only preparation for DISM, BITS download retries with Invoke-WebRequest fallback, and upgrade logging.

## Enablement Packages

With `-EnablementPackage`, the script selects a package by target build, source build, and architecture. Supported
paths and minimum revisions are:

- 24H2 (26100.5074 or later) to 25H2 (26200)
- 24H2 (26100.9168 or later) to 26H2 (26300)
- 25H2 (26200.9168 or later) to 26H2 (26300)

The package hash and size are checked, and Windows servicing events are used to verify installation, including
reboot-required and already-installed outcomes. If no compatible package is available or prerequisites are not met,
the script falls back to ISO media. Enablement packages cannot be combined with `-InPlaceUpgrade`; the
`-RebootAfterUpgrade` parameter does not apply to enablement-package installs.

## Parameters

- `-InPlaceUpgrade`: Uses media matching the installed build for an in-place repair. Not compatible with
  `-EnablementPackage`.
- `-RebootAfterUpgrade`: Restarts after a successful ISO-based upgrade is confirmed. Otherwise, reboot manually.
- `-UnsupportedHardware`: Adds Setup's experimental `/product server` switch.
- `-TargetBuildNumber`: Selects 19045, 26100, 26200, or 26300. Defaults to 26300.
- `-CustomISOUrl`: Downloads the specified ISO and bypasses built-in compatibility, hash, and size checks. It also
  permits same-build repair media with a newer sub-build.
- `-SkipValidation`: Uses an ISO already at `C:\Win11\Win11.iso` without hash or size checks and extracts it again.
- `-ShowProgress`: Displays ISO download progress in the console; avoid using it with NinjaOne activity logging.
- `-MonitorProgress`: Writes Setup progress to `C:\Win11\ProgressResults.log` while Setup runs.
- `-EnablementPackage`: Uses an eligible enablement package; otherwise falls back to ISO media.
- `-DisableSleepDuringUpgrade`: Saves current AC/DC sleep timeouts, disables sleep, then restores the settings.
- `-DownloadAndExtractOnly`: Downloads and extracts media to `C:\Win11\SetupFolder` without starting Setup. Writes
  `C:\Win11\DO_NOT_AUTO_DELETE.txt` to prevent controller cleanup.
- `-LogFilePath`: Sets the main log path. Defaults to `C:\Win11\Win11Upgrade.log`.

Custom ISO URLs bypass validation. Confirm the ISO's architecture, edition, language, and suitability before using
one. `-AllowAfter_4AM` and `-SuppressReboot` are inactive in the current script.

## Usage

### Run Manually

Run PowerShell as Administrator. Load the function by dot-sourcing the script, or download it into memory:

```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/intellicomp/Windows11Upgrade/refs/heads/main/Windows%2011%20Upgrade.ps1' `
    -UseBasicParsing | Invoke-Expression
```

Examples:

```powershell
Update-Win11 -RebootAfterUpgrade
Update-Win11 -TargetBuildNumber 26200 -EnablementPackage
Update-Win11 -EnablementPackage
Update-Win11 -DownloadAndExtractOnly -TargetBuildNumber 26300
Update-Win11 -CustomISOUrl 'https://example.com/Windows11.iso'
```

The default target is 26H2 (26300). Pass `-TargetBuildNumber 26200` to target 25H2.

### Run via NinjaOne

The script's bottom section maps NinjaOne environment variables to the function parameters and invokes the upgrade.
Configure the variables there to select the target build and options. When `ApplyAutomationControls` is `true`, the
script runs only when `windowsMajorVersionUpgradeState` is `Ready to run upgrade script`. The script also increments
`windowsMajorVersionUpgradeAttemptCount`.

## Logging and Monitoring

- Main log: `C:\Win11\Win11Upgrade.log` by default
- Windows Setup source log: `C:\$WINDOWS.~BT\Sources\Panther\setupact.log`
- Copied Setup log: `C:\Win11\Windows11SetupLogs\Panther\setupact.log`
- Setup progress log with `-MonitorProgress`: `C:\Win11\ProgressResults.log`

Follow the main or Setup log in real time:

```powershell
Get-Content 'C:\Win11\Win11Upgrade.log' -Tail 1 -Wait
Get-Content 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log' -Tail 1 -Wait
```

The script generates three helper scripts in `C:\Win11`:

- `Show-BitsProgress.ps1`: Shows BITS transfer progress.
- `Show-UpgradeProgress.ps1`: Shows Setup progress and can optionally display the last Setup log line.
- `Invoke-SpeedTest.ps1`: Runs Ookla Speedtest during the download stage.

These helpers are removed during script cleanup. A separate stop-helper script is not generated by the current script.

## Upgrade and Reboot Behavior

ISO-based upgrades run Setup with `/noreboot`. After Setup completes, the script checks its logs, updates the NinjaOne
upgrade-state custom field to a pending-reboot state, and suspends BitLocker for one reboot. It restarts only when
`-RebootAfterUpgrade` is specified; otherwise, an operator must restart the device.

Pending-reboot custom-field updates preserve an existing manual-intervention prefix, when present. The script also
leaves setup files in place for controller cleanup after reboot and build verification.