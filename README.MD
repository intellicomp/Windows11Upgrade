# Windows 11 Upgrade Script

This repository contains a PowerShell script designed to automate the upgrade process to a specified version of Windows 11. The script handles downloading the ISO, verifying its integrity, extracting its contents, running the upgrade process, and setting up a post-reboot script for verification.

## Features
- Supports upgrades to specific Windows 11 versions (for now version 24H2 only).
- Verifies the Windows version post-reboot using the `RunOnce` registry key.
- Handles unsupported hardware upgrades (experimental).
- Logs all actions to a specified log file.
- Automatically cleans up temporary files and folders after the upgrade.

## Parameters
- **`-InPlaceUpgrade`**: Forces an in-place upgrade. (not live yet)
- **`-AllowAfter_4AM`**: Allows the script to run after 4 AM.
- **`-SuppressReboot`**: Prevents the system from rebooting automatically after the upgrade.
- **`-UnsupportedHardware`**: Enables upgrades on unsupported hardware. (uses an experimental feature)
- **`-TargetBuildNumber`**: Specifies the target build number for the upgrade (default: 26100).
- **`-ShowProgress`**: Displays download progress in the console. (do not use when running via NinjaOne)
- **`-LogFilePath`**: Specifies the path to the log file (default: `C:\Win11\Win11Upgrade.log`).

## Usage
### Running Manually
1. Open PowerShell as an administrator.
2. Load the script into memory by running the following:
   ```powershell
    wget -uri 'https://raw.githubusercontent.com/IntelliScripts/Get-AVInfo/master/Get-AVInfo.ps1' -UseBasicParsing | iex
    ```
3. Call the function by running Update-Win11, along with the desired parameters (ensure that the bottom section of the script where parameters are parsed remains commented out). For ex.:
     ```powershell
    Update-Win11 -AllowAfter_4am -SuppressReboot -TargetBuildNumber 26100
    ```

### Running via NinjaOne
1. The bottom section of the script will be uncommented out to allow the script to parse environment variables (chosen using the NinjaOne interface) and execute automatically.
2. Run the NinjaOne automation, selecting the desired options when running.

### Logging
- Logs are written to the specified log file (default: C:\Win11\Win11Upgrade.log). 
- If run manually, logs will also output to the console.
- If executed via NinjaOne, the console logs will appear under the 'Activity' section for the device in question, in the 'Completed' activity for the script (once it finishes running).

- To monitor the script logs in real-time, execute the script, then run the following on the machine:
    ```powershell
    Get-Content 'C:\Win11\Win11Upgrade.log' -Tail 1 -Wait
    ```
- You can also run the following command to monitor in real-time the setupact.log file (which is created and written to by the Windows setup process during the upgrade):
    ```powershell
    Get-Content 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log' -Tail 1 -Wait
    ```
- Once the upgrade is complete, the setupact.log file will also be copied to the log file location specified in the script ("C:\Win11\Win11Upgrade.log" by default). 


## Notes
- Ensure the script is run with administrative privileges.
- Ensure there is enough free space on the system drive for the download (15 GB) and the actual upgrade (10 GB post-download).
- A post reboot check is performed to verify the success of the upgrade by checking the current Windows build number. The script saves a second PowerShell script to the 'C:\Win11' directory, and that script is added to the `RunOnce` Registry key, to run after the next reboot. 
- The second script also checks if Bitlocker is re-enabled on the C: drive and re-enables it if necessary.
- The second script will delete itself after running. The value of the `RunOnce` Registry key is deleted by default before the command is run. 
  - More information on the RunOnce Registry key:
    - *https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-keys-for-windows-setup*



