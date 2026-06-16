# Enable strict mode
# Set-StrictMode -Version Latest
    
function Update-Win11 {
    <#
.SYNOPSIS
Upgrades a Windows machine to a specified version of Windows 11.

.DESCRIPTION
This script is designed to upgrade a Windows machine to a specified version of Windows 11 (or Windows 10 for ESU). It handles downloading the ISO, verifying its integrity, extracting its contents, running the upgrade process (and setting up the post reboot script (see the notes section)). 
The script can be run either manually or via NinjaOne.

.PARAMETER InPlaceUpgrade
Specifies whether to force an in-place upgrade. Set this to 'true' to enable.

#.PARAMETER AllowAfter_4AM
Allows the script to run after 4 AM. If not set, the script will exit if the current time is after 4 AM.

#.PARAMETER SuppressReboot
Prevents the system from rebooting automatically after the upgrade. If not set, the system will reboot automatically.
NOTE: This controls the reboot behavior initiated manually by the script post-upgrade; the upgrade itself is always run with the /noreboot switch.

.PARAMETER RebootAfterUpgrade
If specified, the script will reboot the system after a successful upgrade (once the upgrade is confirmed and setup.exe has exited).
Note: The upgrade itself is always run with the /noreboot switch; this parameter initiates a manual (non-setup.exe-related) POST-upgrade reboot.

.PARAMETER UnsupportedHardware
Allows upgrades to run on non-supported hardware by using the '/product server' switch when calling setup.exe. Note, this is an experimental feature and may not work as expected.

.PARAMETER TargetBuildNumber
Specifies the target build number for the upgrade. Defaults to '26200' (Windows 11 25H2).

.PARAMETER CustomISOUrl
Specifies a custom ISO download URL instead of using the built-in ISO table.
When this parameter is used, all validation checks (hash, size, and compatibility) are skipped.
This is useful for downloading the latest ISO builds directly from Microsoft or other sources.
The version check is also bypassed when using a custom ISO URL, allowing in-place repairs with newer sub-builds (so no need to use the InPlaceUpgrade parameter even when the ISO version matches the installed version).
Bottom line: The script assumes you know what you're doing when you feed it a custom ISO! Ensure the custom ISO is compatible with the target system (architecture, edition, language).

.PARAMETER SkipValidation
When specified, the script will skip validation checks (hash, size) for manually-provided ISO files.
So if you download or transfer your own ISO file to the machine, the script will not check its hash or size and will proceed with extracting it and the upgrade.

.PARAMETER ShowProgress
Displays the download progress in the console. 
This is not recommended for use with NinjaOne as it will clutter the Ninja Activity logs. Use when running the script interactively on a machine.

.PARAMETER MonitorProgress
Enables monitoring of the ISO download and upgrade progress. Progress is logged to a log file that can be viewed realtime in the console using Get-Content, in conjunction with the tail and wait parameters.

.PARAMETER EnablementPackage
Specifies to use an enablement package for the upgrade. NOTE: This cannot be used to upgrade from versions prior to Windows 11 24H2.

.PARAMETER DisableSleepDuringUpgrade
Prevents the system from entering sleep mode during the upgrade process.
When this parameter is set, the script will modify the system's power settings to disable sleep on both AC and battery power before starting the upgrade process, and will restore the original power settings after the upgrade is complete.

.PARAMETER DownloadAndExtractOnly
When specified, the script will download and extract the ISO file only, without running the upgrade.
This is useful for preparing the installation media for DISM RestoreHealth operations or for manual upgrades.
The extracted ISO contents will be available at C:\Win11\SetupFolder\ and can be used with DISM commands like:
Dism /Online /Cleanup-Image /RestoreHealth /Source:C:\Win11\SetupFolder\sources\install.wim:1 /LimitAccess

.PARAMETER LogFilePath
Specifies the path to the log file where the script will write its logs. Defaults to 'C:\Win11\Win11Upgrade.log'.

.EXAMPLE
Run the script manually with default parameters.
Update-Win11

.EXAMPLE
Run the script manually with specific parameters.
Update-Win11 -TargetBuildNumber 26200

.EXAMPLE
Download and extract the ISO only (for DISM RestoreHealth operations for ex.).
Update-Win11 -DownloadAndExtractOnly -TargetBuildNumber 26200

.Example
Run the script via NinjaOne.
Un-comment the bottom section of the script and deploy it via NinjaOne.

.LINK
https://github.com/intellicomp/Windows11Upgrade

.NOTES
The script is designed to be run either manually or via NinjaOne.
When run manually, the bottom section of the script (where parameters are parsed and the 'Update-Win11' function is called) should be commented out. Just load the script in a shell, press enter, then call the function with the desired parameters (see the first two examples).
When run via NinjaOne, the bottom section is uncommented to allow the script to parse environment variables (selected using the NinjaOne interface) and execute automatically.

You can also run the code below to download and load the script into memory. Then you can call the function by running Update-Win11, along with the desired parameters.
"wget -uri 'https://raw.githubusercontent.com/intellicomp/Windows11Upgrade/refs/heads/main/Windows%2011%20Upgrade.ps1' -UseBasicParsing | iex"

LOGGING
Logs will be written to the specified log file (the default is: "C:\Win11\Win11Upgrade.log"). If run manually, logs will also output to the console.
If executed via NinjaOne, the console logs will appear under the 'Activity' section for the device in question, in the 'Completed' activity for the script (once it finishes running).

MONITORING THE LOGS IN REAL-TIME
To monitor the script logs in real-time (either from the machine or via a remote Ninja powershell session), run the following command:
Get-Content 'C:\Win11\Win11Upgrade.log' -Tail 1 -Wait
This command will display the log file's contents one line at a time as new entries are added.

You can also run the following command to monitor in real-time the setupact.log file (which is created and written to by the Windows setup process during the upgrade):
Get-Content 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log' -Tail 1 -Wait
(Once the upgrade is complete, the setupact.log file will also be copied to the log file location specified in the script ("C:\Win11\Win11Upgrade.log" by default). 

Monitoring the ISO download and upgrade progress (separate from the Win11Upgrade.log script logging- the script logs don't include progress updates on the download or upgrade process itself):
Three helper scripts are written to C:\Win11 during execution:
- Show-BitsProgress.ps1: Monitors BITS download progress of the ISO file. Run manually to view real-time download status.
- Show-UpgradeProgress.ps1: Monitors Windows setup upgrade progress. Run manually to view upgrade percentage in real-time.
- Invoke-SpeedTest.ps1: Runs an Ookla speed test from the console during the download stage.
All helper scripts are automatically removed after the upgrade completes.
Note: The execution policy must be set to something other than 'Restricted' to run these scripts. You can change it by running: 'Set-ExecutionPolicy Bypass -Scope Process' before executing the progress scripts.

====================================================================================================
DATE CREATED: April 2025
LAST UPDATED: 3/2/2026
PURPOSE: Script the Windows upgrade process to a specified version of Windows 11.
NOTES: This script is designed for use in both manual and automated environments (e.g., NinjaOne).
Comments and suggestions welcome!
-THH
====================================================================================================
#>
    [CmdletBinding()]
    param (
        # Parameter to force an in-place upgrade
        [Parameter(Mandatory = $false)]
        [switch]$InPlaceUpgrade,

        # Parameter to allow the script to run after 4 AM
        # <This parameter is NOT currently in use in the script. The script will run regardless of the time of day.>
        #[Parameter(Mandatory = $false)]
        #[switch]$AllowAfter_4AM,

        # <<<This parameter is NOT currently in use in the script. The script does not initiate reboots on its own.>>>
        # Parameter to supress the reboot after the upgrade. 
        # NOTE: This controls the reboot behavior initiated manually by the script post-upgrade; the upgrade itself is always run with the /noreboot switch.
        #[Parameter(Mandatory = $false)]
        #[switch]$SuppressReboot,

        # Parameter to reboot the system after a successful upgrade
        # Note: The upgrade itself is always run with the /noreboot switch; this parameter initiates a manual POST-upgrade reboot only.
        # The SuppressReboot parameter does not currently do anything in this script and will have no affect on the manual reboot caused by the RebootAfterUpgrade parameter.
        [Parameter(Mandatory = $false)]
        [switch]$RebootAfterUpgrade,

        # Parameter for using an experimental feature to allow upgrades on unsupported hardware
        [Parameter(Mandatory = $false)]
        [switch]$UnsupportedHardware,

        # Parameter to specify the target build number for the upgrade, default is 26200 (Windows 11 25H2)
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            # Windows 10 version 22H2 is included in the script for ESU, since to be eligible for the ESU program devices must be running Windows 10, version 22H2
            # https://learn.microsoft.com/en-us/windows/whats-new/enable-extended-security-updates#:~:text=Device%20requirements%3A
            19045, # Windows 10 22H2 / Release date October 18, 2022
            # 22621, # Windows 11 22H2 / Release date September 20, 2022
            # 22631, # Windows 11 23H2 / Release date October 31, 2023
            26100, # Windows 11 24H2 / Release date October 1, 2024
            26200 # Windows 11 25H2 / Release date September 30, 2025
        )]
        [int]$TargetBuildNumber = 26200,

        # Custom ISO URL to download instead of using built-in ISO table (skips all validation checks)
        [Parameter(Mandatory = $false)]
        [string]$CustomISOUrl,

        # Parameter to show download progress in the console (not for use with NinjaOne)
        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress,

        # Parameter to monitor the progress of the upgrade process in a log file
        [switch]$MonitorProgress,

        # Parameter to use an enablement package for the upgrade (i.e., a cumulative update that turns on existing-but-hidden features)
        # https://support.microsoft.com/en-us/topic/description-of-the-windows-update-standalone-installer-in-windows-799ba3df-ec7e-b05e-ee13-1cdae8f23b19#bkmk_wusa_switches
        # < NOT available for upgrading to version 24H2 >
        [Parameter(Mandatory = $false)]
        [switch]$EnablementPackage,

        # Parameter to disable sleep during the upgrade process
        [Parameter(Mandatory = $false)]
        [switch]$DisableSleepDuringUpgrade,

        # Parameter to download and extract the ISO only, without running the upgrade
        [Parameter(Mandatory = $false)]
        [switch]$DownloadAndExtractOnly,

        # Parameter to skip validation checks (hash, size) for manually-provided ISO files
        [Parameter(Mandatory = $false)]
        [switch]$SkipValidation,

        # Parameter to specify the path for the log file, default is C:\Win11\Win11Upgrade.log
        [Parameter(Mandatory = $false)]
        [Validatescript({
                param($Path)
                $directory = Split-Path -Path $Path -Parent
                if (-not (Test-Path -Path $directory)) {
                    throw "The directory '$directory' does not exist. Please provide a valid path."
                }
            })]
        [string]$LogFilePath = "C:\Win11\Win11Upgrade.log"
    )
    
    begin {}
    
    process {
        #region functions
        function Write-Log {
            param(
                [Parameter(Mandatory = $false)] # set to false to allow for the $BlankLine switch
                [string]$Message,
        
                [Parameter(Mandatory = $false)]
                [string]$LogPath = $LogFilePath,
        
                [Parameter(Mandatory = $false)]
                [ValidateSet("Info", "Warning", "Error", "Debug")]
                [string]$Severity = "Info",

                [Parameter(Mandatory = $false)]
                [switch]$BlankLine,

                [Parameter(Mandatory = $false)]
                [switch]$IsHeading,

                [Parameter(Mandatory = $false)]
                [switch]$IsPhaseMarker
            )

            if ($BlankLine) {
                Write-Host ""
                try {
                    Add-Content -Path $LogPath -Value ""
                }
                catch {
                    Write-Host "Failed to write blank line to log file." -ForegroundColor Red
                }
                return
            }
    
            if ($IsHeading -or $IsPhaseMarker) {
                if ($IsHeading) {
                    $formattedMessage = "`n========== $Message =========="
                    $errorType = "heading"
                }
                else {
                    $formattedMessage = "========== $Message =========="
                    $errorType = "phase marker"
                }
                
                Write-Host $formattedMessage
                try { 
                    Add-Content -Path $LogPath -Value $formattedMessage -ErrorAction Stop
                }
                catch {
                    Write-Host "Failed to write $errorType to log file." -ForegroundColor Red 
                }
                return
            }
            
            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $LogEntry = "[$Timestamp] [$Severity] $Message"
        
            switch ($Severity) {
                "Warning" {
                    # Write-Warning "[$Timestamp] $Message"
                    Write-Host "[$Timestamp] $Message" -ForegroundColor Yellow
                }
                "Error" {
                    Write-Host "[$Timestamp] $Message" -ForegroundColor Red
                }
                "Progress" {
                    # Only output to the console, do not write to the log file
                    Write-Host -NoNewline "[$Timestamp] $Message"
                }
                "Debug" {
                    Write-Host "[$Timestamp] $Message" -ForegroundColor Cyan
                }
                default {
                    Write-Host "[$Timestamp] $Message"
                }
            } # switch

            try {
                Add-Content -Path $LogPath -Value $LogEntry -ErrorAction Stop
            }
            catch {
                Write-Host "Failed to write to log file." -ForegroundColor Red
            }
        } # function Write-Log

        function Remove-ProgressHelperScripts {
            Remove-Item 'C:\Win11\Show-BitsProgress.ps1', 'C:\Win11\Show-UpgradeProgress.ps1', 'C:\Win11\Invoke-SpeedTest.ps1' -Force -ErrorAction SilentlyContinue
        } # end function Remove-ProgressHelperScripts

        function Download-File {
            <#
            .SYNOPSIS
            Function for downloading a file from the web and saving it to the specified destination.
        
            .DESCRIPTION
            This function downloads a file from the specified URL and saves it to the provided destination path. 
            It first checks if the file already exists at the destination. If the file exists, it verifies the hash 
            (if provided) to determine whether to skip the download or re-download the file. The function attempts 
            to use BITS for downloading and falls back to Invoke-WebRequest if BITS fails. Optional logging is supported.
        
            .PARAMETER SourceUrl
            The URL of the file to download. Accepts pipeline input by value.
        
            .PARAMETER Destination
            The local path where the file will be saved. Accepts pipeline input by property name.
        
            .PARAMETER ExpectedHash
            The expected SHA256 hash of the file. If provided, the function verifies the hash of the downloaded 
            or existing file.
        
            .PARAMETER LogFile
            The path to a log file where success or error messages will be written.
        
            .EXAMPLE
            # Input by value
            "https://example.com/file.zip" | Download-File -Destination "C:\Temp\file.zip"
        
            .EXAMPLE
            # Input by property name using a PSCustomObject (direct creation)
            [PSCustomObject]@{
                SourceUrl = "https://example.com/file.zip"
                Destination = "C:\Temp\file.zip"
                ExpectedHash = "ABC123..."
            } | Download-File
        
            # Alternate way of casting a hashtable to a PSCustomObject
            $Hash = @{
                SourceUrl = "https://example.com/file.zip"
                Destination = "C:\Temp\file.zip"
                ExpectedHash = "ABC123..."
            }
            [PSCustomObject]$Hash | Download-File   
        
            .NOTES
            Author: THH
            Date: April 9, 2025
            #>
        
        
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] # Accepts pipeline input by value or property name
                [ValidateNotNullOrEmpty()]
                [string]$SourceUrl,
        
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)] # Accepts pipeline input by property name
                [ValidateNotNullOrEmpty()]
                [string]$Destination,
        
                [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)] # Accepts pipeline input by property name
                [string]$ExpectedHash,
        
                [Parameter(Mandatory = $false)]
                [string]$LogFile,

                [Parameter()]
                [switch]$UseBrowserHeaders # not yet implemented
            )
        
            begin {
                Write-Log "Executing file download process."
                # $downloadStartTime = Get-Date

                # Browser-like headers for downloads that require them
                $browserHeaders = @{
                    'User-Agent'      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
                    'Accept'          = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
                    'Accept-Language' = 'en-US,en;q=0.9'
                    'DNT'             = '1'
                }
            }

            process {
                Write-Log "SourceUrl: $SourceUrl"
                Write-Log "Destination: $Destination"
                
                if ($ExpectedHash) {
                    # Write-Log "ExpectedHash: $ExpectedHash"
                }
                
                if ($LogFile) {
                    Write-Log "LogFile: $LogFile"
                }
        
                if (-not $SourceUrl.StartsWith("http")) {
                    Write-Log -Severity Error -Message "Invalid SourceUrl: $SourceUrl. The URL must start with 'http' or 'https'."
                    Write-Log "Exiting with exit code 1."
                    Remove-ProgressHelperScripts
                    exit 1
                }
                
                if (-not (Test-Path -Path (Split-Path -Path $Destination -Parent))) {
                    Write-Log -Severity Error -Message "Invalid Destination: $Destination. The directory does not exist."
                    Write-Log "Exiting with exit code 1."
                    Remove-ProgressHelperScripts
                    exit 1
                }
        
                # Check if the file already exists
                if (Test-Path -Path $Destination) {
                    Write-Log "File already exists at $Destination."
        
                    # If a hash is provided, verify the existing file's hash
                    if ($ExpectedHash) {
                        Write-Log "Verifying hash of the existing file."
                        $ActualHash = (Get-FileHash -Path $Destination -Algorithm SHA256).Hash
                        if ($ActualHash -eq $ExpectedHash) {
                            Write-Log "Existing file matches the expected hash. Skipping download."
                            if ($LogFile) {
                                Write-Log "Success: File already exists and hash verified for $Destination."
                            }
                            return
                        }
                        else {
                            Write-Log -Severity Warning -Message "The file hash does not match the expected hash. Expected: $ExpectedHash, Actual: $ActualHash."
                            Write-Log "Deleting the invalid file and re-downloading it."
                            try {
                                Remove-Item -Path $Destination -Force -ErrorAction Stop   
                            }
                            catch {
                                Write-Log -Severity Warning -Message "Failed to delete the invalid file at $Destination. Error: $($_.Exception.Message)"
                                Write-Log -Severity Info -Message "Exiting with exit code 1."
                                exit 1
                            }
                        }
                    }
                    else {
                        Write-Log "No hash provided. Using the existing file."
                        if ($LogFile) {
                            Write-Log "Success: File already exists at $Destination. No hash verification performed."
                        }
                        return
                    }
                } # if file exists      

                # Clear any existing BITS jobs related to the same destination or source URL
                $existingBitsJobs = Get-BitsTransfer -AllUsers | Where-Object {
                    $_.FileList -and $_.FileList.Count -gt 0 -and (
                        $_.FileList[0].LocalName -eq $Destination -or
                        $_.FileList[0].RemoteName -eq $SourceUrl
                    )
                }
        
                if ($existingBitsJobs) {
                    Write-Log "Found existing BITS jobs related to this script's destination or source URL. Removing them..."
                    foreach ($job in $existingBitsJobs) {
                        try {
                            Remove-BitsTransfer -BitsJob $job -Confirm:$false -ErrorAction Stop
                            Write-Log "Removed BITS job with ID: $($job.JobId), created on $($job.CreationTime.ToString('yyyy-MM-dd HH:mm'))."
                        }
                        catch {
                            Write-Log -Severity Warning -Message "Failed to remove BITS job with ID: $($job.JobId). Error: $_"
                        }
                    }
                }
        
                
                # Retry logic for BITS
                $bitsAttempts = 0
                $bitsSuccess = $false

                # Flag to track if progress is displayed (for later use)
                $progressFlag = $false
                # Flag to track if a sleep warning has been issued (for later use)
                $sleepWarningIssued = $false
                
                while ($bitsAttempts -lt 3 -and $bitsSuccess -eq $false) {
                    $bitsAttempts++
                    $downloadStartTime = Get-Date
                    try {
                        Write-Log "Attempting to download using BITS. Attempt $bitsAttempts of 3."
                        $bitsJob = Start-BitsTransfer -Source $SourceUrl -Destination $Destination -Asynchronous -ErrorAction Stop
        
                        Write-Log "BITS job started with ID: $($bitsJob.JobId)"
                        Write-Log "Initial BITS job state: $($bitsJob.JobState)"

                        if ($bitsJob.JobState -like "*Error*") {
                            $errorDetails = ($bitsJob | Get-BitsTransfer).ErrorDescription
                            Write-Log -Severity Warning -Message "The BITS job encountered an error immediately after starting. State: $($bitsJob.JobState). Error: $errorDetails"
                            if ($bitsAttempts -eq 3) {
                                Write-Log -Message "Removing the BITS job."
                            }
                            else {
                                Write-Log -Message "Removing the BITS job, waiting 5 seconds and retrying."
                            }
                            Remove-BitsTransfer -BitsJob $bitsJob -Confirm:$false
                            Start-Sleep -Seconds 5
                            # Continue with the next download attempt
                            continue
                        }
        
                        # Timeout for the job to reach the 'Transferring' state
                        $stateTimeoutSeconds = 30  # Set timeout duration for state transition (e.g., 30 seconds)
                        $stateElapsedTime = 0
                        $stateSleepInterval = 5  # Check every 5 seconds
        
                        while ($bitsJob.JobState -notlike "Transfer*") {
                            if ($stateElapsedTime -ge $stateTimeoutSeconds) {
                                Write-Log -Severity Warning -Message "Timeout reached while waiting for the BITS job to transition to the 'Transferring' state. Exiting."
                                Remove-BitsTransfer -BitsJob $bitsJob -Confirm:$false
                                throw "BITS job did not transition to the 'Transferring' state within $stateTimeoutSeconds seconds."
                            }

                            Start-Sleep -Seconds $stateSleepInterval
                            $stateElapsedTime += $stateSleepInterval
        
                            # Refresh the BITS job object
                            $bitsJob = Get-BitsTransfer -Id $bitsJob.JobId
                            Write-Log "Current BITS job state: $($bitsJob.JobState)"
        
                            # If the job enters an error state, handle it immediately
                            if ($bitsJob.JobState -eq 'Error') {
                                Write-Log -Severity Warning -Message "BITS job encountered an error while waiting for the 'Transferring' state. State: $($bitsJob.JobState)"
                                $errorDetails = ($bitsJob | Get-BitsTransfer).ErrorDescription
                                Write-Log -Severity Warning -Message "Error details: $errorDetails"
                                Remove-BitsTransfer -BitsJob $bitsJob -Confirm:$false
                                throw "BITS job failed to start transferring."
                            }
                        }
        
                        # The section below is to enable progress monitoring for the BITS downloads.
                        # All output to the console also gets into the Ninja Activities log and the progress monitoring can really clog it up so don't use this with Ninja.
                        # If running live on the machine itself, progress will show up in the console and look fine on screen without the clutter.
                        if ($ShowProgress) {
                            if ($bitsJob.JobState -eq 'Transferring') {
                                Write-Log "BITS job transitioned to 'Transferring' state. Monitoring the progress of the download (at the console only)."
                                # # Uncomment the following line to retrieve the process ID of the BITS service host process
                                # $BITSsvchostProcess = Get-Process -ID (Get-CimInstance Win32_Service | Where-Object Name -eq BITS |Select-Object -ExpandProperty ProcessID)
        
                                # Monitor the download progress
                                while ($bitsJob.JobState -eq 'Transferring') {
                                    Start-Sleep -Seconds 5
            
                                    # Refresh the BITS job object
                                    $bitsJob = Get-BitsTransfer -Id $bitsJob.JobId
            
                                    # Access the first file in the FileList to get progress details
                                    $file = $bitsJob.FileList[0]
            
                                    # Calculate progress percentage and file size
                                    $progress = [math]::Round(($file.BytesTransferred / $file.BytesTotal) * 100, 0)
                                    $downloadedMB = [math]::Round($file.BytesTransferred / 1MB, 0)
                                    $totalMB = [math]::Round($file.BytesTotal / 1MB, 0)
            
                                    # Display progress on the same line
                                    $progressFlag = $true
                                    Write-Host -NoNewline "`rDownload progress: $progress% ($downloadedMB MB of $totalMB MB)"
                                }    
                            }
                        } # if run from the console show progress
                        else {
                            # Wait for the BITS job to complete.
                            while ($bitsJob.JobState -eq 'Transferring') {
                                Start-Sleep -Seconds 5
            
                                # Refresh the BITS job object
                                $bitsJob = Get-BitsTransfer -Id $bitsJob.JobId
                            }  
                        } # if !$ShowProgress

                        # Handle non-Transferring states
                        if ($bitsJob.JobState -eq 'Transferred') {
                            Complete-BitsTransfer -BitsJob $bitsJob
                            if ($progressFlag -eq $true) {
                                Write-Host ""    
                            }
                            Write-Log "BITS transfer job complete (including TransientError recovery). File is at $($Destination)."
                            # Set the $bitsSuccess flag to true to exit the BITS While loop and to skip the Invoke-WebRequest block
                            $bitsSuccess = $true

                            $downloadEndTime = Get-Date
                            $downloadDuration = $downloadEndTime - $downloadStartTime
                            Write-Log "Total download time for attempt $($bitsAttempts): $($downloadDuration.ToString('hh\:mm\:ss'))."
                        }
                        elseif ($bitsJob.JobState -like "*Error*") {
                            Write-Log -Severity Warning -Message "BITS job encountered an error. State: $($bitsJob.JobState)"
                            $errorDetails = $bitsJob.ErrorDescription
                            Write-Log -Severity Warning -Message "Error details: $errorDetails"
                            Remove-BitsTransfer -BitsJob $bitsJob -Confirm:$false
                            throw "BITS job failed."
                        }
                        else {
                            Write-Log "BITS job ended with unexpected state: $($bitsJob.JobState)"
                        }
                    } # Try block for BITS
                    catch {
                        <#
                    <Original catch block for BITS>
                    catch {
                        if ($bitsAttempts -lt 3) {
                            Write-Log -Severity Warning -Message "BITS download attempt $bitsAttempts failed. Error: $($_.Exception.Message). Retrying after 5 seconds..."
                            Start-Sleep -Seconds 5
                        }
                        else {
                            Write-Log -Severity Warning -Message "BITS download attempt $bitsAttempts failed. Error: $($_.Exception.Message)."
                            Write-Log -Message "BITS download failed after $bitsAttempts attempts. Falling back to Invoke-WebRequest."
                            $bitsSuccess = $false
                        }
                    } # Catch block for BITS
                    #>
                        # Save the original error message, so that if Complete-BitsTransfer in the next try block fails, the script can output both error messages, 
                        # a) the original error that got the job to the TransientError state in the first place and b) the error from the failed Complete-BitsTransfer attempt.
                        $originalErrorMessage = $_.Exception.Message

                        # Check for specific BITS error messages related to sleep/power/network issues and output sleep warning, but only once per download operation
                        if (-not $sleepWarningIssued -and (
                                $originalErrorMessage -match "The transfer was paused because the computer is in power-saving mode" -or
                                $originalErrorMessage -match "There are currently no active network connections. Background Intelligent Transfer Service \(BITS\) will try again when an adapter is connected.")
                        ) {
                            $sleepWarning = Check-SleepSettings
                            if ($sleepWarning) {
                                Write-Log -Severity Warning -Message $sleepWarning
                            }
                        }

                        # Handle TransientError state
                        if ($bitsJob -and $bitsJob.JobState -eq 'TransientError') {
                            try {
                                # Attempt to complete the BITS transfer and recover from the TransientError state
                                Complete-BitsTransfer -BitsJob $bitsJob
                                Write-Log -Severity Warning -Message "BITS job entered TransientError state, but the transfer was completed successfully. Original error: $originalErrorMessage"
                                $bitsSuccess = $true

                                $downloadEndTime = Get-Date
                                $downloadDuration = $downloadEndTime - $downloadStartTime
                                Write-Log "Total download time for attempt $($bitsAttempts): $($downloadDuration.ToString('hh\:mm\:ss'))."
                            }
                            catch {
                                $completeErrorMessage = $_.Exception.Message
                                if ($bitsAttempts -lt 3) {
                                    Write-Log -Severity Warning -Message "BITS job entered TransientError state, and Complete-BitsTransfer failed. Original error: $originalErrorMessage. Complete-BitsTransfer error: $completeErrorMessage. Retrying after 5 seconds..."
                                    Start-Sleep -Seconds 5
                                }
                                else {
                                    Write-Log -Severity Warning -Message "BITS job entered TransientError state, and Complete-BitsTransfer failed. Original error: $originalErrorMessage. Complete-BitsTransfer error: $completeErrorMessage."
                                    Write-Log -Message "BITS download failed after $bitsAttempts attempts. Falling back to Invoke-WebRequest."
                                    $bitsSuccess = $false
                                }
                            }
                        } # if TransientError state
                        else {
                            # Handle other error states
                            if ($bitsAttempts -lt 3) {
                                Write-Log -Severity Warning -Message "BITS download attempt $bitsAttempts failed. Error: $originalErrorMessage. Retrying after 5 seconds..."
                                Start-Sleep -Seconds 5
                            }
                            else {
                                Write-Log -Severity Warning -Message "BITS download attempt $bitsAttempts failed. Error: $originalErrorMessage."
                                Write-Log -Message "BITS download failed after $bitsAttempts attempts. Falling back to Invoke-WebRequest."
                                $bitsSuccess = $false
                            }
                        } # if other error states
                    } # Catch block for BITS
                } # While loop / attempt to use BITS
        
                # Clean up the BITS job before moving on to using Invoke-WebRequest
                if ($bitsJob) {
                    Remove-BitsTransfer -BitsJob $bitsJob -Confirm:$false -ErrorAction SilentlyContinue
                }
        
                # If BITS fails, retry with Invoke-WebRequest
                if ($bitsSuccess -eq $false) {
                    $webRequestAttempts = 0
                    $webRequestSuccess = $false
                    while ($webRequestAttempts -lt 3 -and $webRequestSuccess -eq $false) {
                        $webRequestAttempts++
                        $downloadStartTime = Get-Date
                        # Save the current progress preference
                        $OriginalProgressPreference = $ProgressPreference
                        $ProgressPreference = 'SilentlyContinue'
        
                        try {
                            # Attempt to download using Invoke-WebRequest
                            Write-Log "Attempting to download using Invoke-WebRequest. Attempt $webRequestAttempts of 3."
                            #Invoke-WebRequest -Uri $SourceUrl -OutFile $Destination -ErrorAction Stop
                            if ($UseBrowserHeaders) {
                                Write-Log "Using browser-like headers for Invoke-WebRequest due to custom ISO downloads from temp Microsoft URLs typically requiring them."
                                Invoke-WebRequest -Uri $SourceUrl -OutFile $Destination -Headers $browserHeaders -ErrorAction Stop
                            }
                            else {
                                Invoke-WebRequest -Uri $SourceUrl -OutFile $Destination -ErrorAction Stop
                            }
                            Write-Log "Download completed successfully using Invoke-WebRequest. File is at $($Destination)."
                            $webRequestSuccess = $true

                            $downloadEndTime = Get-Date
                            $downloadDuration = $downloadEndTime - $downloadStartTime
                            Write-Log "Total download time for attempt $($webRequestAttempts): $($downloadDuration.ToString('hh\:mm\:ss'))."
                        }
                        catch {
                            if ($webRequestAttempts -lt 3) {
                                Write-Log -Severity Warning -Message "Attempt $webRequestAttempts failed. Error: $($_.Exception.Message). Retrying after 5 seconds..."
                                Start-Sleep -Seconds 5
                            }
                            else {
                                Write-Log -Severity Warning -Message "Attempt $webRequestAttempts failed. Error: $($_.Exception.Message)."
                                Write-Log -Message "Invoke-WebRequest download failed after $webRequestAttempts attempts."
                                $webRequestSuccess = $false
                            }
                        }
                        finally {
                            # Restore the original progress preference
                            $ProgressPreference = $OriginalProgressPreference
                        }
                    } # While loop for Invoke-WebRequest attempts

                    # If both BITS and Invoke-WebRequest fail, log the error and exit
                    if (-not $webRequestSuccess) {
                        Write-Log -Severity Error -Message "File download failed after all attempts using BITS and Invoke-WebRequest."
                        $sleepWarning = Check-SleepSettings
                        if ($sleepWarning) {
                            Write-Log -Severity Warning -Message $sleepWarning
                        }
                        Write-Log -Severity Info "Exiting the script."
                        Remove-ProgressHelperScripts
                        exit 1
                    }
                } # attempt to use Invoke-WebRequest IF $bitsSuccess -eq $false

                # Verify the hash if provided
                if ($ExpectedHash) {
                    Write-Log "Verifying file hash."
                    $ActualHash = (Get-FileHash -Path $Destination -Algorithm SHA256).Hash
                    if ($ActualHash -ne $ExpectedHash) {
                        Write-Log "Error: Hash verification failed for $($Destination). Expected hash: $ExpectedHash, Actual hash: $ActualHash."
                        
                        # If the file is small (e.g., less than 10KB), check for HTML and extract the <title> line
                        # Useful for diagnosing downloads blocked by filters such as a DNS filter
                        $fileSize = (Get-Item $Destination).Length
                        if ($fileSize -lt 10000) {
                            $fileContent = Get-Content $Destination -Raw
                            if ($fileContent -match '<title>(.*?)</title>') {
                                #$title = $Matches[1]
                                $title = $Matches[0]
                                Write-Log "File appears to contain HTML. HTML <title> tags found: '$title'"
                            }
                            <#
                            else {
                                # Output first non-empty line for context
                                $firstLine = ($fileContent -split "`r?`n" | Where-Object { $_.Trim() })[0]
                                Write-Log "File content preview: $firstLine"
                            }
                            #>
                        }
                        Write-Log "Exiting script due to hash mismatch."
                        Remove-ProgressHelperScripts
                        exit 1
                    }
                    else {
                        Write-Log "Hash verification successful."
                    }
                } # if hash is provided
                else {
                    Write-Log "No hash provided. Skipping verification."
                } # if hash is not provided
            } # process
        
            end {
                # Write-Log "File download process completed."
                # $downloadEndTime = Get-Date
                # $downloadDuration = $downloadEndTime - $downloadStartTime
                # Write-Log "Total download time: $($downloadDuration.ToString('hh\:mm\:ss'))."
            }
        } # function Download-File

        function Show-BitsProgress {
            param (
                [Parameter(Mandatory)]
                [Guid]$JobId,
                [int]$IntervalSeconds = 2,
                [switch]$LogToFile,
                [string]$ProgressLogFile = "$env:SystemDrive\Win11\ProgressResults.log"
            )
            function Format-Size {
                param([double]$Bytes)
                if ($Bytes -ge 1GB) {
                    return @{ Value = "{0:N2}" -f ($Bytes / 1GB); Unit = "GB" }
                }
                elseif ($Bytes -ge 1MB) {
                    return @{ Value = "{0:N2}" -f ($Bytes / 1MB); Unit = "MB" }
                }
                else {
                    return @{ Value = "{0:N0}" -f $Bytes; Unit = "bytes" }
                }
            }
            while ($true) {
                $job = Get-BitsTransfer -Id $JobId -ErrorAction SilentlyContinue
                if (-not $job) {
                    Write-Host "BITS job not found."
                    break
                }
                $file = $job.FileList[0]
                $progress = if ($file.BytesTotal -gt 0) {
                    [math]::Round(($file.BytesTransferred / $file.BytesTotal) * 100, 1)
                }
                else { 0 }
                $transferred = Format-Size $file.BytesTransferred
                $total = Format-Size $file.BytesTotal
                $unit = if ($transferred.Unit -eq $total.Unit) { $transferred.Unit } else { "$($transferred.Unit)/$($total.Unit)" }
                $progressMsg = "Progress: {0}% ({1} / {2} {3}) - State: {4}" -f $progress, $transferred.Value, $total.Value, $unit, $job.JobState

                if ($LogToFile) {
                    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    $LogEntry = "[$Timestamp] [BITS] $progressMsg"
                    Add-Content -Path $ProgressLogFile -Value $LogEntry
                }
                else {
                    Write-Host "`r$progressMsg" -NoNewline
                }

                if ($job.JobState -notin 'Transferring', 'Connecting') { break }
                Start-Sleep -Seconds $IntervalSeconds
            }
            Write-Host ""
        }

        function 7z-Install {
            <#
            .SYNOPSIS
            Checks for 7-Zip installation and installs it if not found.
    
            .DESCRIPTION
            This function checks if 7-Zip is installed on the system. If not, it downloads and installs 7-Zip silently.
            #>

            # Check if 7-Zip is already installed
            $possiblePaths = @(
                "$env:ProgramFiles\7-Zip\7z.exe",
                "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
            )
            $sevenZipExe = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

            if ($sevenZipExe) {
                Write-Log "7-Zip is already installed at $sevenZipExe"
                return $sevenZipExe
            }
            else {
                Write-Log "7-Zip not found, proceeding with download and installation."
                # Download and install 7-Zip
                $installerUrl = "https://www.7-zip.org/a/7z2500-x64.exe"
                $downloadPath = "$env:TEMP\7z_installer.exe"
                try {
                    Invoke-WebRequest -Uri $installerUrl -OutFile $downloadPath -ErrorAction Stop
                }
                catch {
                    Write-Log -Severity Error -Message "Failed to download 7-Zip installer. Error: $_"
                    Write-Log -Severity Info "Files have been left in place. Exiting with exit code 1."
                    exit 1
                }
                Write-Log "Download complete. Installing 7-Zip..."
                Start-Process -FilePath $downloadPath -ArgumentList "/S" -Wait
                
                # Check again after install
                $sevenZipExe = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

                if ($sevenZipExe) {
                    Write-Log "Installation complete. 7z.exe is at: $sevenZipExe."
                    Write-Log "Removing the install file..."
                    Remove-Item -Path $downloadPath -Force
                    return $sevenZipExe
                }
                else {
                    Write-Log "7z.exe not found after installation."
                    Write-Log -Severity Error "The 7-Zip install failed. Files have been left in place. Exiting with exit code 1."
                    exit 1
                }
            }
        } # function 7z-Install

        function Extract-ISO {
            [CmdletBinding()]
            param (
                # # The path to the ISO file to be extracted
                [Parameter(Mandatory = $true)]
                [string]$SourceFile,

                # # The destination folder where the contents of the ISO will be extracted
                [Parameter(Mandatory = $true)]
                [string]$DestinationFolder,

                # The expected size of the extracted folder (in bytes) for verification
                [Parameter(Mandatory = $false)]
                [int64]$expectedExtractedFolderSize
            )

            process {
                Write-Log "Setting up the prerequisites for extracting the ISO file."

                # Define paths for 7z.exe and 7z.dll
                $7zipFolder = "$Win11Directory\7zip"
                if (-not (Test-Path -Path $7zipFolder)) {
                    try {
                        New-Item -ItemType Directory -Path $7zipFolder | Out-Null
                        Write-Log "Created the $($7zipFolder) folder."
                    }
                    catch {
                        Write-Log -Severity Warning "Failed to create 7zip folder at $($7zipFolder)."
                        return
                    }
                }
                $7zipExePath = "$7zipFolder\7z.exe"
                $7zipDllPath = "$7zipFolder\7z.dll"

                # Define the expected hashes for 7z.exe and 7z.dll
                $expected7zipExeHash = "034ECA579F68B44F8F41294D8C9DAC96F032C57DEE0877095DA47913060DFF84"
                $expected7zipDllHash = "6CD22F513CE36B4727BB6C353C58182C7CC8A14CBE3EEFDCA85C2A25906A0077"

                # Download 7z.exe and 7z.dll if not already present
                if (-not (Test-Path -Path $7zipExePath)) {
                    Write-Log "Downloading 7z.exe..."
                    Download-File -SourceUrl "https://ltshare.nyc3.digitaloceanspaces.com/PortableTools/7z.exe" -Destination $7zipExePath -ExpectedHash $expected7zipExeHash
                }
                else {
                    Write-Log "7z.exe already exists. Skipping download."
                }
                if (-not (Test-Path -Path $7zipDllPath)) {
                    Write-Log "Downloading 7z.dll..."
                    Download-File -SourceUrl "https://ltshare.nyc3.digitaloceanspaces.com/PortableTools/7z.dll" -Destination $7zipDllPath -ExpectedHash $expected7zipDllHash
                }
                else {
                    Write-Log "7z.dll already exists. Skipping download."
                }

                # Verify that 7z.exe and 7z.dll were downloaded successfully
                if (-not (Test-Path -Path $7zipExePath) -or -not (Test-Path -Path $7zipDllPath)) {
                    Write-Log -Severity Warning "Failed to download 7z.exe or 7z.dll. Exiting the function."
                    return
                }

                # Write-Log "Extracting the ISO file using 7z..."
                <#
                # $7zipCommand = "& `"$7zipExePath`" x `"$SourceFile`" -o`"$DestinationFolder`" -y"
                # Invoke-Expression $7zipCommand

                # Verify that the extraction was successful
                if (-not (Test-Path -Path $DestinationFolder)) {
                    Write-Log -Severity Warning "Failed to extract the ISO file to $($DestinationFolder) using 7z. Exiting the function."
                    return
                }
                Write-Log "Successfully extracted the ISO to $($DestinationFolder)."
                #>

                #>
                # Define log file paths for standard output and error
                # Redirecting unneeded output from 7z so as not to clutter the console
                # $stdoutLog = "$7zipFolder\7z_stdout.log"
                # $stderrLog = "$7zipFolder\7z_stderr.log"


                # Call the 7z-Install function to ensure 7-Zip is installed and return the path to 7z.exe
                # $7zipExePath = 7z-Install

                $stdoutLog = "C:\Windows\Temp\7z_stdout.log"
                $stderrLog = "C:\Windows\Temp\7z_stderr.log"
        
                $Parameters = @{
                    FilePath               = $7zipExePath
                    ArgumentList           = "x `"$SourceFile`" -o`"$DestinationFolder`" -y"
                    NoNewWindow            = $true
                    Wait                   = $true
                    RedirectStandardOutput = $stdoutLog
                    RedirectStandardError  = $stderrLog
                }

                Write-Log "Prerequisites for extracting the ISO file are complete."
                try {
                    Write-Log "Initiating the extraction process using 7z. Please wait..."
                    Start-Process @Parameters

                    # verify that the extraction was successful using the folder size
                    $extractedFolderSize = Get-ChildItem -Path $DestinationFolder -Recurse | Measure-Object -Property Length -Sum | Select-Object -ExpandProperty Sum
                    if ($extractedFolderSize -ne $expectedExtractedFolderSize) {
                        Write-Log -Severity Warning "The extracted folder size does not match the expected folder size."
                        Write-Log "Leaving the ISO file in place for the next run."
                        Remove-Item 'C:\Win11\Show-UpgradeProgress.ps1' -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path $7zipFolder -Recurse -Force -ErrorAction SilentlyContinue
                        Restore-SleepSettings
                        Write-Log "Exiting the script."
                        exit 1
                    }
                    else {
                        Write-Log "ISO successfully extracted to $($DestinationFolder)."
                    }
                }
                catch {
                    Write-Log -Severity Warning "Failed to extract the ISO file using 7z. Error: $_."
                    Write-Log "Leaving the ISO file in place for the next run. Exiting the script."
                    exit
                }

                # delete the ISO file and the 7zip folder
                if (Test-Path -Path $SourceFile) {
                    Remove-Item -Path $SourceFile -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted the ISO file at $($SourceFile)."
                }

                
                if (Test-Path -Path $7zipFolder) {
                    Remove-Item -Path $7zipFolder -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted the 7zip folder at $($7zipFolder)."
                }
            } # process
        } # function Extract-ISO

        function Wait-SetupProcessesComplete {
            param(
                [int]$MaxWaitMinutes = 5
            )
    
            Write-Log "Setup.exe has exited. Waiting for all setup-related processes to complete..."
            $waitStart = Get-Date
            $allProcessesExited = $false

            while (-not $allProcessesExited -and ((Get-Date) - $waitStart).TotalMinutes -lt $MaxWaitMinutes) {
                $remainingSetupProcs = Get-Process | Where-Object { 
                    $_.Name -match '^Setup.*$|^SetupHost$|^SetupPrep$' 
                } -ErrorAction SilentlyContinue
        
                if ($remainingSetupProcs) {
                    $procNames = ($remainingSetupProcs | Select-Object -ExpandProperty Name | Sort-Object -Unique) -join ', '
                    Write-Log "Waiting for setup processes to complete: $procNames"
                    Start-Sleep -Seconds 10
                }
                else {
                    $allProcessesExited = $true
                    Write-Log "All setup-related processes have completed."
                }
            }

            if (-not $allProcessesExited) {
                Write-Log -Severity Warning "Timeout reached. Some setup processes may still be running after $MaxWaitMinutes minutes."
            }
    
            return $allProcessesExited
        } # function Wait-SetupProcessesComplete
        
        function Suspend-BitLockerUntilReboot {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $false)]
                [string]$DriveLetter = "C"
            )

            process {
                Write-Log "Suspending BitLocker protection for drive $($DriveLetter): until the next reboot..."
                try {
                    Suspend-BitLocker -MountPoint $DriveLetter -RebootCount 1 -ErrorAction Stop | Out-Null
                    Write-Log "BitLocker protection successfully suspended."
                }
                catch {
                    Write-Log -Severity Warning "Failed to suspend BitLocker protection for drive $DriveLetter. Error: $_"
                }
            }
        } # function Suspend-BitLockerUntilReboot

        function Check-SleepSettings {
            param(
                [switch]$VerboseOutput
            )
    
            $sleepThresholdSeconds = 600 # 10 minutes
            $sleepSettings = @{}

            # Get current sleep settings for AC and DC
            $acSleepHex = (powercfg -q scheme_current sub_sleep standbyidle | Select-String "Current AC Power Setting Index").ToString().Split(":")[-1].Trim()
            $dcSleepHex = (powercfg -q scheme_current sub_sleep standbyidle | Select-String "Current DC Power Setting Index").ToString().Split(":")[-1].Trim()

            $acSleepDec = [convert]::ToInt32($acSleepHex, 16)
            $dcSleepDec = [convert]::ToInt32($dcSleepHex, 16)

            $sleepSettings["AC"] = @{ Hex = $acSleepHex; Dec = $acSleepDec }
            $sleepSettings["DC"] = @{ Hex = $dcSleepHex; Dec = $dcSleepDec }

            $lowSleepAC = $acSleepDec -gt 0 -and $acSleepDec -lt $sleepThresholdSeconds
            $lowSleepDC = $dcSleepDec -gt 0 -and $dcSleepDec -lt $sleepThresholdSeconds

            # Format AC and DC values with minutes if seconds > 0
            $acSleepStr = "$acSleepDec seconds"
            if ($acSleepDec -gt 0) {
                $acSleepStr += " ($([math]::Round($acSleepDec/60,2)) min)"
            }
            $dcSleepStr = "$dcSleepDec seconds"
            if ($dcSleepDec -gt 0) {
                $dcSleepStr += " ($([math]::Round($dcSleepDec/60,2)) min)"
            }
    
            if ($VerboseOutput -or $lowSleepAC -or $lowSleepDC) {
                # Determine if the machine is on AC or battery power
                $BatteryStatus = Get-CimInstance -ClassName Win32_Battery
                if (!$BatteryStatus) {
                    $chassis = Get-CimInstance -ClassName Win32_SystemEnclosure
                    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-systemenclosure?redirectedfrom=MSDN
                    # https://powershell.one/wmi/root/cimv2/win32_systemenclosure
                    $laptopTypes = @(8, 9, 10, 14)
                    $isLaptop = $chassis.ChassisTypes | Where-Object { $_ -in $laptopTypes }
                    if ($isLaptop) {
                        $BatteryMessage = "No Win32_Battery object detected. This device is likely a laptop based on the Win32_SystemEnclosure chassis type."
                    }
                    else {
                        $BatteryMessage = "No Win32_Battery object detected. This device is likely a desktop based on the Win32_SystemEnclosure chassis type."
                    }
                } # if no battery object
                else {
                    # if ((Get-WmiObject -Namespace root\wmi -Class BatteryStatus).PowerOnline) { "The machine is connected to AC power." } else { "The machine is running on battery power." }
                    # https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-battery
                    if ($BatteryStatus.BatteryStatus -eq 1) {
                        $BatteryMessage = "The machine is currently running on battery power. Estimated charge remaining: $($BatteryStatus.EstimatedChargeRemaining)%."
                    }
                    elseif ($BatteryStatus.BatteryStatus -eq 2) {
                        $BatteryMessage = "The machine is currently connected to AC power."
                    }    
                } # if battery object exists

                if ($lowSleepAC -or $lowSleepDC) {
                    $BatteryMessage += " Low sleep settings detected: AC = $acSleepStr, DC = $dcSleepStr. Low sleep settings can interrupt downloads and cause BITS/Invoke-WebRequest failures. To temporarily disable sleep, run: powercfg /change standby-timeout-ac 0; powercfg /change standby-timeout-dc 0."
                }
                else {
                    $BatteryMessage += " Current sleep settings: AC = $acSleepStr, DC = $dcSleepStr."
                }
                return $BatteryMessage
            }
            else {
                return $null
            }
        } # function Check-SleepSettings

        function Restore-SleepSettings {
            if ($DisableSleepDuringUpgrade -and -not $SleepSettingsAlreadyDisabled) {
                Write-Log "Restoring original sleep settings..."
                try {
                    if ($originalAC) { powercfg /change standby-timeout-ac $originalACMin }
                    if ($originalDC) { powercfg /change standby-timeout-dc $originalDCMin }
            
                    # Confirm that the sleep settings were restored
                    $restoredAC = (powercfg -q scheme_current sub_sleep standbyidle | Select-String "Current AC Power Setting Index").ToString().Split(":")[-1].Trim()
                    $restoredDC = (powercfg -q scheme_current sub_sleep standbyidle | Select-String "Current DC Power Setting Index").ToString().Split(":")[-1].Trim()
            
                    if ($restoredAC -eq $originalAC -and $restoredDC -eq $originalDC) {
                        Write-Log "Sleep settings successfully restored to their original values: AC=$restoredAC, DC=$restoredDC."
                    }
                    else {
                        Write-Log -Severity Warning "Sleep settings were not restored to their original values. Current AC: $restoredAC, DC: $restoredDC. Original AC: $originalAC, DC: $originalDC."
                    }
                }
                catch {
                    Write-Log -Severity Warning "Failed to restore sleep settings: $_"
                    Write-Log "Original sleep setting values were: AC=$originalAC, DC=$originalDC"
                }
            } # if $DisableSleepDuringUpgrade -and -not $SleepSettingsAlreadyDisabled
        } # function Restore-SleepSettings

        function Convert-DecimalToHex {
            param (
                [Parameter(Mandatory = $true)]
                [int]$Number
            )
            # For negative numbers, get the unsigned 32-bit hex representation
            if ($Number -lt 0) {
                return ("0x{0:X}" -f ($Number -band 0xFFFFFFFF))
            }
            else {
                return ("0x{0:X}" -f $Number)
            }
        } # function Convert-DecimalToHex
        #endregion functions

        <#
        # Validate the TargetBuildNumber parameter
        $validBuildNumbers = @(22631, 26100, 26200)
        if (-not ($validBuildNumbers -contains $TargetBuildNumber)) {
            Write-Log -Severity Warning "Invalid TargetBuildNumber specified: $TargetBuildNumber. Valid options are: $($validBuildNumbers -join ', ').
            Exiting the script. Please provide a valid build number and try again." 
            return
        }
        #>

        $Win11Directory = "C:\Win11"
        # Check if the C:\Win11 directory exists, create it if it doesn't
        if (-not (Test-Path -Path "C:\Win11")) {
            try {
                New-Item -ItemType Directory -Path "C:\Win11" | Out-Null
                Write-Log "Created the $($Win11Directory) directory."
            }
            catch {
                Write-Log -Severity Warning "Failed to create the C:\Win11 directory. Error: $($_.Exception.Message)"
                return
            }
        }
        else {
            Write-Log -BlankLine
            # Write-Log "The C:\Win11 directory already exists."
        }

        if ($Env:TargetBuildNumber) {
            Write-Log "<<<<<    Starting the Windows 11 ($Env:TargetBuildNumber) upgrade process    >>>>>"    
        }
        else {
            Write-Log "<<<<<    Starting the Windows 11 ($TargetBuildNumber) upgrade process    >>>>>"
        }

        # Output log file path
        Write-Log "The script log file can be found at `"C:\Win11\Win11Upgrade.log`"."
        Write-Log "Machine name: $($Env:COMPUTERNAME)"
        # Calculate boot time and uptime
        $BootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        $UT = (Get-Date) - $BootTime
        $Uptime = "{0:dd}d: {0:hh}h: {0:mm}m" -f $UT
        Write-Log "Last boot time: $BootTime / Uptime: $Uptime"
        # Write-Log "The setupact log file can be found at `"$Win11Directory\Windows11SetupLogs\Panther\setupact.log.`"."

        <# No longer in use since adding in the ApplyAutomationControls
        # File to track number of times this script has been run on this machine
        $ScriptRunCountFile = "C:\Win11\Win11Upgrade_RunCount.txt"
        if (Test-Path -Path $ScriptRunCountFile) {
            $ScriptRunCount = [int](Get-Content -Path $ScriptRunCountFile)
        }
        else {
            $ScriptRunCount = 0
        }
        Write-Log "This script has been run on this machine $($ScriptRunCount) time(s)."
        $ScriptRunCount++
        Set-Content -Path $ScriptRunCountFile -Value $ScriptRunCount -ErrorAction SilentlyContinue
        #>
        if (Test-Path "C:\Win11\Win11Upgrade_RunCount.txt") {
            # Remove the old run count file if it exists
            Remove-Item -Path "C:\Win11\Win11Upgrade_RunCount.txt" -Force -ErrorAction SilentlyContinue
            Write-Log "Removed the old Win11Upgrade_RunCount.txt file."
        }

        # When running on a schedule via NinjaOne, apply automation controls, namely take into account the value of the upgrade state CF
        if ($Env:ApplyAutomationControls -eq "true") {
            # Exit if the state custom field is not set to "Ready to run upgrade script". 
            # (If the machine is already at the target build number, logic later on in the script will cause the script to exit, regardless of the CF value or if ApplyAutomationControls is used.)
            $upgradeStateCustomField = Ninja-Property-Get windowsMajorVersionUpgradeState
            if ($upgradeStateCustomField -ne "Ready to run upgrade script") {
                if ([string]::IsNullOrWhiteSpace($upgradeStateCustomField)) {
                    Write-Log "The windowsMajorVersionUpgradeState custom field is empty. Exiting with exit code 0."
                }
                else {
                    Write-Log "The windowsMajorVersionUpgradeState custom field value is $($upgradeStateCustomField). Exiting with exit code 0."
                }
                exit 0
            }
        }

        # Increment the attempt count custom field.
        $attemptCount = [int](Ninja-Property-Get windowsMajorVersionUpgradeAttemptCount)
        Write-Log "This script has run on this machine $($attemptCount) time(s). Incrementing the attempt count custom field by 1."
        $attemptCount ++
        Ninja-Property-Set windowsMajorVersionUpgradeAttemptCount $attemptCount

        # Check if the script is running with administrative privileges
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Log -Severity Warning "The script must be run as an administrator. Exiting the script."
            return
        }

        <#
        # Check if the current time is after 4 AM
        $currentHour = (Get-Date).Hour
        if ($currentHour -ge 4) {
            if (-not $AllowAfter_4AM) {
                Write-Log -Severity Warning "The current time is $(Get-Date -Format "hh:mm:ss tt") and the 'AllowAfter_4AM' parameter was not specified. Exiting the script."
                return
            }
            else {
                Write-Log "The current time is $(Get-Date -Format "hh:mm:ss tt"). The 'AllowAfter_4AM' parameter was specified. Proceeding with the script."
            }
        } # if current time is after 4 AM
        #>

        # Check for existing setup.exe processes running for a long time (e.g., > 3 hours)
        $existingSetups = Get-Process -Name setup* -ErrorAction SilentlyContinue
        $maxSetupAgeHours = 3

        if ($existingSetups) {
            $now = Get-Date
            foreach ($proc in $existingSetups) {
                $runTime = $now - $proc.StartTime
                if ($runTime.TotalHours -ge $maxSetupAgeHours) {
                    Write-Log -Severity Warning "Process $($proc.Name) (PID $($proc.Id)) has been running for more than $maxSetupAgeHours hours. Please stop all setup.exe processes and re-run this script."
                    Write-Log -Severity Info "Leaving setup files in place and exiting the script."
                    exit 1
                }
            }
        }

        # Check for Get-Volume throwing errors
        # If Get-Volume fails, set a flag to avoid using it later for free space checks
        $AvoidGetVolume = $false
        try {
            $null = Get-Volume -DriveLetter C -ErrorAction Stop
        }
        catch {
            $AvoidGetVolume = $true
            Write-Log -Severity Warning "Get-Volume failed during initial check. Will use Get-PSDrive for all free space checks. Error: $($_.Exception.Message)."
        }

        #Region set up progress monitoring scripts
        Write-Log "Writing the progress helper scripts to $($Win11Directory)."
        # Write Show-BitsProgress.ps1 to C:\Win11
        # Run manually from a PowerShell console to monitor the BITS download progress
        @'
function Show-BitsProgress {
    param (
        [Parameter(Mandatory)]
        [Guid]$JobId,
        [int]$IntervalSeconds = 2
    )
    function Format-Size {
        param([double]$Bytes)
        if ($Bytes -ge 1GB) {
            return @{ Value = "{0:N2}" -f ($Bytes / 1GB); Unit = "GB" }
        } elseif ($Bytes -ge 1MB) {
            return @{ Value = "{0:N2}" -f ($Bytes / 1MB); Unit = "MB" }
        } else {
            return @{ Value = "{0:N0}" -f $Bytes; Unit = "bytes" }
        }
    }
    $startTime = $job.CreationTime
    while ($true) {
        # The -AllUsers parameter is to allow for using this helper script on the front end (NOT as System) 
        # and still be able to access the BITS job created by the System account when running the script via NinjaOne
        # $job = Get-BitsTransfer -Id $JobId -AllUsers -ErrorAction SilentlyContinue # cannot use both -Id and -AllUsers together
        $job = Get-BitsTransfer -AllUsers | Where-Object { $_.JobId -eq $JobId }
        if (-not $job) {
            Write-Host "BITS job not found."
            break
        }
        $file = $job.FileList[0]
        $progress = if ($file.BytesTotal -gt 0) {
            [math]::Round(($file.BytesTransferred / $file.BytesTotal) * 100, 1)
        }
        else { 0 }
        $transferred = Format-Size $file.BytesTransferred
        $total = Format-Size $file.BytesTotal
        $unit = if ($transferred.Unit -eq $total.Unit) { $transferred.Unit } else { "$($transferred.Unit)/$($total.Unit)" }
        $elapsed = (Get-Date) - $startTime
        $elapsedStr = $elapsed.ToString("hh\:mm\:ss")
        Write-Host ("`rProgress: {0}% ({1} / {2} {3}) - State: {4} - Elapsed: {5}   " -f $progress, $transferred.Value, $total.Value, $unit, $job.JobState, $elapsedStr) -NoNewline
        if ($job.JobState -notin 'Transferring', 'Connecting') { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
    Write-Host ""
}

$job = Get-BitsTransfer * | Where-Object { $_.JobState -eq 'Transferring' }
if (-not $job) {
    Write-Host "No BITS jobs found in 'Transferring' state. Exiting."
    return
}
Show-BitsProgress -JobId $job.JobId
'@ | Set-Content -Path "$Win11Directory\Show-BitsProgress.ps1"

        # Write Show-UpgradeProgress.ps1 to C:\Win11
        # Run manually from a PowerShell console to monitor the progress of setup.exe
        @'
param (
    [switch]$ShowLastLogLine
)
    
$setupProcs = Get-Process -Name Setup* -ErrorAction SilentlyContinue
if (-not $setupProcs) {
    Write-Host "No Windows setup processes found. Upgrade is not in progress. Exiting."
    return
}
While (Get-Process -Name Setup* -ErrorAction SilentlyContinue) {
    $progress = (Get-ItemProperty HKLM:\SYSTEM\Setup\MoSetup\Volatile -Name SetupProgress -ErrorAction SilentlyContinue).SetupProgress
    Write-Host "`rUpgrade progress: $progress%" -NoNewline
    
    if ($ShowLastLogLine) {
        $lastLogLine = Get-Content 'C:\$WINDOWS.~BT\Sources\Panther\setupact.log' -Tail 1 -ErrorAction SilentlyContinue
        if ($lastLogLine) {
            Write-Host "`nLast entry in setupact.log: $lastLogLine"
        }
    }
    
    Start-Sleep -Seconds 10
}
'@ | Set-Content -Path "$Win11Directory\Show-UpgradeProgress.ps1"

        # Write Invoke-SpeedTest.ps1 to C:\Win11
        # Run manually from a PowerShell console to test network speed during ISO download
        @'
param(
    [switch]$All
)

function Invoke-SpeedTest {
    [CmdletBinding()]
    param(
        [switch]$All
    )

    $TempDir = Join-Path $env:TEMP 'SpeedtestCLI'
    $ZipPath = Join-Path $TempDir 'speedtest.zip'
    $ExePath = Join-Path $TempDir 'speedtest.exe'
    $Url = 'https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-win64.zip'

    if (-not (Test-Path $ExePath)) {
        if (-not (Test-Path $TempDir)) {
            New-Item -ItemType Directory -Path $TempDir | Out-Null
        }

        Write-Host 'Downloading Ookla Speedtest CLI...'
        $PreviousProgressPreference = $ProgressPreference
        try {
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing
        }
        finally {
            $ProgressPreference = $PreviousProgressPreference
        }

        Expand-Archive -Path $ZipPath -DestinationPath $TempDir -Force
        Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
    }

    Write-Host 'Running speedtest...'
    $Results = & $ExePath --accept-license --accept-gdpr 2>$null

    if ($All) {
        $Results
    }
    else {
        $Results | Where-Object { $_ -match '^\s+Download:' -or $_ -match 'Result URL:' }
    }
}

Invoke-SpeedTest -All:$All
'@ | Set-Content -Path "$Win11Directory\Invoke-SpeedTest.ps1"
        #endregion set up progress monitoring scripts
        
        #region initializing variables
        Write-Log -IsPhaseMarker "---- [PHASE 1: Pre-Flight Checks] ----"
        $WindowsVersionInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $CurrentBuildNumber = [int]$WindowsVersionInfo.CurrentBuildNumber # [Environment]::OSVersion.Version.Build
        
        if ($WindowsVersionInfo.PSObject.Properties['LCUVer']) {
            # $WindowsLCU = [int]($WindowsVersionInfo.LCUVer.split(".")[3]) # the latest cumulative update version
            $WindowsBuildAndCU = $WindowsVersionInfo.LCUVer.split(".")[-2..-1] -join "." # the latest cumulative update version
        }
        elseif ($WindowsVersionInfo.PSObject.Properties['WinREVersion']) {
            # $WindowsLCU = [int]($WindowsVersionInfo.WinREVersion.split(".")[3]) # the latest cumulative update version
            $WindowsBuildAndCU = $WindowsVersionInfo.WinREVersion.split(".")[-2..-1] -join "." # the latest cumulative update version
        }
        else {
            $WindowsBuildAndCU = $WindowsVersionInfo.CurrentBuildNumber
        }
        
        $WindowsEdition = $WindowsVersionInfo.ProductName

        # Check if the current build is already up to date - unless an in-place upgrade is being performed, downloading only, or using custom ISO
        if ( ($CurrentBuildNumber -ge $TargetBuildNumber) -and (-not $InPlaceUpgrade -and -not $DownloadAndExtractOnly -and -not $CustomISOUrl -and -not $SkipValidation) ) {
            Write-Log "Windows is already up to date. Current build number: $($WindowsBuildAndCU), Target build number: $($TargetBuildNumber). Exiting the script."
            Remove-ProgressHelperScripts
            return
        }

        if ($SkipValidation) {
            Write-Log "SkipValidation parameter specified. Hash and size validation checks will be skipped for the ISO file."
        }

        if ($InPlaceUpgrade) {
            # Override TargetBuildNumber when InPlaceUpgrade is specified
            Write-Log "In-place upgrade/repair mode specified. Overriding TargetBuildNumber parameter and will attempt to use an ISO matching current build $($CurrentBuildNumber)."
            $TargetBuildNumber = $CurrentBuildNumber
        }

        # Block using EnablementPackage parameter with InPlaceUpgrade parameter:
        if ($InPlaceUpgrade -and $EnablementPackage) {
            Write-Log -Severity Warning "InPlaceUpgrade and EnablementPackage cannot be used together. In-place repair requires same-build ISO. Exiting with exit code 1."
            exit 1
        }

        # Check if the en-GB language is installed
        # Set $enGB to $false initially, otherwise, if the registry key does not exist, $enGB will be $null and neither part of the logic in the if statement of the 26100 section in the switch statement, will run
        $enGB = $false
        try {
            # https://www.autoitscript.com/autoit3/docs/appendix/OSLangCodes.htm
            if ((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language').InstallLanguage -eq '0809') {
                $enGB = $true
            }
        }
        catch {
            Write-Log -Severity Warning "Failed to check for en-GB language. Error: $_. Exception.Message"
        }

        # Check processor architecture
        $arch = (Get-CimInstance Win32_Processor).Architecture
        switch ($arch) {
            #0 { $archName = "x86" }
            #1 { $archName = "MIPS" }
            #2 { $archName = "Alpha" }
            #3 { $archName = "PowerPC" }
            5 { $archName = "ARM" }
            #6 { $archName = "Itanium" }
            9 { $archName = "x64" }
            12 { $archName = "ARM64" }
            default { $archName = "Unknown architecture: $arch" }
        }
        
        # Block unsupported architectures for Windows 10 22H2 (19045)
        if ($TargetBuildNumber -eq 19045) {
            if ($archName -eq "ARM64" -or $archName -eq "ARM" -or $archName -eq "x86") {
                Write-Log -Severity Warning "Windows 10 22H2 (19045) ISOs for ARM and 32-bit (x86) machines are not included in this script. Exiting with exit code 1."
                Remove-ProgressHelperScripts
                exit 1
            }
        } # if Windows 10 22H2

        Write-Log "System info: Edition=$($WindowsEdition), CurrentBuild=$($WindowsBuildAndCU), TargetBuild=$($TargetBuildNumber), Arch=$archName, Language=$(if ($enGB) { 'en-GB' } else { 'en-US' })."
        if ($enGB -and !$EnablementPackage) {
            Write-Log "The en-GB language is installed on this machine. Using the English International ISO."
        }

        # ISO Metadata Table
        $ISOs = @(
            # Windows 11 25H2 (26200) - English (United States)
            @{
                Build      = 26200
                Arch       = 'x64'
                Tags       = @('Home', 'Pro', 'Edu', 'Ent')
                Url        = 'https://ltshare.nyc3.cdn.digitaloceanspaces.com/Win11_25h2/Win11_25H2_English_x64.iso'
                ISOSize    = 7736125440
                FolderSize = 7730485137
                Hash       = 'D141F6030FED50F75E2B03E1EB2E53646C4B21E5386047CB860AF5223F102A32'
                Language   = 'en-US'
            },
            # Windows 11 25H2 (26200) - English (International)
            @{
                Build      = 26200
                Arch       = 'x64'
                Tags       = @('Home', 'Pro', 'Edu', 'Ent')
                Url        = 'https://ltshare.nyc3.cdn.digitaloceanspaces.com/Win11_25h2/Win11_25H2_EnglishInternational_x64.iso'
                ISOSize    = 7754645504
                FolderSize = 7748701620
                Hash       = 'BAAEB6C90DD51648154B64C40C9E0C14D93A427F611A1BB49C8077FA2FF73364'
                Language   = 'en-GB'
            },
            # Windows 11 25H2 (26200) - ARM64 English (United States)
            @{
                Build      = 26200
                Arch       = 'ARM64'
                Tags       = @('Pro', 'Edu', 'Ent')
                Url        = 'https://ltshare.nyc3.cdn.digitaloceanspaces.com/Win11_25h2/SW_DVD9_Win_Pro_11_25H2_Arm64_English_Pro_Ent_EDU_N_MLF_X24-13111.ISO'
                ISOSize    = 7210936320
                FolderSize = 7205055833 # 7307792895
                Hash       = '8A01A5D5DEF7EE9013943FD4F181ED13CB6C8EE5EF8F0EB03862CFD1F6200E15'
                Language   = 'en-US'
            },
            # Windows 11 25H2 (26200) - ARM64 English (International)
            @{
                Build      = 26200
                Arch       = 'ARM64'
                Tags       = @('Pro', 'Edu', 'Ent')
                Url        = 'https://ltshare.nyc3.cdn.digitaloceanspaces.com/Win11_25h2/SW_DVD9_Win_Pro_11_25H2_Arm64_Eng_Intl_Pro_Ent_EDU_N_MLF_X24-13140.ISO'
                ISOSize    = 7221297152
                FolderSize = 7215112149
                Hash       = 'F2389D183F1F8E57EE5FCEE6A24FBC20FCC1B4D82307BBD5E7A7610F5B21DBA8'
                Language   = 'en-GB'
            },
            # Windows 11 24H2 (26100) - English (United States) Home/Pro/Edu
            @{
                Build      = 26100
                Arch       = 'x64'
                Tags       = @('Home', 'Pro', 'Edu')
                Url        = 'https://ltshare.nyc3.digitaloceanspaces.com/Win11_24H2/Win11_24H2_English_x64.iso'
                ISOSize    = 5819484160
                FolderSize = 5813856759
                Hash       = 'B56B911BF18A2CEAEB3904D87E7C770BDF92D3099599D61AC2497B91BF190B11'
                Language   = 'en-US'
            },
            # Windows 11 24H2 (26100) - English (United States) Enterprise
            @{
                Build      = 26100
                Arch       = 'x64'
                Tags       = @('Ent')
                Url        = 'https://ltshare.nyc3.digitaloceanspaces.com/Win11_24H2/SW_DVD9_Win_Pro_11_24H2_64BIT_English_Pro_Ent_EDU_N_MLF_X23-69812.ISO'
                ISOSize    = 5722114048
                FolderSize = 5716480766
                Hash       = 'D0DCA325314322518AE967D58C3061BCAE57EE9743A8A1CF374AAD8637E5E8AC'
                Language   = 'en-US'
            },
            # Windows 11 24H2 (26100) - English (International) Home/Pro/Edu
            @{
                Build      = 26100
                Arch       = 'x64'
                Tags       = @('Home', 'Pro', 'Edu')
                Url        = 'https://ltshare.nyc3.digitaloceanspaces.com/Win11_24H2/Win11_24H2_EnglishInternational_x64.iso'
                ISOSize    = 5832091648
                FolderSize = 5826157508
                Hash       = 'D5A4C97C3E835C43B1B9A31933327C001766CE314608BA912F2FFFC876044309'
                Language   = 'en-GB'
            },
            # Windows 11 24H2 (26100) - ARM64 Pro/Ent/Edu only
            @{
                Build      = 26100
                Arch       = 'ARM64'
                Tags       = @('Pro', 'Edu', 'Ent')
                Url        = 'https://ltshare.nyc3.digitaloceanspaces.com/Win11_24H2/SW_DVD9_Win_Pro_11_24H2_Arm64_English_Pro_Ent_EDU_N_MLF_X23-69850.ISO'
                ISOSize    = 5388951552
                FolderSize = 5383086643
                Hash       = '15FF94A99E89846C54316275F60EA697C9517E5DEA7B3A963157A4C632524F72'
                Language   = 'en-US'
            },
            # Windows 10 22H2 (19045) - x64 Home
            @{
                Build      = 19045
                Arch       = 'x64'
                Tags       = @('Home')
                Url        = 'https://ltshare.nyc3.cdn.digitaloceanspaces.com/Win10_22H2/Win10_22H2_64.iso'
                ISOSize    = 4783996928
                FolderSize = 4778197366
                Hash       = 'D209C7860967A6F70389487A3FB2276444D651472024FFF931A0F33B7FF16B99'
                Language   = 'en-US'
            },
            # Windows 10 22H2 (19045) - x64 Pro/Ent/Edu
            @{
                Build      = 19045
                Arch       = 'x64'
                Tags       = @('Pro', 'Ent', 'Edu')
                Url        = 'https://ltshare.nyc3.cdn.digitaloceanspaces.com/Win10_22H2/Win10_22H2_64_Pro_Ent_EDU.ISO'
                ISOSize    = 5970708480
                FolderSize = 5965268755
                Hash       = 'BA1C32F0BDA69022A4843F05C91B90DB8DCA6EC13123D1CF7C8160828128BD64'
                Language   = 'en-US'
            }
            # Windows 11 23H2 (22631) - x64 Home/Pro/Edu
            @{
                Build      = 22631
                Arch       = 'x64'
                Tags       = @('Home', 'Pro', 'Edu')
                Url        = 'https://ltshare.nyc3.digitaloceanspaces.com/Win11_23H2/Win11_23H2_English_x64v2.iso'
                ISOSize    = 6812706816
                FolderSize = 6807219850
                Hash       = '36DE5ECB7A0DAA58DCE68C03B9465A543ED0F5498AA8AE60AB45FB7C8C4AE402'
                Language   = 'en-US'
            },
            # Windows 11 23H2 (22631) - x64 Enterprise
            @{
                Build      = 22631
                Arch       = 'x64'
                Tags       = @('Ent')
                Url        = 'https://ltshare.nyc3.digitaloceanspaces.com/Win11_23H2/SW_DVD9_Win_Pro_11_23H2.6_64BIT_English_Pro_Ent_EDU_N_MLF_X23-75490.ISO'
                ISOSize    = 6972778496
                FolderSize = 6967281618
                Hash       = '4B0A020ABEDD7ABE7F1CAAFF252EE59AF6706DBE9ECECCA6ECD4FB28A3EBC6A7'
                Language   = 'en-US'
            }
        ) # $ISOs array

        # Edition Tag Selection
        switch -Regex ($WindowsEdition) {
            "Home" { $EditionTag = "Home"; break }
            "Pro" { $EditionTag = "Pro"; break }
            "Education" { $EditionTag = "Edu"; break }
            "Enterprise" { $EditionTag = "Ent"; break }
            default { $EditionTag = $null }
        }

        # Language Tag Selection
        $LanguageTag = if ($enGB) { 'en-GB' } else { 'en-US' }

        # Validate ISO availability for InPlaceUpgrade
        if ($InPlaceUpgrade) {
            # Skip ISO validation if using custom ISO URL
            if (-not $CustomISOUrl) {
                # Check if an ISO exists for this build
                Write-Log "Validating ISO availability for in-place repair of current build $CurrentBuildNumber..."
                $buildAvailable = $ISOs | Where-Object { $_.Build -eq $CurrentBuildNumber }
                if (-not $buildAvailable) {
                    Write-Log -Severity Warning "No ISO available in this script for current build $($CurrentBuildNumber). In-place repair cannot proceed. Available builds: $($ISOs.Build | Sort-Object -Unique)"
                    Write-Log "Exiting with exit code 1."
                    exit 1
                }
                Write-Log "ISO validation passed: ISO available for build $CurrentBuildNumber."
            }
            else {
                Write-Log "Using custom ISO URL for in-place repair. Skipping ISO availability validation."
            }
        }

        # Enablement Package Logic
        $EnablementPackageAvailable = $false
        if ($EnablementPackage) {
            Write-Log "EnablementPackage specified. Preparing to run enablement package upgrade..."
            # Check that the current build is 24H2 (26100) and that the target build specified when running the script is 25H2 (26200)
            if ($TargetBuildNumber -eq 26200 -and $CurrentBuildNumber -eq 26100) {
                # Windows 11 24H2 must be at build 26100.5074 or higher (KB5064081 or later)
                # https://support.microsoft.com/en-us/topic/kb5054156-feature-update-to-windows-11-version-25h2-by-using-an-enablement-package-4d307e2d-3028-4323-bb46-552cff491643
                $currentRevision = [int]$WindowsBuildAndCU.Split('.')[-1]
                $requiredRevision = 5074
                if ($currentRevision -lt $requiredRevision) {
                    Write-Log -Severity Warning "Enablement package requires Windows 11 24H2 build 26100.5074 or higher. Current build: $WindowsBuildAndCU. Falling back to ISO method."
                    $EnablementPackageAvailable = $false
                }
                else {
                    $EnablementPackageAvailable = $true
                    # https://pureinfotech.com/windows-11-25h2-enablement-package-iso-direct-download/
                    if ($archName -eq "x64") {
                        $EnablementPackageUrl = "https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/fa84cc49-18b2-4c26-b389-90c96e6ae0d2/public/windows11.0-kb5054156-x64_a0c1638cbcf4cf33dbe9a5bef69db374b4786974.msu"
                        $EnablementPackageHash = "92EDDA7EEAA19B60D15CCDF777556BF0662EE9FEA1DCC9AEC281FCF12068044C"
                    }
                    elseif ($archName -eq "ARM64") {
                        $EnablementPackageUrl = "https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/78b265e5-83a8-4e0a-9060-efbe0bac5bde/public/windows11.0-kb5054156-arm64_3d5c91aaeb08a87e0717f263ad4a61186746e465.msu"
                        $EnablementPackageHash = "0C1FDC7BEB0137E66DD693880890F984EB5768B2292EF9D16F4D13CA665A1B5C"
                    }
                    else {
                        Write-Log -Severity Warning "Enablement package is not available for architecture: $archName. Falling back to ISO method."
                        $EnablementPackageAvailable = $false
                    }  
                }
            }
            else {
                Write-Log -Severity Warning "Enablement package can only be used when upgrading from 24H2 (26100) to 25H2 (26200). Current build: $CurrentBuildNumber, Target build: $TargetBuildNumber. Falling back to ISO method."
                $EnablementPackageAvailable = $false
            }
        } # if $EnablementPackage

        # ISO Selection Logic
        if (-not $EnablementPackageAvailable) {
            if ($CustomISOUrl) {
                # Using custom ISO URL - skip ALL validation checks (compatibility, hash, size)
                Write-Log "Using custom ISO URL: $CustomISOUrl"
                Write-Log "Skipping all validation checks."
                
                $Download_Path = $CustomISOUrl
                # Skip hash and size validation for custom URLs
                $ExpectedISOSize = $null
                $ExpectedFolderSize = $null
                $ExpectedFileHash = $null
            }
            else {
                # Using built-in ISO table - perform all validations
                # Block unsupported architectures for Windows 10 22H2 (19045)
                if ($TargetBuildNumber -eq 19045 -and ($archName -eq "ARM64" -or $archName -eq "ARM" -or $archName -eq "x86")) {
                    Write-Log -Severity Warning "Windows 10 22H2 (19045) ISOs for ARM and 32-bit (x86) machines are not included in this script. Exiting with exit code 1."
                    exit 1
                }
                # Block ARM64 Home (not available)
                if ($archName -eq "ARM64" -and $EditionTag -eq "Home") {
                    Write-Log -Severity Warning "ARM64 architecture detected and Windows Edition is Home. The ARM ISO in this script does not include Home edition. Exiting with exit code 1."
                    exit 1
                }
                # Lookup ISO
                $iso = $ISOs | Where-Object {
                    $_.Build -eq $TargetBuildNumber -and
                    $_.Arch -eq $archName -and
                    ($_.Tags -contains $EditionTag) -and
                    $_.Language -eq $LanguageTag
                }
                if ($null -eq $iso) {
                    Write-Log -Severity Warning "No ISO found for build $TargetBuildNumber, arch $archName, edition $EditionTag, language $LanguageTag. Exiting with exit code 1."
                    exit 1
                }
                $Download_Path = $iso.Url
                $ExpectedISOSize = $iso.ISOSize
                $ExpectedFolderSize = $iso.FolderSize
                $ExpectedFileHash = $iso.Hash

                Write-Debug "After setting the download path, the Download_Path is $($Download_Path)."

                # Check if any of the required variables are empty
                if (-not $Download_Path -or -not $ExpectedFolderSize -or -not $ExpectedISOSize -or -not $ExpectedFileHash) {
                    Write-Log -Severity Warning "One or more required variables are null. Exiting the script."
                    exit 1
                }
            }
        } # if not using enablement package
        else {
            # Enablement package will be used
            $EnablementPackageFile = "$Win11Directory\Win11_25H2_Enablement_$archName.msu"
        } # else using enablement package

        # Enablement Package Installation Logic
        if ($EnablementPackage -and $EnablementPackageAvailable) {
            # Check if the MSU file exists and matches the expected hash before downloading
            $msuPresentAndValid = $false
            if (Test-Path $EnablementPackageFile) {
                Write-Log "Enablement package file is present. Verifying hash..."
                $actualHash = (Get-FileHash -Path $EnablementPackageFile -Algorithm SHA256).Hash
                if ($actualHash -eq $EnablementPackageHash) {
                    Write-Log "Enablement package file matches the expected hash. Skipping download."
                    $msuPresentAndValid = $true
                }
                else {
                    Write-Log -Severity Warning "Enablement package file hash does not match expected. Deleting and re-downloading."
                    Remove-Item -Path $EnablementPackageFile -Force
                }
            }

            if (-not $msuPresentAndValid) {
                try {
                    Download-File -SourceUrl $EnablementPackageUrl -Destination $EnablementPackageFile -ExpectedHash $EnablementPackageHash
                }
                catch {
                    Write-Log -Severity Error "Failed to download enablement package. Error: $_"
                    Remove-ProgressHelperScripts
                    exit 1
                }
            }

            $wusaArgs = "`"$EnablementPackageFile`" /quiet /norestart"

            Write-Log "A reboot is required post-installation. The reboot will be suppressed."
            Write-Log "The enablement package installation command: 'wusa.exe $wusaArgs'"
            Write-Log "Installing the enablement package using wusa.exe..."
            $wusaProcess = Start-Process -FilePath "wusa.exe" -ArgumentList $wusaArgs -Wait -PassThru

            # Output total run time for wusa.exe
            if ($wusaProcess) {
                $wusaDuration = $wusaProcess.ExitTime - $wusaProcess.StartTime
                Write-Log "wusa execution complete. Total runtime: $($wusaDuration.ToString('hh\:mm\:ss')). Checking Event Viewer for confirmation of success."
            }
            else {
                Write-Log -Severity Warning "wusa execution complete. Failed to retrieve wusa process information after installation. Checking Event Viewer for confirmation of success."
            }
            
            # Wait a few seconds to allow the event to be written to the log
            Write-Log "Waiting 5 seconds for Event Viewer to update..."
            Start-Sleep -Seconds 5

            # Get the most recent relevant WUSA event (ID 2 or 3) from the Setup log
            $wusaEvents = Get-WinEvent -LogName Setup -MaxEvents 30 | Where-Object {
                $_.ProviderName -eq "Microsoft-Windows-WUSA" -and ($_.Id -eq 2 -or $_.Id -eq 3)
            }

            # Find the most recent event for this enablement package attempt
            $evt = $null
            foreach ($ev in $wusaEvents) {
                if ($ev.Id -eq 2 -and $ev.Message -match "KB5054156") {
                    $evt = $ev
                    break
                }
                elseif ($ev.Id -eq 3 -and $ev.Message -match "2359302") {
                    # ID 3 with error 2359302 means "already installed"
                    $evt = $ev
                    break
                }
            }

            if ($evt) {
                if ($evt.Id -eq 2) {
                    Write-Log "Enablement package KB5054156 installed successfully, as confirmed in Event Viewer (Event ID 2)."
                }
                elseif ($evt.Id -eq 3) {
                    Write-Log "Enablement package KB5054156 is already installed (Event ID 3, error 2359302). Pending reboot to complete activation."
                }
                $pendingRebootValue = "Pending Reboot Enablement Package / TargetBuild $TargetBuildNumber / $(Get-Date -Format 'MM-dd-yyyy HH:mm:ss')"
                $currentCF = Ninja-Property-Get windowsMajorVersionUpgradeState
                if ($null -eq $currentCF -or $currentCF -notmatch "^Pending Reboot Enablement Package") {
                    Write-Log "Updating the windowsMajorVersionUpgradeState custom field to '$pendingRebootValue'."
                    Ninja-Property-Set windowsMajorVersionUpgradeState $pendingRebootValue
                    Suspend-BitLockerUntilReboot
                }

                # Delete the MSU file before exiting
                if (Test-Path $EnablementPackageFile) {
                    try {
                        Remove-Item -Path $EnablementPackageFile -Force
                        Write-Log "Deleted the enablement package file at $EnablementPackageFile."
                    }
                    catch {
                        Write-Log -Severity Warning "Failed to delete the enablement package file at $EnablementPackageFile. Error: $_"
                    }
                }
                Write-Log "Script execution complete. Exiting with exit code 0."
                Remove-ProgressHelperScripts
                exit 0
            }
            else {
                Write-Log -Severity Warning "The Enablement package installation completed but confirmation of success or already-installed state was not found in Event Viewer."
                Write-Log "Script execution complete. Exiting."
                Remove-ProgressHelperScripts
                exit 1
            }       
        } # if EnablementPackage

        # Write-Log "ISO download URL: $($Download_Path)."
       
        # Installer paths
        $Installer_ISO_Path = "$Win11Directory\Win11.iso"
        $ISOFolderPath = "$Win11Directory\SetupFolder"
        $Installer_exe = "Setup.exe"  
        
        # Initialize sleep variables for later use
        $originalAC = $null
        $originalDC = $null
        #endregion initializing variables
        
        # Disable sleep during upgrade if specified
        if ($DisableSleepDuringUpgrade) {
            Write-Log "Disabling sleep during upgrade."
            $SleepSettingsAlreadyDisabled = $false
            try {
                $originalAC = (powercfg -q scheme_current sub_sleep standbyidle | Select-String "Current AC Power Setting Index").ToString().Split(":")[-1].Trim()
                $originalDC = (powercfg -q scheme_current sub_sleep standbyidle | Select-String "Current DC Power Setting Index").ToString().Split(":")[-1].Trim()
                $originalACMin = [convert]::ToInt32($originalAC, 16) / 60
                $originalDCMin = [convert]::ToInt32($originalDC, 16) / 60

                if ($originalACMin -eq 0 -and $originalDCMin -eq 0) {
                    Write-Log "Sleep is already disabled for both AC and DC power. No changes made."
                    $SleepSettingsAlreadyDisabled = $true
                }
                else {
                    Write-Log "Saving current sleep settings... (AC: $originalAC ($originalACMin minutes), DC: $originalDC ($originalDCMin minutes))"
                    powercfg /change standby-timeout-ac 0
                    powercfg /change standby-timeout-dc 0
                    Write-Log "Sleep disabled for AC and DC power."
                }
            }
            catch {
                Write-Log -Severity Warning "Failed to disable sleep settings: $_"
            }
        } # if DisableSleepDuringUpgrade

        # Clean up existing ISO and setup folder if CustomISOUrl is specified
        # Since we can't validate if existing files match the custom URL, always start fresh
        if ($CustomISOUrl) {
            if ((Test-Path $ISOFolderPath) -or (Test-Path $Installer_ISO_Path)) {
                Write-Log "CustomISOUrl specified. Removing any existing ISO or setup folder to ensure fresh download..."
            
                if (Test-Path $ISOFolderPath) {
                    try {
                        Remove-Item -Path $ISOFolderPath -Recurse -Force -ErrorAction Stop
                        Write-Log "Deleted existing setup folder at $ISOFolderPath."
                    }
                    catch {
                        Write-Log -Severity Warning "Failed to delete existing setup folder at $ISOFolderPath. Error: $($_.Exception.Message)"
                        Write-Log -Severity Info "Exiting with exit code 1."
                        Remove-ProgressHelperScripts
                        exit 1
                    }
                }
            
                if (Test-Path $Installer_ISO_Path) {
                    try {
                        Remove-Item -Path $Installer_ISO_Path -Force -ErrorAction Stop
                        Write-Log "Deleted existing ISO file at $Installer_ISO_Path."
                    }
                    catch {
                        Write-Log -Severity Warning "Failed to delete existing ISO file at $Installer_ISO_Path. Error: $($_.Exception.Message)"
                        Write-Log -Severity Info "Exiting with exit code 1."
                        Remove-ProgressHelperScripts
                        exit 1
                    }
                }
            } # if existing ISO or setup folder
        } # if CustomISOUrl

        # Verify ISO exists when SkipValidation is used
        if ($SkipValidation -and -not (Test-Path $Installer_ISO_Path)) {
            Write-Log -Severity Warning "SkipValidation specified but ISO file not found at $Installer_ISO_Path."
            Write-Log -Severity Info "Place your ISO file at: $Installer_ISO_Path and run the script again."
            Write-Log -Severity Info "Exiting with exit code 1."
            Remove-ProgressHelperScripts
            exit 1
        }

        # Clean up existing setup folder if SkipValidation is used (for when you supply your own ISO)
        if ($SkipValidation -and (Test-Path $ISOFolderPath)) {
            Write-Log "SkipValidation specified. Removing existing setup folder to ensure fresh extraction..."
            try {
                Remove-Item -Path $ISOFolderPath -Recurse -Force -ErrorAction Stop
                Write-Log "Removed existing setup folder at $ISOFolderPath."
            }
            catch {
                Write-Log -Severity Warning "Failed to remove existing setup folder: $_"
                Write-Log -Severity Info "Exiting with exit code 1."
                Remove-ProgressHelperScripts
                exit 1
            }
        } # if SkipValidation

        Write-Log -IsPhaseMarker "---- [PHASE 2: ISO Download] ----"
        Write-Log "Checking if the ISO file and/or the setup folder are present..."

        # Initialize flag for ISO presence and validity
        $ISOPresentAndValid = $false
        # Initialize flag for the extracted folder presence and validity
        $ISOFolderPresentAndValid = $false

        # if SkipValidation was used, this should return false since we already deleted the folder earlier
        if (Test-Path $ISOFolderPath) { 
            $folderSize = Get-ChildItem -Path $ISOFolderPath -Recurse -ErrorAction SilentlyContinue | 
            Measure-Object -Property Length -Sum | 
            Select-Object -ExpandProperty Sum
            
            # Skip size validation if using custom ISO URL
            if ($CustomISOUrl) {
                $ISOFolderPresentAndValid = $true  
                Write-Log "The setup folder is present. Skipping size validation (custom ISO URL specified)."
                
                # The ISO file should in theory already be deleted on a previous run if a valid setup folder is present from then, but if for some reason it's not, delete it
                if (Test-Path -Path $Installer_ISO_Path) {
                    try {
                        Remove-Item -Path $Installer_ISO_Path -Force -ErrorAction Stop
                        Write-Log "Deleted leftover ISO file at $Installer_ISO_Path."
                    }
                    catch {
                        Write-Log -Severity Warning -Message "Failed to delete leftover ISO file at $Installer_ISO_Path. Error: $($_.Exception.Message)"
                    }
                }
                # If the 7zip folder is present from a previous run, delete it as well
                $sevenZipFolder = "$Win11Directory\7zip"
                if (Test-Path -Path $sevenZipFolder) {
                    try {
                        Remove-Item -Path $sevenZipFolder -Recurse -Force -ErrorAction Stop
                        Write-Log "Deleted leftover 7zip folder at $sevenZipFolder."
                    }
                    catch {
                        Write-Log -Severity Warning -Message "Failed to delete leftover 7zip folder at $sevenZipFolder. Error: $($_.Exception.Message)"
                    }
                }
            }
            elseif ($folderSize -eq $ExpectedFolderSize) {
                $ISOFolderPresentAndValid = $true  
                Write-Log "The setup folder is present and matches the expected size."
            
                # The ISO file should be deleted if a valid setup folder is present from a previous run, but if for some reason it's not, delete it
                if (Test-Path -Path $Installer_ISO_Path) {
                    try {
                        Remove-Item -Path $Installer_ISO_Path -Force -ErrorAction Stop
                        Write-Log "Deleted leftover ISO file at $Installer_ISO_Path."
                    }
                    catch {
                        Write-Log -Severity Warning -Message "Failed to delete leftover ISO file at $Installer_ISO_Path. Error: $($_.Exception.Message)"
                    }
                }
                # If the 7zip folder is present from a previous run, delete it as well
                $sevenZipFolder = "$Win11Directory\7zip"
                if (Test-Path -Path $sevenZipFolder) {
                    try {
                        Remove-Item -Path $sevenZipFolder -Recurse -Force -ErrorAction Stop
                        Write-Log "Deleted leftover 7zip folder at $sevenZipFolder."
                    }
                    catch {
                        Write-Log -Severity Warning -Message "Failed to delete leftover 7zip folder at $sevenZipFolder. Error: $($_.Exception.Message)"
                    }
                }
            }
            else {
                Write-Log -Severity Warning "The setup folder is present but does not match the expected size. Deleting the folder..."
                try {
                    Remove-Item -Path $ISOFolderPath -Recurse -Force -ErrorAction Stop
                    Write-Log "Deleted the invalid setup folder at $ISOFolderPath."
                }
                catch {
                    Write-Log -Severity Warning "Failed to delete the invalid setup folder at $ISOFolderPath. Error: $($_.Exception.Message)"
                    Remove-ProgressHelperScripts
                    Write-Log -Severity Info "Exiting the script."
                    exit 1
                }
            }
        } # if setup folder is present

        if ($ISOFolderPresentAndValid -eq $false) {
            if (Test-Path -Path $Installer_ISO_Path) {               
                # Skip size validation if using custom ISO URL or SkipValidation
                if ($CustomISOUrl -or $SkipValidation) {
                    Write-Log "ISO file present. Skipping ISO file size and hash validation (custom ISO URL or SkipValidation specified)."
                    $ISOPresentAndValid = $true
                }
                else {
                    Write-Log "The ISO file is present. Verifying the file size..."
                    $ISOFileSize = (Get-Item -Path $Installer_ISO_Path).Length
                
                    if ($ISOFileSize -eq $ExpectedISOSize) {
                        Write-Log "The ISO file size matches the expected size."
                        $ISOPresentAndValid = $true
                    }
                    else {
                        Write-Log -Severity Warning "The ISO file size does not match the expected size. Deleting the file..."
                        try {
                            Remove-Item -Path $Installer_ISO_Path -Force -ErrorAction Stop
                            Write-Log "Deleted the ISO file at $Installer_ISO_Path."
                        }
                        catch {                        
                            Write-Log -Severity Warning -Message "Failed to delete the invalid ISO file at $Installer_ISO_Path. Error: $($_.Exception.Message)"
                            Remove-ProgressHelperScripts
                            Write-Log -Severity Info "Exiting the script."
                            exit 1
                        }
                    } # else ISO size does not match
                } # else not CustomISOUrl or SkipValidation
            } # if ISO file is present
    
            if ($ISOPresentAndValid -eq $false) {            
                # Check for sufficient free space on the system drive for the download
                Write-Log "Checking for sufficient free space on the system drive for the download..."
                if ($AvoidGetVolume -eq $true) {
                    $FreeSpaceGB = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
                }
                else {
                    $FreeSpaceGB = [math]::Round((Get-Volume -DriveLetter C -ErrorAction Stop).SizeRemaining / 1GB, 2)
                }
                if ($FreeSpaceGB -lt 15) {
                    Write-Log -Severity Warning "There are $FreeSpaceGB GB free on the system drive. At least 15 GB is required."
                    Remove-ProgressHelperScripts
                    Write-Log -Severity Info "The helper scripts have been removed from $($Win11Directory)."
                    Write-Log -Severity Info "Exiting the script."
                    return
                }
                else {
                    Write-Log "There are $FreeSpaceGB GB free on the system drive. Proceeding."
                }

                # Check battery and sleep settings before initializing download
                $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
                $onBattery = $battery -and $battery.BatteryStatus -eq 1

                $sleepWarning = $null
                if ($onBattery) {
                    $sleepWarning = Check-SleepSettings
                    if ($sleepWarning) {
                        # Write-Log -Severity Warning -Message "Machine is running on battery and sleep when idle while on battery is set to 10 minutes or less."
                        Write-Log -Severity Warning -Message $sleepWarning
                        Write-Log -Severity Info -Message "Exiting with exit code 1."
                        Remove-ProgressHelperScripts
                        exit 1
                    }
                }
            
                # Download the ISO file using the Download-File function
                Write-Debug "Downloading the Windows 11 $($Version) ISO from $($Download_Path) and saving to $($Installer_ISO_Path)."
                # Write-Log -Severity Debug "Downloading the Windows 11 $($Version) ISO from $($Download_Path) and saving to $($Installer_ISO_Path)."
                Write-Log "To monitor the ISO download progress run helper script C:\Win11\Show-BitsProgress.ps1 at a console. To test throughput during download, run C:\Win11\Invoke-SpeedTest.ps1 (add optional -All). Run 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process' if you're blocked from running helper scripts."
                try {
                    # Skip hash validation if using custom ISO URL and use browser headers with Invoke-WebRequest to avoid 403 errors
                    if ($CustomISOUrl) {
                        Download-File -SourceUrl $Download_Path -Destination $Installer_ISO_Path #-UseBrowserHeaders
                    }
                    else {
                        Download-File -SourceUrl $Download_Path -Destination $Installer_ISO_Path -ExpectedHash $ExpectedFileHash
                    }
                }
                catch {
                    Write-Log -Severity Warning "An unexpected error occurred during the attempt to download the ISO. Error: $_"
                    Remove-ProgressHelperScripts
                    Write-Log -Severity Info "Exiting the script."
                    exit
                }
            } # if ISO file is not valid or is missing
        } # if ISO extracted folder is not present or not valid
        

        Write-Log "Checking that there are at least 10 GB free on the system drive..."
        # $freeSpaceGB = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
        if ($AvoidGetVolume -eq $true) {
            $freeSpaceGB = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
        }
        else {
            $freeSpaceGB = [math]::Round((Get-Volume -DriveLetter C).SizeRemaining / 1GB, 2)
        }
        Write-Log "There are $freeSpaceGB GB free on C:."
        if ($freeSpaceGB -lt 10) {
            Write-Log -Severity Warning "There isn't enough free space on the system drive. At least 10 GB is required. Leaving the ISO file or setup folder in place for the next attempt and exiting the script."
            Remove-ProgressHelperScripts
            Write-Log -Severity Info "The helper scripts have been removed from $($Win11Directory)."
            return
        } # if free space is less than 10 GB

        
        # Mount the ISO file
        # $mountedDrive = Mount-ISOFile -ISO_Path $Installer_ISO_Path
        
        # Remove download-stage helper scripts from C:\Win11
        Remove-Item 'C:\Win11\Show-BitsProgress.ps1', 'C:\Win11\Invoke-SpeedTest.ps1' -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed the Show-BitsProgress.ps1 and Invoke-SpeedTest.ps1 helper scripts."

        #region ISO Extraction
        Write-Log -IsPhaseMarker "---- [PHASE 3: ISO Extraction] ----"
        if ($ISOFolderPresentAndValid -eq $false) {
            # Extract the contents of the ISO file to a temporary folder. Create the folder if it doesn't exist.  
            if (Test-Path -Path $ISOFolderPath) {
                # cannot use '().Sum' in the next line since Strict Mode will throw an error if the setup folder is empty and we call a property on $null
                $folderSize = Get-ChildItem -Path $ISOFolderPath -Recurse -ErrorAction SilentlyContinue | 
                Measure-Object -Property Length -Sum | 
                Select-Object -ExpandProperty Sum
                
                # Skip size validation if using custom ISO URL
                if ($CustomISOUrl) {
                    Write-Log "The ISO file has already been extracted to $($ISOFolderPath). Skipping size validation (custom ISO URL specified)."
                }
                elseif ($folderSize -eq $ExpectedFolderSize) {
                    Write-Log "The ISO file has already been extracted to $($ISOFolderPath) and matches the expected folder size."
                }
                else {
                    Write-Log -Severity Warning "The ISO setup folder is already present but its size does not match the expected folder size. Deleting the folder and re-extracting the ISO..."
                    Remove-Item -Path $ISOFolderPath -Recurse -Force -ErrorAction SilentlyContinue
                    New-Item -ItemType Directory -Path $ISOFolderPath | Out-Null
                    try {
                        # Skip folder size validation parameter if using custom ISO URL
                        if ($CustomISOUrl) {
                            Extract-ISO -SourceFile $Installer_ISO_Path -DestinationFolder $ISOFolderPath
                        }
                        else {
                            Extract-ISO -SourceFile $Installer_ISO_Path -DestinationFolder $ISOFolderPath -expectedExtractedFolderSize $ExpectedFolderSize
                        }
                    }
                    catch {
                        Write-Log -Severity Warning "An unexpected error occurred during the attempt to re-extract the ISO. Error: $_"
                        return
                    }
                } # if folder exists and size does not match
            } # if folder exists
            else {
                New-Item -ItemType Directory -Path $ISOFolderPath | Out-Null
                try {
                    # Skip folder size validation parameter if using custom ISO URL
                    if ($CustomISOUrl) {
                        Extract-ISO -SourceFile $Installer_ISO_Path -DestinationFolder $ISOFolderPath
                    }
                    else {
                        Extract-ISO -SourceFile $Installer_ISO_Path -DestinationFolder $ISOFolderPath -expectedExtractedFolderSize $ExpectedFolderSize
                    }
                }
                catch {
                    Write-Log -Severity Warning "An unexpected error occurred during the attempt to extract the ISO. Error: $_"
                    return
                }    
            } # if folder does not exist
        } # if ISO extracted folder is not present or not valid
        #endregion ISO Extraction

        # If DownloadAndExtractOnly parameter was specified, create marker file and exit
        if ($DownloadAndExtractOnly) {
            # Create marker file to prevent automatic cleanup by controller script
            $markerContent = @"
The Windows 11 Setup Files were extracted using the -DownloadAndExtractOnly parameter of the upgrade script.
Extracted - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

PURPOSE & USAGE:

1. DISM RestoreHealth (recommended - repairs Windows component corruption)
   Dism /Online /Cleanup-Image /RestoreHealth /Source:C:\Win11\SetupFolder /LimitAccess
   
   Note: Remove /LimitAccess to allow fallback to Windows Update

2. DISM with WIM file (requires edition index selection)
   Step 1: Dism /Get-WimInfo /WimFile:C:\Win11\SetupFolder\sources\install.wim
   Step 2: Dism /Online /Cleanup-Image /RestoreHealth /Source:WIM:C:\Win11\SetupFolder\sources\install.wim:6 /LimitAccess

3. Manual Windows upgrade: Run C:\Win11\SetupFolder\setup.exe

CLEANUP:
When finished delete this file to allow auto-cleanup.
"@
            $markerContent | Set-Content "$Win11Directory\DO_NOT_AUTO_DELETE.txt" -Force
            
            Write-Log "The ISO has been successfully downloaded and extracted to: $ISOFolderPath."
            Write-Log "You can use this with DISM RestoreHealth. For detailed instructions, see: $Win11Directory\DO_NOT_AUTO_DELETE.txt"
            Write-Log "Created marker file DO_NOT_AUTO_DELETE.txt in $Win11Directory to prevent automatic cleanup by the controller script. Delete the marker file to re-enable auto-cleanup."
            Write-Log "The 'DownloadAndExtractOnly' parameter was specified. Exiting the script without running the upgrade."
            Remove-ProgressHelperScripts
            return
        }

        #region Installation
        Write-Log -IsPhaseMarker "---- [PHASE 4: Upgrade Installation] ----"
        # Construct the path to the setup.exe file
        $setupPath = "$($ISOFolderPath)\$Installer_exe"
        Write-Log "Checking for the presence of setup.exe in $($ISOFolderPath)."
        if (-not (Test-Path -Path $setupPath)) {
            Write-Log -Severity Warning "Setup.exe not found in $($ISOFolderPath). Exiting the script."
            return
        } # if setup.exe not found
        else {
            Write-Log "Setup.exe is present."
        }

        # Construct arguments for the setup.exe command using a hash table
        # https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-command-line-options?view=windows-11
        if ($InPlaceUpgrade) {
            Write-Log "Constructing the arguments for IN-PLACE REPAIR installation..."
            $upgradeArgs = [ordered]@{
                "/auto"           = "upgrade"           # Still use upgrade mode
                "/quiet"          = $null
                "/showoobe"       = "none"
                "/compat"         = "ignorewarning"
                "/dynamicupdate"  = "disable"           # Don't try to download newer version
                "/EULA"           = "accept"
                "/noreboot"       = $null
                "/copylogs"       = "`"$Win11Directory\Windows11SetupLogs`""
        
                # Explicitly keep everything during repair
                "/MigrateDrivers" = "all"              # Keep all drivers
                #"/Telemetry"               = "Disable"          # Optional: disable telemetry during repair
                #"/ResizeRecoveryPartition" = "disable" # Don't resize recovery partition
            }
        }
        else {
            if (!$RebootAfterUpgrade) {
                Write-Log "Constructing the arguments for setup.exe. NOTE: The system will NOT automatically reboot after the upgrade."    
            } 
            else {
                Write-Log "Constructing the arguments for setup.exe. NOTE: The system will be manually rebooted after the upgrade."
            }
            
            $upgradeArgs = [ordered]@{
                "/auto"          = "upgrade"
                "/quiet"         = $null
                "/showoobe"      = "none"
                "/compat"        = "ignorewarning"
                "/dynamicupdate" = "enable"
                "/EULA"          = "accept"
                "/noreboot"      = $null
                "/copylogs"      = "`"$Win11Directory\Windows11SetupLogs`""
            }
        }        
        
        # Conditionally add the /product argument for non-Win11-compatible machines
        if ($UnsupportedHardware) {
            Write-Log "The 'UnsupportedHardware' parameter was used. Adding the '/product server' argument to bypass hardware compatibility checks."
            $upgradeArgs["/product"] = "server"
        }
        # Conditionally add the /bitlocker argument for BitLocker suspension
        #if (-not $SuppressReboot) {
        #    $upgradeArgs["/bitlocker"] = "AlwaysSuspend"
        #}
        

        # Convert the hash table to a string of arguments
        $argsString = ($upgradeArgs.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join " "
        
        # Initialize the upgrade success flag
        $upgradeSuccess = $false
                
        <#
        if ($SuppressReboot) {
            Write-Log "The 'SuppressReboot' parameter was used. The system will not reboot automatically after the upgrade."
        }
        else {
            Write-Log "The 'SuppressReboot' parameter was NOT used. The system will reboot automatically after a successful upgrade."
        }
        #>
        # For now I've disabled the SuppressReboot parameter and relevant logic until we iron out the post-reboot script and scheduled task.
        # Instead we're using the /noreboot argument to prevent the automatic reboot after the upgrade, and manual reboots will be required after the upgrade.
        # Write-Log "The system will NOT automatically reboot after the upgrade."
        
        # Output the command with arguments for debugging purposes
        Write-Log "The upgrade command: '$($setupPath)' $($argsString)"
        
        Write-Log "To monitor the upgrade progress run helper script C:\Win11\Show-UpgradeProgress.ps1 at a console. Run 'Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process' if you're blocked from running the script."

        Write-Log "Starting the installation. Please wait..."

        if ($MonitorProgress) {
            # Start setup.exe without -Wait, capture the process object
            $setupProcess = Start-Process -FilePath $setupPath -ArgumentList "$($argsString)" -NoNewWindow -PassThru

            # Monitor progress while setup.exe is running, log the progress to a separate log file
            $progressLogFile = "$($Win11Directory)\ProgressResults.log"
            Write-Log "The MonitorProgress parameter is enabled. Progress status will be written to $($progressLogFile). Run 'Get-Content $($progressLogFile) -Tail 1 -Wait' to view the progress in real-time."
            # Ensure the progress log file exists, create it if it doesn't
            if (-not (Test-Path $progressLogFile)) {
                New-Item -Path $progressLogFile -ItemType File -Force | Out-Null
            }
            else {
                # Clear the contents of the progress log file if it already exists
                Clear-Content -Path $progressLogFile -ErrorAction SilentlyContinue
            }

            # Wait until process SetupHost starts, as only then does the SetupProgress Registry key below get populated
            Write-Log "Waiting for SetupHost process to begin before monitoring upgrade progress..."
            while (-not (Get-Process -Name SetupHost -ErrorAction SilentlyContinue)) {
                Start-Sleep -Seconds 5
            }

            # Log previous SetupProgress value if present
            # (Will cause issues with strict mode enabled..)
            $existingProgress = (Get-ItemProperty HKLM:\SYSTEM\Setup\MoSetup\Volatile -Name SetupProgress -ErrorAction SilentlyContinue).SetupProgress
            if ($existingProgress) {
                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Add-Content -Path $progressLogFile -Value "[$Timestamp] [Progress] Previous SetupProgress value detected: $($existingProgress)%"
                Add-Content -Path $progressLogFile -Value "(This value is from a previous run and may not reflect the current upgrade.)"
                Add-Content -Path $progressLogFile -Value "" # Blank line
                Add-Content -Path $progressLogFile -Value "===== Current Upgrade Progress ====="
                Add-Content -Path $progressLogFile -Value "" # Blank line
                # Wait 10 seconds to give time for the progress value to update
                Start-Sleep -Seconds 10
            }
    
            while (-not $setupProcess.HasExited) {
                $progress = (Get-ItemProperty HKLM:\SYSTEM\Setup\MoSetup\Volatile -Name SetupProgress -ErrorAction SilentlyContinue).SetupProgress
                if ($progress) {
                    try {
                        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        $progressLogEntry = "[$Timestamp] [Progress] Upgrade progress: $progress%"
                        Add-Content -Path $progressLogFile -Value $progressLogEntry
                        # Set-Content -Path $progressLogFile -Value $progressLogEntry
                        Start-Sleep -Seconds 30    
                    }
                    catch {
                        Write-Log -Severity Warning "An error occurred while monitoring the setup progress. Error: $_"
                        # Wait until setup.exe has exited
                        while (-not $setupProcess.HasExited) {
                            Start-Sleep -Seconds 30
                        }
                    }
                } # if $progress
            } # end While loop

            # Since -wait is not used, ensure PowerShell waits for all process resources to be released and the exit code to be set
            $setupProcess.WaitForExit()
            # WaitForExit on its own doesn't seem to be enough here, adding a 10 second wait as well
            Start-Sleep -Seconds 10

            # Wait for all setup processes to complete if RebootAfterUpgrade was specified
            if ($RebootAfterUpgrade) {
                Wait-SetupProcessesComplete -MaxWaitMinutes 5
            }

            if ($progressLogEntry) {
                # $setupProcess has exited, continue with the rest of the script
                Add-Content -Path $progressLogFile -Value "Setup.exe has exited. The last progress entry was: $($progressLogEntry). Return to the main log file at $($LogFilePath)."
            }
            else {
                Add-Content -Path $progressLogFile -Value "Setup.exe has exited. No progress entries were recorded. Return to the main log file at $($LogFilePath)."
            }
        } # if $MonitorProgress
        else {
            # Start the setup.exe process with the constructed arguments and retrieve the process object
            $setupProcess = Start-Process -FilePath $setupPath -ArgumentList "$($argsString)" -Wait -NoNewWindow -PassThru

            # Wait for all setup processes to complete only if RebootAfterUpgrade was specified
            if ($RebootAfterUpgrade) {
                Wait-SetupProcessesComplete -MaxWaitMinutes 5
            }
        } # if !$MonitorProgress
       
        # Use this section to monitor the setup.exe upgrade progress in real-time, when running interactively. 
        # You'll need to paste this in a sep. console window since setup.exe is configured to hold up the console with the -wait parameter.
        # This is not for use when running via Ninja as it will clutter the output in the Activities section.
        # <<< NOTE: This is no longer needed with the Show-UpgradeProgress helper script. Just run that script in a separate console to monitor progress (C:\Scripts\Show-UpgradeProgress.ps1). >>>
        <#
        $startTime = Get-Date
        While (Get-Process -Name Setup* -ErrorAction SilentlyContinue) {
            $progress = (Get-ItemProperty HKLM:\SYSTEM\Setup\MoSetup\Volatile -Name SetupProgress -ErrorAction SilentlyContinue).SetupProgress
            Write-Host "`rUpgrade progress: $progress%" -NoNewline
            Start-Sleep -Seconds 10

            # Check if the process has been running for more than 3 hours
            if ((Get-Date) - $startTime -gt (New-TimeSpan -Hours 3)) {
            Write-Log -Severity Warning "Setup process has been running for more than 3 hours. Exiting the loop."
            break
            }
        }
        #>

        if ($Env:MonitorProgress -eq "true") {
            try {
                $finalProgress = (Get-ItemProperty HKLM:\SYSTEM\Setup\MoSetup\Volatile -Name SetupProgress -ErrorAction SilentlyContinue).SetupProgress
                if ($finalProgress) {
                    Write-Log "Final SetupProgress Registry value after setup.exe exited: $finalProgress%"
                }
                else {
                    Write-Log -Severity Warning -Message "No SetupProgress Registry value found after setup.exe exited."
                }
            }
            catch {
                Write-Log -Severity Warning -Message "Could not read SetupProgress Registry value after setup.exe exited. Error: $($_.Exception.Message)"
            }
        }

        # Calculate the duration of the setup.exe process
        $duration = $setupProcess.ExitTime - $setupProcess.StartTime
        if ($duration) {
            Write-Log "Total runtime for the setup.exe upgrade process: $($duration.ToString("hh\:mm\:ss"))."    
        }
        

        # Check the exit code of the setup.exe process
        if ($setupProcess.ExitCode) {
            if ($setupProcess.ExitCode -eq 0) {
                Write-Log "Setup.exe completed successfully with exit code 0."  
                # $upgradeSuccess = $true
            }
            else {
                # Convert the decimal representation of the setup.exe exit code to hex
                $hexExitCode = Convert-DecimalToHex -Number $setupProcess.ExitCode
                Write-Log -Severity Warning "Setup.exe failed with exit code $($setupProcess.ExitCode) ($hexExitCode in hex)."
                if ($setupProcess.ExitCode -eq '-2147023278') {
                    Write-Log -Severity Warning "Exit code meaning: '0x80070652 -2147023278 ERROR_INSTALL_ALREADY_RUNNING ErrorClientUpdateInProgress'. (See https://learn.microsoft.com/en-us/archive/technet-wiki/15260.windows-update-agent-error-codes.)"
                }
            }
        }
        #else {
        #    Write-Log -Severity Warning "Setup.exe did not return an exit code. Checking the logs.."
        #}
        #endregion Installation

        <#
        #Region DEBUG
        Write-Log "BEGIN DEBUG checks"
        # Check for presence and size of the $WINDOWS.~BT\NewOS folder
        $stagedFolder = "C:\`$WINDOWS.~BT\NewOS"
        if (Test-Path $stagedFolder) {
            $folderSize = (Get-ChildItem -Path $stagedFolder -Recurse | Measure-Object -Property Length -Sum).Sum
            Write-Log -Severity Debug "NewOS folder detected at $stagedFolder. Current size of the folder: $([math]::Round($folderSize / 1GB, 2)) GB."
            #
            #if ($folderSize -gt 5GB) {
            #    Write-Log -Severity Debug "Current size of the NewOS folder: $([math]::Round($folderSize / 1GB, 2)) GB. The NewOS folder appears to be fully staged."
            #}
            #else {
            #    Write-Log -Severity Debug "Current size of the NewOS folder: $([math]::Round($folderSize / 1GB, 2)) GB. The NewOS folder may not be fully staged."
            #}
            #
        }
        else {
            Write-Log -Severity Debug "No NewOS folder found at $stagedFolder."
        }

        # Check for presence of Windows.old folder after upgrade
        $windowsOldPath = "$env:SystemDrive\Windows.old"
        if (Test-Path -Path $windowsOldPath) {
            Write-Log -Severity Debug -Message "Windows.old folder detected at $windowsOldPath."
            # $windowsOldSize = (Get-ChildItem -Path $windowsOldPath -Recurse | Measure-Object -Property Length -Sum).Sum
            # Write-Log -Severity Debug -Message "Windows.old folder size: $([math]::Round($windowsOldSize / 1GB, 2)) GB."
        }
        else {
            Write-Log -Severity Debug -Message "Windows.old folder not detected at $windowsOldPath."
        }

        # After setup.exe exits, check if other setup-related processes are still running
        $otherSetupProcesses = Get-Process | Where-Object { $_.Name -match '^SetupHost$|^SetupPrep$' } -ErrorAction SilentlyContinue
        if ($otherSetupProcesses) {
            $procNames = $otherSetupProcesses | Select-Object -ExpandProperty Name
            Write-Log -Severity Debug "Setup.exe has exited, but the following setup processes are still running: $($procNames -join ', ')."
        }
        else {
            Write-Log -Severity Debug "Setup.exe exited. No additional setup-related processes (SetupHost, SetupPrep) are running. Proceeding with post-upgrade checks."
        }
        Write-Log "END DEBUG checks"
        #Endregion DEBUG
        #>

        # Remove the upgrade progress monitoring script from C:\Win11
        Remove-Item 'C:\Win11\Show-UpgradeProgress.ps1' -Force -ErrorAction SilentlyContinue
        Write-Log -Message "Removed the Show-UpgradeProgress.ps1 helper script."

        # Restore original sleep settings if they were modified before the upgrade
        Restore-SleepSettings

        #region Post-Install Checks
        if (Test-Path -Path "$Win11Directory\Windows11SetupLogs\Panther\setupact.log") {
            Write-Log "The setupact log file was copied to `"$Win11Directory\Windows11SetupLogs\Panther\setupact.log.`" (It can also be found in the usual location: `"C:\`$Windows.~BT\Sources\Panther`")."
            # Check the last line of the setupact.log file
            $setupActTail = Get-Content "$Win11Directory\Windows11SetupLogs\Panther\setupact.log" -Tail 1 -ErrorAction SilentlyContinue
            if ($setupActTail) { 
                Write-Log -Message "Last line of the setupact log file: $($setupActTail)"   
            
                if ($setupActTail -like "*Rebooting system*prevented by command line override*") {
                    $upgradeSuccess = $true
                    Write-Log -Message "Upgrade SUCCESSFUL. Rebooting system prevented by command line override."
                
                    # Update the windowsMajorVersionUpgradeState custom field to indicate that a reboot is pending, even if ApplyAutomationControls is not set to true.
                    if ($InPlaceUpgrade) {
                        Write-Log "Updating the windowsMajorVersionUpgradeState custom field to 'Repair completed - Pending Reboot / TargetBuild $TargetBuildNumber / $(Get-Date -Format 'MM-dd-yyyy HH:mm:ss')'."
                        Ninja-Property-Set windowsMajorVersionUpgradeState "Repair completed - Pending Reboot / TargetBuild $TargetBuildNumber / $(Get-Date -Format 'MM-dd-yyyy HH:mm:ss')"        
                    }
                    else {
                        # Preserve "Ticket for manual intervention needed" if present.
                        $pendingRebootDateStr = Get-Date -Format 'MM-dd-yyyy HH:mm:ss'
                        $currentCF = Ninja-Property-Get windowsMajorVersionUpgradeState
                        if ($currentCF -like "*Ticket for manual intervention needed*") {
                            $newCF = "Ticket for manual intervention needed / Pending Reboot / TargetBuild $TargetBuildNumber / $pendingRebootDateStr"
                        }
                        else {
                            $newCF = "Pending Reboot / TargetBuild $TargetBuildNumber / $pendingRebootDateStr"
                        }
                        Write-Log "Updating the windowsMajorVersionUpgradeState custom field to '$newCF'."
                        Ninja-Property-Set windowsMajorVersionUpgradeState $newCF
                    }
                }
                else {
                    # Switch for result codes associated with Windows Setup compatibility warnings, as well as other errors:
                    $resultCodesURL = "https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes#result-codes"
                    $error80070002URL = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-windows-update-error-0x80070002"
                    $error0x80070490URL = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/installing-updates-features-roles/troubleshoot-windows-update-error-0x80070490"
                    # $errorSystemReservedPartitionURL = "https://support.microsoft.com/en-us/topic/-we-couldn-t-update-system-reserved-partition-error-installing-windows-10-46865f3f-37bb-4c51-c69f-07271b6672ac"
                    $preMessage = "Result code message and description:"
                    switch -Wildcard ($setupActTail) {
                        "*0xC1900210*" { Write-Log -Severity Warning -Message "$($preMessage) MOSETUP_E_COMPAT_SCANONLY	Setup didn't find any compat issue.`nSee $($resultCodesURL)." }
                        "*0xC1900208*" { Write-Log -Severity Warning -Message "$($preMessage) MOSETUP_E_COMPAT_INSTALLREQ_BLOCK	Setup found an actionable compat issue, such as an incompatible app.`nSee $($resultCodesURL)." }
                        "*0xC1900204*" { Write-Log -Severity Warning -Message "$($preMessage) MOSETUP_E_COMPAT_MIGCHOICE_BLOCK	The migration choice selected isn't available (ex: Enterprise to Home).`nSee $($resultCodesURL)." }
                        "*0xC1900200*" { Write-Log -Severity Warning -Message "$($preMessage) MOSETUP_E_COMPAT_SYSREQ_BLOCK	The computer isn't eligible for Windows 10.`nSee $($resultCodesURL)." }
                        "*0xC190020E*" { Write-Log -Severity Warning -Message "$($preMessage) MOSETUP_E_INSTALLDISKSPACE_BLOCK	The computer doesn't have enough free space to install.`nSee $($resultCodesURL)." }
                        "*0x80070002*" { Write-Log -Severity Warning -Message "$($preMessage) 0x80070002 -2147024894 ERROR_FILE_NOT_FOUND The System cannot find the file specified.`nSee $($error80070002URL)." }
                        "*0x80070490*" { Write-Log -Severity Info -Message "See $($error0x80070490URL)." }
                    } # switch

                    if ($setupActTail -like "*0xC190020E*") {
                        # If the last line in the logs indicates a disk space issue, extract the amount of space required from the log file
                        # In theory setupdiag can also be used since it pulls the same number from the logs and the upgrade process auto-runs setupdiag when the upgrade fails (with results logged to: C:\Windows\Logs\SetupDiag\*)
                        $diskSpaceLine = Select-String -Path "$Win11Directory\Windows11SetupLogs\Panther\setupact.log" -Pattern 'MOUPG\s+DiskSpace: Required disk space is \[(\d+)\] MB without using external drive' | Select-Object -Last 1
                        if ($diskSpaceLine) {
                            if ($diskSpaceLine -match '\[(\d+)\]') {
                                $neededMB = $Matches[1]
                            }
                            else {
                                $neededMB = $null
                            }
                            if ($neededMB) {
                                Write-Log -Severity Warning -Message "Required free space (pulled from the setupact log file): $neededMB MB."
                            }
                        }
                    }

                    Write-Log -Severity Warning -Message "Upgrade FAILED."
                }
            } # if $SetupActTail is not empty
            else {
                Write-Log -Severity Warning "Failed to read the setupact.log log file."
                # return
            } # else $SetupActTail is empty
        } # if setupact.log file exists
        else {
            Write-Log -Severity Warning "The setupact.log file does not exist at `"$Win11Directory\Windows11SetupLogs\Panther\setupact.log.`". Check `"C:\`$Windows.~BT\Sources\Panther`" for the logs."
        } # if setupact.log file does not exist


        if ($upgradeSuccess -eq $true) {
            if ($InPlaceUpgrade) {
                Write-Log "Leaving the setup folder at $($ISOFolderPath) in place until after the reboot, at which point the controler script will clean up."  
            }
            else {
                Write-Log "Leaving the setup folder at $($ISOFolderPath) in place until after the reboot, at which point the controler script will clean up after confirming the machine is at build number $($TargetBuildNumber)."
            }
            <#
            # Clean up the setup folder
            if (Test-Path -Path $ISOFolderPath) {
                try {
                    Remove-Item -Path $ISOFolderPath -Recurse -Force -ErrorAction Stop
                    Write-Log "The setup folder at $($ISOFolderPath) has been deleted successfully."
                }
                catch {
                    Write-Log -Severity Warning "Failed to delete the setup folder at $($ISOFolderPath). Error: $_"
                }
            }
            else {
                Write-Log -Severity Warning "No setup folder to delete at $($ISOFolderPath)."
            }
            #>

            # Call the Suspend-BitLockerUntilReboot function to suspend BitLocker protection until after the next reboot
            Suspend-BitLockerUntilReboot

            if ($RebootAfterUpgrade) {
                Write-Log "The RebootAfterUpgrade parameter was specified. Restarting the computer to complete the upgrade."
                shutdown.exe /r /t 0 /f /d p:2:3 /c "ITC Windows 11 upgrade completed. Restarting to apply changes."
            }
            else {
                Write-Log "The RebootAfterUpgrade parameter was not specified. Please reboot manually to complete the upgrade."
            }

            <#
            # Check if the reboot was suppressed
            if ($SuppressReboot) {
                Write-Log "Initializing the post-reboot procedure."
                Initialize-RebootProcedure -LogFilePath $LogFilePath -TargetBuildNumber $TargetBuildNumber

                Write-Log "The 'SuppressReboot' parameter was used. The post reboot script will run on next startup. Please reboot the system manually to complete the upgrade."
            }
            else {
                Write-Log "The 'SuppressReboot' parameter was not used. Initializing the post-reboot procedure."
                Initialize-RebootProcedure -LogFilePath $LogFilePath -TargetBuildNumber $TargetBuildNumber

                # Call the Suspend-BitLockerUntilReboot function to suspend BitLocker protection until after the next reboot
                Suspend-BitLockerUntilReboot

                Write-Log "Restarting the computer to complete the upgrade."

                # Restart the system to complete the upgrade
                # <p:2:3:> Type p: Planned / Major Reason Code 2: Operating System. / Minor Reason Code 3: Upgrade.
                shutdown.exe /r /t 0 /f /d p:2:3 /c "ITC Windows 11 upgrade completed. Restarting to apply changes."
            } # if reboot is not suppressed
            #>
        } # if upgrade was successful
        else {
            Write-Log -Severity Warning "The upgrade was not successful. Check the logs for more details. The setup folder at $($ISOFolderPath) has been left in place for the next attempt."
        } # if upgrade was not successful
        #endregion Post-Install Checks

        Write-Log "Script execution complete. Exiting."
    } # process
    end {}
} # function Update-Win11


# ===============================================================================================================================
# To be used when running the script via NinjaOne only. 
# Comment out the rest of the script if manually running on a machine at the console.

# Parse the parameters from the environment variables or default values
$InPlaceUpgrade = $Env:InPlaceUpgrade -eq "true"
# $AllowAfter_4AM = $Env:AllowAfter_4AM -eq "true"
$UnsupportedHardware = $Env:UnsupportedHardware -eq "true"
$EnablementPackage = $Env:EnablementPackage -eq "true"
$DownloadAndExtractOnly = $Env:DownloadAndExtractOnly -eq "true"
# $SuppressReboot = $Env:SuppressReboot -eq "true"
$RebootAfterUpgrade = $Env:RebootAfterUpgrade -eq "true"
$CustomISOUrl = if ($Env:CustomISOUrl) { $Env:CustomISOUrl } else { $null }
$SkipValidation = $Env:SkipValidation -eq "true"
$MonitorProgress = $Env:MonitorProgress -eq "true"
$DisableSleepDuringUpgrade = $Env:DisableSleepDuringUpgrade -eq "true"
$TargetBuildNumber = if ($Env:TargetBuildNumber) { [int]$Env:TargetBuildNumber } else { 26200 }
# $LogFilePath = if ([string]::IsNullOrWhiteSpace($Env:LogFilePath)) { "C:\Win11\Win11Upgrade.log" } else { $Env:LogFilePath }

# Construct the parameter set dynamically
$Params = @{
    TargetBuildNumber = $TargetBuildNumber
    # LogFilePath       = $LogFilePath
}

if ($InPlaceUpgrade) { $Params["InPlaceUpgrade"] = $true }
# if ($AllowAfter_4AM) { $Params["AllowAfter_4AM"] = $true }
if ($UnsupportedHardware) { $Params["UnsupportedHardware"] = $true }
#if ($SuppressReboot) { $Params["SuppressReboot"] = $true }
if ($DownloadAndExtractOnly) { $Params["DownloadAndExtractOnly"] = $true }
if ($RebootAfterUpgrade) { $Params["RebootAfterUpgrade"] = $true }
if ($CustomISOUrl) { $Params["CustomISOUrl"] = $CustomISOUrl }
if ($SkipValidation) { $Params["SkipValidation"] = $true }
if ($EnablementPackage) { $Params["EnablementPackage"] = $true }
if ($MonitorProgress) { $Params["MonitorProgress"] = $true }
if ($DisableSleepDuringUpgrade) { $Params["DisableSleepDuringUpgrade"] = $true }
    
# Call the Update-Win11 function with the constructed parameters
Update-Win11 @Params