function Update-Win11 {
    <#
.SYNOPSIS
Upgrades a Windows machine to a specified version of Windows 11.

.DESCRIPTION
This script is designed to upgrade a Windows machine to a specified version of Windows 11. It handles downloading the ISO, verifying its integrity, extracting its contents, running the upgrade process and setting up the post reboot script (see the notes section). 
The script can be run either manually or via NinjaOne.

.PARAMETER InPlaceUpgrade
Specifies whether to force an in-place upgrade. Set this to 'true' to enable.

.PARAMETER AllowAfter_4AM
Allows the script to run after 4 AM. If not set, the script will exit if the current time is after 4 AM.

.PARAMETER SuppressReboot
Prevents the system from rebooting automatically after the upgrade. If not set, the system will reboot automatically.
NOTE: This controls the reboot behavior initiated manually by the script post-upgrade; the upgrade itself is always run with the /noreboot switch.

.PARAMETER UnsupportedHardware
Allows upgrades to run on non-supported hardware by using the '/product server' switch when calling setup.exe. Note, this is an experimental feature and may not work as expected.

.PARAMETER TargetBuildNumber
Specifies the target build number for the upgrade. Defaults to '26100' (Windows 11 24H2).

.PARAMETER ShowProgress
Displays the download progress in the console. 
This is not recommended for use with NinjaOne as it will clutter the Ninja Activity logs. Use when running the script interactively on a machine.

.PARAMETER LogFilePath
Specifies the path to the log file where the script will write its logs. Defaults to 'C:\Win11\Win11Upgrade.log'.

.EXAMPLE
Run the script manually with default parameters.
Update-Win11

.EXAMPLE
Run the script manually with specific parameters.
Update-Win11 -InPlaceUpgrade -AllowAfter_4AM -SuppressReboot -TargetBuildNumber 26100

.Example
Run the script via NinjaOne.
Uncomment the bottom section of the script and deploy it via NinjaOne.

.NOTES
The script is designed to be run either manually or via NinjaOne.
When run manually, the bottom section of the script (where parameters are parsed and the 'Update-Win11' function is called) should be commented out. Just load the script in a shell, press enter, then call the function with the desired parameters (see the first two examples).
When run via NinjaOne, the bottom section is uncommented to allow the script to parse environment variables (selected using the NinjaOne interface) and execute automatically.

A post reboot check is performed to verify the success of the upgrade by checking the current Windows build number. The script saves a second PowerShell script to the 'C:\Win11' directory, and that script is added to the RunOnce Registry key, to run after the next reboot. 
The script also checks if Bitlocker is re-enabled on the C: drive and re-enables it if necessary.
The script will delete itself after running. The value of the RunOnce Registry key is deleted by default before the command is run. More information on the RunOnce Registry key:
https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-keys-for-windows-setup

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

====================================================================================================
AUTHOR: THH
DATE CREATED: April 2025
LAST UPDATED: 5/9/2025
VERSION: 1.0
PURPOSE: Automate the upgrade process to a specified version of Windows 11.
NOTES: This script is designed for use in both manual and automated environments (e.g., NinjaOne).
Comments and suggestions welcome!
====================================================================================================
#>
    [CmdletBinding()]
    param (
        # Parameter to force an in-place upgrade
        [Parameter(Mandatory = $false)]
        [switch]$InPlaceUpgrade,

        # Parameter to allow the script to run after 4 AM
        [Parameter(Mandatory = $false)]
        [switch]$AllowAfter_4AM,

        # Parameter to supress the reboot after the upgrade. 
        # NOTE: This controls the reboot behavior initiated manually by the script post-upgrade; the upgrade itself is always run with the /noreboot switch.
        [Parameter(Mandatory = $false)]
        [switch]$SuppressReboot,

        # Parameter for using an experimental feature to allow upgrades on unsupported hardware
        [Parameter(Mandatory = $false)]
        [switch]$UnsupportedHardware,

        # Parameter to specify the target build number for the upgrade, default is 26100 (Windows 11 24H2)
        [Parameter(Mandatory = $false)]
        [ValidateSet(
            # 22621, # Windows 11 22H2 / Release date September 20, 2022
            # 22631, # Windows 11 23H2 / Release date October 31, 2023
            26100 # Windows 11 24H2 / Release date October 1, 2024
        )]
        [int]$TargetBuildNumber = 26100,

        # Parameter to show download progress in the console (not for use with NinjaOne)
        [Parameter(Mandatory = $false)]
        [switch]$ShowProgress,

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
                [Parameter(Mandatory = $true)]
                [string]$Message,
        
                [Parameter(Mandatory = $false)]
                [string]$LogPath = $LogFilePath,
        
                [Parameter(Mandatory = $false)]
                [ValidateSet("Info", "Warning", "Error")]
                [string]$Severity = "Info"
            )

            $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $LogEntry = "[$Timestamp] [$Severity] $Message"
        
            switch ($Severity) {
                "Warning" {
                    Write-Warning $Message
                }
                "Error" {
                    Write-Host $Message -ForegroundColor Red
                }
                "Progress" {
                    # Only output to the console, do not write to the log file
                    Write-Host -NoNewline $Message
                }
                default {
                    Write-Host $Message
                }
            } # switch

            try {
                Add-Content -Path $LogPath -Value $LogEntry -ErrorAction Stop
            }
            catch {
                Write-Host "Failed to write to log file." -ForegroundColor Red
            }
        } # function Write-Log

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
                [string]$LogFile
            )
        
            begin {
                Write-Log "Executing file download process."
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
                    return
                }
                
                if (-not (Test-Path -Path (Split-Path -Path $Destination -Parent))) {
                    Write-Log -Severity Error -Message "Invalid Destination: $Destination. The directory does not exist."
                    return
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
                            Remove-Item -Path $Destination -Force -ErrorAction SilentlyContinue
                        }
                    }
                    else {
                        Write-Log "No hash provided. Using the existing file."
                        if ($LogFile) {
                            Write-Log "Success: File already exists at $Destination. No hash verification performed."
                        }
                        return
                    }
                }
        
                
                # Clear any existing BITS jobs related to the same destination or source URL
                $existingBitsJobs = Get-BitsTransfer -AllUsers | Where-Object {
                    $_.FileList.LocalName -eq $Destination -or $_.FileList.RemoteName -eq $SourceUrl
                }
        
                if ($existingBitsJobs) {
                    Write-Log "Found existing BITS jobs related to the destination or source URL. Removing them..."
                    foreach ($job in $existingBitsJobs) {
                        Remove-BitsTransfer -BitsJob $job -Confirm:$false
                        Write-Log "Removed BITS job with ID: $($job.JobId)"
                    }
                }
        
                
                # Retry logic for BITS
                $bitsAttempts = 0
                $bitsSuccess = $false
                
                # Flag to track if progress is displayed, needed for later
                $progressFlag = $false
                
                while ($bitsAttempts -lt 3 -and $bitsSuccess -eq $false) {
                    $bitsAttempts++
                    try {
                        Write-Log "Attempting to download using BITS. Attempt $bitsAttempts of 3."
                        $bitsJob = Start-BitsTransfer -Source $SourceUrl -Destination $Destination -Asynchronous -ErrorAction Stop
        
                        Write-Log "BITS job started with ID: $($bitsJob.JobId)"
                        Write-Log "Initial BITS job state: $($bitsJob.JobState)"

                        if ($bitsJob.JobState -like "*Error*") {
                            Write-Log -Severity Warning -Message "The BITS job encountered an error immediately after starting. State: $($bitsJob.JobState)"
                            Write-Log -Message "Removing the BITS job, waiting 5 seconds and retrying."
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
                                $errorDetails = $bitsJob | Get-BitsTransfer -Error
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
                        }
                    

                        # Handle non-Transferring states
                        if ($bitsJob.JobState -eq 'Transferred') {
                            Complete-BitsTransfer -BitsJob $bitsJob
                            if ($progressFlag -eq $true) {
                                Write-Host ""
                                Write-Log "BITS transfer job complete. File is at $($Destination)."    
                            }
                            else {
                                Write-Log "BITS transfer job complete. File is at $($Destination)."
                            }
                            $bitsSuccess = $true                        
                        }
                        elseif ($bitsJob.JobState -like "*Error*") {
                            Write-Log -Severity Warning -Message "BITS job encountered an error. State: $($bitsJob.JobState)"
                            $errorDetails = $bitsJob | Get-BitsTransfer -Error
                            Write-Log -Severity Warning -Message "Error details: $errorDetails"
                            throw "BITS job failed."
                        }
                        else {
                            Write-Log "BITS job ended with unexpected state: $($bitsJob.JobState)"
                        }
                    }
                    catch {
                        if ($bitsAttempts -lt 3) {
                            Write-Log -Severity Warning -Message "BITS download attempt $bitsAttempts failed. Error: $_.Exception.Message. Retrying after 5 seconds..."
                            Start-Sleep -Seconds 5
                        }
                        else {
                            Write-Log -Severity Warning -Message "BITS download attempt $bitsAttempts failed. Error: $_.Exception.Message."
                            Write-Log -Message "BITS download failed after $bitsAttempts attempts. Falling back to Invoke-WebRequest."
                            $bitsSuccess = $false
                        }
                    }
                } # Attempt to use BITS
        
        
                # If BITS fails, retry with Invoke-WebRequest
                if ($bitsSuccess -eq $false) {
                    $webRequestAttempts = 0
                    $webRequestSuccess = $false
                    while ($webRequestAttempts -lt 3 -and $webRequestSuccess -eq $false) {
                        $webRequestAttempts++
        
                        # Save the current progress preference
                        $OriginalProgressPreference = $ProgressPreference
                        $ProgressPreference = 'SilentlyContinue'
        
                        try {
                            # Attempt to download using Invoke-WebRequest
                            Write-Log "Attempting to download using Invoke-WebRequest. Attempt $webRequestAttempts of 3."
                            Invoke-WebRequest -Uri $SourceUrl -OutFile $Destination -ErrorAction Stop
                            Write-Log "Download completed successfully using Invoke-WebRequest. File is at $($Destination)."
                            $webRequestSuccess = $true
                        }
                        catch {
                            if ($webRequestAttempts -lt 3) {
                                Write-Log -Severity Warning -Message "Attempt $webRequestAttempts failed. Error: $_.Exception.Message. Retrying after 5 seconds..."
                                Start-Sleep -Seconds 5
                            }
                            else {
                                Write-Log -Severity Warning -Message "Attempt $webRequestAttempts failed. Error: $_.Exception.Message."
                                Write-Log -Message "Invoke-WebRequest download failed after $webRequestAttempts attempts."
                                $webRequestSuccess = $false
                            }
                        }
                        finally {
                            # Restore the original progress preference
                            $ProgressPreference = $OriginalProgressPreference
                        }
                    }
                } # attempt to use Invoke-WebRequest
        
                # Verify the hash if provided
                if ($ExpectedHash) {
                    Write-Log "Verifying file hash."
                    $ActualHash = (Get-FileHash -Path $Destination -Algorithm SHA256).Hash
                    if ($ActualHash -ne $ExpectedHash) {
                        Write-Log "Error: Hash verification failed for $($Destination). Expected: $ExpectedHash, Actual: $ActualHash."
                        return
                    }
                    else {
                        Write-Log "Hash verification succeeded."
                    }
                } # if hash is provided
                else {
                    Write-Log "No hash provided. Skipping verification."
                } # if hash is not provided
            } # process
        
            end {
                # Write-Log "File download process completed."
            }
        } # function Download-File
        
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
                Write-Log "Extracting the contents of the ISO to $($DestinationFolder)..."

                # Define paths for 7z.exe and 7z.dll
                $7zipFolder = "$Win11Directory\7zip"
                if (-not (Test-Path -Path $7zipFolder)) {
                    New-Item -ItemType Directory -Path $7zipFolder | Out-Null
                }
                $7zipExePath = "$7zipFolder\7z.exe"
                $7zipDllPath = "$7zipFolder\7z.dll"

                # Define the expected hashes for 7z.exe and 7z.dll
                $expected7zipExeHash = "034ECA579F68B44F8F41294D8C9DAC96F032C57DEE0877095DA47913060DFF84"
                $expected7zipDllHash = "6CD22F513CE36B4727BB6C353C58182C7CC8A14CBE3EEFDCA85C2A25906A0077"

                # Download 7z.exe and 7z.dll
                Write-Log "Downloading 7z..."
                Download-File -SourceUrl "https://labtech.intellicomp.net/Labtech/Transfer/Scripts/DataComm/Utilities/7z.exe" -Destination $7zipExePath -ExpectedHash $expected7zipExeHash
                Download-File -SourceUrl "https://labtech.intellicomp.net/Labtech/Transfer/Scripts/DataComm/Utilities/7z.dll" -Destination $7zipDllPath -ExpectedHash $expected7zipDllHash

                # Verify that 7z.exe and 7z.dll were downloaded successfully
                if (-not (Test-Path -Path $7zipExePath) -or -not (Test-Path -Path $7zipDllPath)) {
                    Write-Log -Severity Warning "Failed to download 7z.exe or 7z.dll. Exiting the function."
                    return
                }

                Write-Log "Extracting the ISO file using 7z..."
                <#
                # $7zipCommand = "& `"$7zipExePath`" x `"$SourceFile`" -o`"$DestinationFolder`" -y"
                # Invoke-Expression $7zipCommand

                # Verify that the extraction was successful
                if (-not (Test-Path -Path $DestinationFolder)) {
                    Write-Log -Severity Warning "Failed to extract the ISO file to $($DestinationFolder) using 7z. Exiting the function."
                    return
                }
                Write-Log "ISO file extracted successfully to $($DestinationFolder)."
                #>

                # Define log file paths for standard output and error
                # Redirecting unneeded output from 7z so as not to clutter the console
                $stdoutLog = "$7zipFolder\7z_stdout.log"
                $stderrLog = "$7zipFolder\7z_stderr.log"
        
                $Parameters = @{
                    FilePath               = $7zipExePath
                    ArgumentList           = "x `"$SourceFile`" -o`"$DestinationFolder`" -y"
                    NoNewWindow            = $true
                    Wait                   = $true
                    RedirectStandardOutput = $stdoutLog
                    RedirectStandardError  = $stderrLog
                }

                try {
                    Start-Process @Parameters

                    # verify that the extraction was successful using the folder size
                    $extractedFolderSize = (Get-ChildItem -Path $DestinationFolder -Recurse | Measure-Object -Property Length -Sum).Sum
                    if ($extractedFolderSize -ne $expectedExtractedFolderSize) {
                        Write-Log -Severity Warning "Failed to extract the ISO file using 7z. Exiting the function."
                        Write-Log "Leaving the ISO file in place for the next run. Exiting the script."
                        exit
                    }
                    else {
                        Write-Log "ISO file extracted successfully to $($DestinationFolder)."
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
        
        <#
        function Initialize-RebootProcedure {
            param (
                [Parameter(Mandatory = $false)]
                [string]$LogFilePath,

                [Parameter(Mandatory = $false)]
                [int]$TargetBuildNumber = $TargetBuildNumber
            )
        
            Write-Log "Creating a scheduled task and powershell script for the post-reboot checks."

            $taskScript = @"
            param (
                [String]`$LogFilePath = `"C:\Win11\Win11Upgrade.log`",
                [int]`$TargetBuildNumber = $TargetBuildNumber
            )
        
            function Write-Log {
                param(
                    [Parameter(Mandatory = `$true)]
                    [string]`$Message,
                
                    [Parameter(Mandatory = `$false)]
                    [string]`$LogPath = `$LogFilePath,
                
                    [Parameter(Mandatory = `$false)]
                    [ValidateSet("Info", "Warning", "Error")]
                    [string]`$Severity = "Info"
                )
        
                `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                `$LogEntry = "[`$Timestamp] [`$Severity] `$Message"
                
                switch (`$Severity) {
                    "Warning" {
                        Write-Warning $Message
                    }
                    "Error" {
                        Write-Host `$Message -ForegroundColor Red
                    }
                    "Progress" {
                        # Only output to the console, do not write to the log file
                        Write-Host -NoNewline `$Message
                    }
                    default {
                        Write-Host `$Message
                    }
                } # switch
        
                try {
                    Add-Content -Path `$LogPath -Value `$LogEntry -ErrorAction Stop
                }
                catch {
                    Write-Host "Failed to write to log file." -ForegroundColor Red
                }
            } # function Write-Log
        
            Write-Log "<<<<<    The machine rebooted. Starting the post-reboot script.   >>>>>"
        
            # Check the current Windows version after the reboot
            Write-Log "Checking the Windows build number."
            # `$PostUpgradeVersionInfo = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
            `$newBuildNumber = [Environment]::OSVersion.Version.Build

            if (`$newBuildNumber -ge $TargetBuildNumber) {
                Write-Log "Post-reboot check: Upgrade confirmed SUCCESSFUL. Current build number: `$(`$newBuildNumber), Target build number: $TargetBuildNumber."
            }
            else {
                Write-Log -Severity Warning "Post-reboot check: Upgrade FAILED. Current build number: `$(`$newBuildNumber), Expected build number: $TargetBuildNumber."
            }
        
            # Confirm Bitlocker was re-enabled for C:
            Write-Log "Checking BitLocker."
            `$bitlockerStatus = Get-BitLockerVolume -MountPoint "C:"
            if (`$bitlockerStatus.ProtectionStatus -eq "On") {
                Write-Log "BitLocker is enabled again for the C: drive."
            }
            else {
                Write-Log -Severity Warning "BitLocker was NOT re-enabled for the C: drive. Please check the BitLocker status."
            }

            # Clean up: Delete the scheduled task and the temporary script
            Write-Log "< Cleaning up >"
            `$taskName = "WindowsUpgradePostRebootCheck"
            `$scriptPath = "C:\Win11\WindowsUpgradePostRebootCheck.ps1"
            
            Unregister-ScheduledTask -TaskName `$taskName -Confirm:`$false -ErrorAction SilentlyContinue
            # Confirm the task was deleted
            `$task = Get-ScheduledTask -TaskName `$taskName -ErrorAction SilentlyContinue
            if (`$task) {
                Write-Log -Severity Warning "Scheduled task `$(`$taskName) still exists. Please check the task scheduler."
            }
            else {
                Write-Log "Scheduled task `$(`$taskName) was successfully deleted."
            }
            
            Remove-Item -Path `$scriptPath -Force -ErrorAction SilentlyContinue
            # Confirm the script was deleted
            if (Test-Path -Path `$scriptPath) {
                Write-Log -Severity Warning "Temporary script `$(`$scriptPath) was not successfully deleted. Please check the script location."
            }
            else {
                Write-Log "Temporary script `$(`$scriptPath) was successfully deleted."
            }

            Write-Log "< Cleanup complete >."
            Write-Log "Post-reboot script complete."
"@

            Write-Debug "Task script content: $taskScript"

            # Save the script to a temporary file
            # $taskScriptPath = "$Win11Directory\WindowsUpgradePostRebootCheck.ps1"
            $taskScriptPath = "C:\Win11\WindowsUpgradePostRebootCheck.ps1"
            Set-Content -Path $taskScriptPath -Value $taskScript
            
            # Configure permissions for the script, administrators only
            $acl = Get-Acl -Path $taskScriptPath
            # Create a new access rule for the Administrators group
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Administrators", # User or group
                "FullControl", # Permissions
                "None", # Applies to subfolders and files
                "None", # No special flags
                "Allow"           # Allow rule
            )
            # Remove inheritance and clear existing permissions
            $acl.SetAccessRuleProtection($true, $false)

            # Add the new rule for Administrators
            $acl.SetAccessRule($adminRule)

            # Apply the updated ACL to the file
            Set-Acl -Path $taskScriptPath -AclObject $acl
            
            Write-Log "Permissions for the script file have been updated."

        
            # Create the scheduled task            
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$taskScriptPath`" -LogFilePath `"$LogFilePath`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
            Register-ScheduledTask -TaskName "WindowsUpgradePostRebootCheck" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
            
            # Confirm the task was created
            $task = Get-ScheduledTask -TaskName "WindowsUpgradePostRebootCheck" -ErrorAction SilentlyContinue
            if ($task) {
                Write-Log "Scheduled task 'WindowsUpgradePostRebootCheck' was successfully created."
            }
            else {
                Write-Log -Severity Warning "Scheduled task 'WindowsUpgradePostRebootCheck' was NOT successfully created. Please check the task scheduler."
            }
            # Confirm the script was created
            if (Test-Path -Path $taskScriptPath) {
                Write-Log "Temporary script $($taskScriptPath) was successfully created."
            }
            else {
                Write-Log -Severity Warning "Temporary script $($taskScriptPath) was NOT successfully created. Please check the script location."
            }
        } # function Initialize-RebootProcedure
        #>

        function Initialize-RebootProcedure {
            # Define the path where the script will be saved
            $scriptPath = "C:\Win11\WindowsUpgradePostRebootCheck.ps1"

            # Define the script content as an array of strings
            $scriptContent = @'
            param (
                [string]$LogFilePath = "C:\Win11\Win11Upgrade.log",
                [int]$TargetBuildNumber = $targetBuildNumber
            )

            function Write-Log {
                param (
                    [string]$Message,
                    [string]$Severity = "Info"
                )
                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $LogEntry = "[$Timestamp] [$Severity] $Message"

                try {
                    Add-Content -Path $LogFilePath -Value $LogEntry -erroraction stop
                }
                catch {
                    Write-Host "Failed to write to log file: $_"
                }
            } # function Write-Log

            Write-Log "<<<<<    Post-reboot script started.    >>>>>"

            # Check the current Windows build number
            Write-Log "Checking the Windows build number."
            $newBuildNumber = [Environment]::OSVersion.Version.Build
            if ($newBuildNumber -ge $TargetBuildNumber) {
                Write-Log "Upgrade confirmed SUCCESSFUL. Current build number: $newBuildNumber, Target build number: $TargetBuildNumber."
            }
            else {
                Write-Log "Upgrade FAILED. Current build number: $newBuildNumber, Expected build number: $TargetBuildNumber." -Severity "Warning"
            }

            # Confirm Bitlocker was re-enabled for C:
            Write-Log "Checking BitLocker."
            $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:"
            if ($bitlockerStatus.ProtectionStatus -eq "On") {
                Write-Log "BitLocker is re-enabled for the C: drive."
            }
            else {
                Write-Log -Severity Warning "BitLocker was NOT re-enabled for the C: drive."
            }

            # Perform cleanup
            Write-Log "Cleaning up post-reboot script."
            $ScriptPath = "C:\Win11\WindowsUpgradePostRebootCheck.ps1"
            Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue

            if (Test-Path $ScriptPath) {
                Write-Log "Failed to remove post-reboot script." -Severity "Warning"
            }
            else {
                Write-Log "Post-reboot script removed successfully."
            }
'@

            # Write the script content to the file
            $scriptContent | Set-Content -Path $scriptPath -Force

            Write-Host "Script saved to $scriptPath"

            # Get the current ACL for the file
            $acl = Get-Acl -Path $scriptPath

            # Create a new access rule for the Administrators group
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "Administrators", # User or group
                "FullControl", # Permissions
                "None", # Applies to subfolders and files
                "None", # No special flags
                "Allow"           # Allow rule
            )

            # Remove inheritance and clear existing permissions
            $acl.SetAccessRuleProtection($true, $false)

            # Add the new rule for Administrators
            $acl.SetAccessRule($adminRule)

            # Apply the updated ACL to the file
            Set-Acl -Path $scriptPath -AclObject $acl

            Write-Host "Permissions for the script file have been locked down to administrators only."

            # Define the command to run the script
            $command = "PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

            # Add to the RunOnce key for all users
            # https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "WindowsUpgradePostRebootCheck" -Value $command

            Write-Host "Post-reboot script added to RunOnce registry key."
        } # function Initialize-RebootProcedure

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
        #endregion functions

        <#
        # Validate the TargetBuildNumber parameter
        $validBuildNumbers = @(22631, 26100)
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
                Write-Log -Severity Warning "Failed to create the C:\Win11 directory. Error: $_.Exception.Message"
                return
            }
        }
        else {
            Write-Log "The C:\Win11 directory already exists."
        }

        Write-Log "<<<<<    Starting the Windows 11 upgrade process    >>>>>"

        # Output log file path
        Write-Log "The script log file can be found at `"C:\Win11\Win11Upgrade.log`"."
        # Write-Log "The setupact log file can be found at `"$Win11Directory\Windows11SetupLogs\Panther\setupact.log.`"."

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


        # Check if the script is running with administrative privileges
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Log -Severity Warning "The script must be run as an administrator. Exiting the script."
            return
        }

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

        
        #region initializing variables
        Write-Log "Initializing variables..."
        $WindowsVersionInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $CurrentBuildNumber = [int]$WindowsVersionInfo.CurrentBuildNumber # [Environment]::OSVersion.Version.Build
        
        if ($WindowsVersionInfo.LCUVer) {
            $WindowsLCU = [int]($WindowsVersionInfo.LCUVer.split(".")[3]) # the latest cumulative update version
            $WindowsBuildAndCU = $WindowsVersionInfo.LCUVer.split(".")[-2..-1] -join "." # the latest cumulative update version
        }
        else {
            $WindowsLCU = [int]($WindowsVersionInfo.WinREVersion.split(".")[3]) # the latest cumulative update version
            $WindowsBuildAndCU = $WindowsVersionInfo.WinREVersion.split(".")[-2..-1] -join "." # the latest cumulative update version
        }
        
        
        $WindowsEdition = $WindowsVersionInfo.ProductName

        <#
        # Minimum version for using the Windows 11 enablement package to upgrade from version 22H2 to version 23H2
        # https://support.microsoft.com/en-us/topic/kb5027397-feature-update-to-windows-11-version-23h2-by-using-an-enablement-package-b9e76726-3c94-40de-b40b-99decba3db9d
        $Win_Enablement_Minimum_OSBuild = 22621 # Windows 11 22H2 / Release date September 20, 2022
        # Check for the following prerequisite installed before updating to Win11 version 23H2 using the enablment package: 22621.2506 or a later cumulative update
        $Win_Enablement_Minimum_CumulativeUpdate = 22621.2506
        #>

        # Check if the current build is already up to date
        if ($CurrentBuildNumber -ge $TargetBuildNumber) {
            Write-Log "Windows is already up to date. Current build number: $($WindowsBuildAndCU), Target build number: $($TargetBuildNumber). Exiting the script."
            return
        }
        

        <#
        Write-Log "Checking compatibility with Windows 11 version $($TargetBuildNumber)..."
        # Using the hash table format for future extensibility when adding newer versions of Windows 11
        $CompatibilityChecks = @{
            26100 = @{
                MinimumBuild = 22621
                MinimumLCU   = 3672
                Message      = "The current build number ($($CurrentBuildNumber)) is not compatible with Windows 11 version 24H2. Devices must be running at least version 22H2 with the May 2024 non-security preview update (build 22621.3672) or later."
            }
        }

        # Check if the current build number is less than the minimum required for the target version
        if ($CompatibilityChecks.ContainsKey($TargetBuildNumber)) {
            $Check = $CompatibilityChecks[$TargetBuildNumber]
            if ( ($CurrentBuildNumber -lt $Check.MinimumBuild) -or ($WindowsLCU -lt $Check.MinimumLCU) ) {
                Write-Log -Severity Warning $Check.Message
                return
            }
            else {
                Write-Log "The current build is compatible with Windows 11 version $($TargetBuildNumber)."
            }
        } 
        #>

        # switch statement to set the possible download paths and expected file sizes and hashes based on the target build number
        switch ($TargetBuildNumber) {
            22631 {    
                $Version = "23H2"                            
                # Enterprise 64-bit
                $Download_Path_ENT_64 = "https://ltshare.nyc3.digitaloceanspaces.com/Win11_23H2/SW_DVD9_Win_Pro_11_23H2.6_64BIT_English_Pro_Ent_EDU_N_MLF_X23-75490.ISO"
                $ISO_Length_ENT_64 = 6972778496
                $Folder_Length_ENT_64 = 6967281618
                # Home/Pro/Education 64-bit
                $Download_Path_Home_Pro_EDU_64 = "https://ltshare.nyc3.digitaloceanspaces.com/Win11_23H2/Win11_23H2_English_x64v2.iso"
                $ISO_Length_Home_Pro_EDU_64 = 6812706816
                $Folder_Length_Home_Pro_EDU_64 = 6807219850
            } # 23H2
            26100 {
                $Version = "24H2"
                # Enterprise 64-bit
                $Download_Path_ENT_64 = "https://ltshare.nyc3.digitaloceanspaces.com/Win11_24H2/SW_DVD9_Win_Pro_11_24H2_64BIT_English_Pro_Ent_EDU_N_MLF_X23-69812.ISO"
                $ISO_Length_ENT_64 = 5722114048
                $Folder_Length_ENT_64 = 5716480766
                $ExpectedFileHash_ENT_64 = "D0DCA325314322518AE967D58C3061BCAE57EE9743A8A1CF374AAD8637E5E8AC"
                # Home/Pro/Education 64-bit
                $Download_Path_Home_Pro_EDU_64 = "https://ltshare.nyc3.digitaloceanspaces.com/Win11_24H2/Win11_24H2_English_x64.iso"
                $ISO_Length_Home_Pro_EDU_64 = 5819484160
                $Folder_Length_Home_Pro_EDU_64 = 5813856759
                $ExpectedFileHash_Home_Pro_EDU_64 = "B56B911BF18A2CEAEB3904D87E7C770BDF92D3099599D61AC2497B91BF190B11"
            } # 24H2
        } # switch
         

        Write-Log "Windows Edition detected: $($WindowsEdition)."

        # Set the download path and expected file size from the target build number, based on the Windows edition
        if ($WindowsEdition -match "Home|Pro|Education") {
            $Download_Path = $Download_Path_Home_Pro_EDU_64
            $ExpectedFolderSize = $Folder_Length_Home_Pro_EDU_64
            $ExpectedISOSize = $ISO_Length_Home_Pro_EDU_64
            $ExpectedFileHash = $ExpectedFileHash_Home_Pro_EDU_64
        } # if Home or Pro or Education
        elseif ($WindowsEdition -like "*Enterprise*") {
            $Download_Path = $Download_Path_ENT_64
            $ExpectedFolderSize = $Folder_Length_ENT_64
            $ExpectedISOSize = $ISO_Length_ENT_64
            $ExpectedFileHash = $ExpectedFileHash_ENT_64
        } # else Enterprise

        # Check if any of the required variables are empty
        if (-not $Download_Path -or -not $ExpectedFolderSize -or -not $ExpectedISOSize -or -not $ExpectedFileHash) {
            Write-Log -Severity Warning "One or more required variables are empty. Exiting the script."
            return
        }

        # Write-Log "ISO download URL: $($Download_Path)."
       
        # Installer paths
        $Installer_ISO_Path = "$Win11Directory\Win11.iso"
        $ISOFolderPath = "$Win11Directory\SetupFolder"
        $Installer_exe = "Setup.exe"    
        
        #endregion initializing variables
        
        
        Write-Log "Checking if the ISO file and/or the extracted folder are present..."

        # Initialize flag for ISO presence and validity
        $ISOPresentAndValid = $false
        # Initialize flag for the ISO extracted folder presence and validity
        $ISOFolderPresentAndValid = $false

        if ((Test-Path $ISOFolderPath) -and (Get-ChildItem -Path $ISOFolderPath -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum -eq $ExpectedFolderSize) {
            $ISOFolderPresentAndValid = $true  
            Write-Log "The ISO extracted folder is present and matches the expected size." 
        }

        if ($ISOFolderPresentAndValid -eq $false) {
            if (Test-Path -Path $Installer_ISO_Path) {
                Write-Log "The ISO file is present. Verifying the file size..."
                $ISOFileSize = (Get-Item -Path $Installer_ISO_Path).Length
    
                if ($ISOFileSize -eq $ExpectedISOSize) {
                    Write-Log "The ISO file size matches the expected size."
                    $ISOPresentAndValid = $true
                }
                else {
                    Write-Log -Severity Warning "The ISO file size does not match the expected size. Deleting the file..."
                    Remove-Item -Path $Installer_ISO_Path -Force
                    Write-Log "The invalid ISO file has been deleted."
                }
            } # if ISO file is present
            else {
                Write-Log "The ISO file and extracted folder are not present."
            } # if ISO file is not present
    
            if ($ISOPresentAndValid -eq $false) {            
                # Check for sufficient free space on the system drive for the download
                Write-Log "Checking for sufficient free space on the system drive for the download..."
                $FreeSpaceGB = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
                if ($FreeSpaceGB -lt 15) {
                    Write-Log -Severity Warning "Insufficient free space on the system drive for the download. At least 15 GB is required. Exiting the script."
                    return
                }
                else {
                    Write-Log "There are $FreeSpaceGB GB free on the system drive. Proceeding."
                }
            
                # Download the ISO file using the Download-File function
                Write-Debug "Downloading the Windows 11 $($Version) ISO from $($Download_Path) and saving to $($Installer_ISO_Path)."
                try {
                    Download-File -SourceUrl $Download_Path -Destination $Installer_ISO_Path -ExpectedHash $ExpectedFileHash
                }
                catch {
                    Write-Log -Severity Warning "An unexpected error occurred during the attempt to download the ISO. Error: $_"
                    return
                }
            } # if ISO file is not valid or missing
        } # if ISO extracted folder is not present or not valid
        

        Write-Log "Checking that there are at least 10 GB free on the system drive..."
        $freeSpaceGB = [math]::Round((Get-PSDrive -Name C).Free / 1GB, 2)
        if ($freeSpaceGB -lt 10) {
            Write-Log -Severity Warning "There isn't enough free space on the system drive. At least 10 GB is required. Leaving the ISO file in place for the next attempt and exiting the script."
            return
        } # if free space is less than 10 GB

        
        # Mount the ISO file
        # $mountedDrive = Mount-ISOFile -ISO_Path $Installer_ISO_Path
        
        #region ISO Extraction
        if ($ISOFolderPresentAndValid -eq $false) {
            # Extract the contents of the ISO file to a temporary folder. Create the folder if it doesn't exist.        
            if (Test-Path -Path $ISOFolderPath) {
                if ((Get-ChildItem -Path $ISOFolderPath -Recurse | Measure-Object -Property Length -Sum).Sum -eq $ExpectedFolderSize) {
                    Write-Log "The ISO file has already been extracted to $($ISOFolderPath) and matches the expected folder size."
                }
                else {
                    Write-Log -Severity Warning "The ISO extracted folder size does not match the expected size. Deleting the folder and re-extracting the ISO..."
                    Remove-Item -Path $ISOFolderPath -Recurse -Force -ErrorAction SilentlyContinue
                    New-Item -ItemType Directory -Path $ISOFolderPath | Out-Null
                    try {
                        Extract-ISO -SourceFile $Installer_ISO_Path -DestinationFolder $ISOFolderPath -expectedExtractedFolderSize $ExpectedFolderSize
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
                    Extract-ISO -SourceFile $Installer_ISO_Path -DestinationFolder $ISOFolderPath -expectedExtractedFolderSize $ExpectedFolderSize
                }
                catch {
                    Write-Log -Severity Warning "An unexpected error occurred during the attempt to extract the ISO. Error: $_"
                    return
                }    
            } # if folder does not exist
        } # if ISO extracted folder is not present or not valid
        #endregion ISO Extraction


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
        Write-Log "Constructing arguments for setup.exe..."
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
        # Conditionally add the /product argument for non-Win11-compatible machines
        if ($UnsupportedHardware) {
            $upgradeArgs["/product"] = "server"
        }
        

        # Convert the hash table to a string of arguments
        $argsString = ($upgradeArgs.GetEnumerator() | ForEach-Object { "$($_.Key) $($_.Value)" }) -join " "
        
        # Initialize the upgrade success flag
        $upgradeSuccess = $false
                
        if ($SuppressReboot) {
            Write-Log "The 'SuppressReboot' parameter was used. The system will not reboot automatically after the upgrade."
        }
        else {
            Write-Log "The 'SuppressReboot' parameter was NOT used. The system will reboot automatically after a successful upgrade."
        }

        # Output the command with arguments for debugging purposes
        Write-Log "The upgrade command: `"$($setupPath)`" $($argsString)"

        Write-Log "Starting the installation. Please wait..."
        # Start the setup.exe process with the constructed arguments and retrieve the process object
        $setupProcess = Start-Process -FilePath $setupPath -ArgumentList "$($argsString)" -Wait -NoNewWindow -PassThru

        
        # Use this section to monitor the setup.exe upgrade progress in real-time, when running interactively. 
        # You'll need to paste this in a sep. console window since setup.exe is configured to hold up the console with the -wait parameter.
        # This is not for use when running via Ninja as it will clutter the output in the Activities section.
        <#
        $startTime = Get-Date
        While (Get-Process -Name Setup* -ErrorAction SilentlyContinue) {
            $progress = (Get-ItemProperty HKLM:\SYSTEM\Setup\MoSetup\Volatile -Name SetupProgress -ErrorAction SilentlyContinue).SetupProgress
            Write-Host "`rUpgrade progress: $progress%" -NoNewline
            Start-Sleep -Seconds 10

            # Check if the process has been running for more than 3 hours
            if ((Get-Date) - $startTime -gt (New-TimeSpan -Hours 3)) {
            Write-Log -Severity Warning "Setup process has been running for more than 3 hours. Exiting the monitoring loop."
            break
            }
        }
        #>

        # Calculate the duration of the setup.exe process
        $duration = $setupProcess.ExitTime - $setupProcess.StartTime
        if ($duration) {
            Write-Log "Total runtime for the setup.exe upgrade process: $($duration.ToString("hh\:mm\:ss"))."    
        }
        

        # Check the exit code of the setup.exe process
        if ($setupProcess.ExitCode -eq 0) {
            Write-Log "Setup.exe completed successfully with exit code 0."  
            $upgradeSuccess = $true 
        }
        else {
            Write-Log -Severity Warning "Setup.exe failed with exit code $($setupProcess.ExitCode)."
            # return
        }


        Write-Log "The setupact log file can be found at `"$Win11Directory\Windows11SetupLogs\Panther\setupact.log.`"."
        # Check the last line of the setupact.log file
        $setupActTail = Get-Content "$Win11Directory\Windows11SetupLogs\Panther\setupact.log" -Tail 1 -ErrorAction SilentlyContinue
        if ($setupActTail) { 
            Write-Log -Message "Last line of the setupact log file: $($setupActTail)"   
            
            if ($setupActTail -like "*Rebooting system*prevented by command line override*") {
                Write-Log -Message "Upgrade SUCCESSFUL. Rebooting system prevented by command line override."
            }
            else {
                # Switch for result codes associated with Windows Setup compatibility warnings:
                $resultCodesURL = "https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/windows-10-upgrade-error-codes#result-codes"
                switch -Wildcard ($setupActTail) {
                    "*0xC1900210*" { Write-Log -Severity Warning -Message "MOSETUP_E_COMPAT_SCANONLY	Setup didn't find any compat issue.`nSee $($resultCodesURL)." }
                    "*0xC1900208*" { Write-Log -Severity Warning -Message "MOSETUP_E_COMPAT_INSTALLREQ_BLOCK	Setup found an actionable compat issue, such as an incompatible app.`nSee $($resultCodesURL)." }
                    "*0xC1900204*" { Write-Log -Severity Warning -Message "MOSETUP_E_COMPAT_MIGCHOICE_BLOCK	The migration choice selected isn't available (ex: Enterprise to Home).`nSee $($resultCodesURL)." }
                    "*0xC1900200*" { Write-Log -Severity Warning -Message "MOSETUP_E_COMPAT_SYSREQ_BLOCK	The computer isn't eligible for Windows 10.`nSee $($resultCodesURL)." }
                    "*0xC190020E*" { Write-Log -Severity Warning -Message "MOSETUP_E_INSTALLDISKSPACE_BLOCK	The computer doesn't have enough free space to install.`nSee $($resultCodesURL)." }
                } # switch
                Write-Log -Severity Warning -Message "Upgrade FAILED."
            }
        } # if $SetupActTail is not empty
        else {
            Write-Log -Severity Warning "Failed to read the setupact.log log file."
            # return
        } # else $SetupActTail is empty


        # Cleanup the upgrade files and folders
        if ($upgradeSuccess -eq $true) {

            # Deleting the extracted installer folder
            if (Test-Path -Path $ISOFolderPath) {
                try {
                    Remove-Item -Path $ISOFolderPath -Recurse -Force -ErrorAction Stop
                    Write-Log "The extracted installer folder at $($ISOFolderPath) has been deleted successfully."
                }
                catch {
                    Write-Log -Severity Warning "Failed to delete the extracted installer folder at $($ISOFolderPath). Error: $_"
                }
            }
            else {
                Write-Log -Severity Warning "No extracted installer folder found at $($ISOFolderPath) to delete."
            }

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
        } # if upgrade was successful
        else {
            Write-Log -Severity Warning "The upgrade was not successful. Please check the logs for more details."
        } # if upgrade was not successful

        # Unmount the ISO after the upgrade
        # Unmount-ISOFile -ISO_Path $Installer_ISO_Path
    } # process
    end {}
} # function Update-Win11


# =========================================================================================================================
<#
# To be used when running the script via NinjaOne only

# Parse the parameters from the environment variables or default values
$InPlaceUpgrade = $Env:InPlaceUpgrade -eq "true"
$AllowAfter_4AM = $Env:AllowAfter_4AM -eq "true"
$SuppressReboot = $Env:SuppressReboot -eq "true"
$UnsupportedHardware = $Env:UnsupportedHardware -eq "true"
$SuppressReboot = $Env:SuppressReboot -eq "true"
$TargetBuildNumber = if ($Env:TargetBuildNumber) { [int]$Env:TargetBuildNumber } else { 26100 }
# $LogFilePath = if ([string]::IsNullOrWhiteSpace($Env:LogFilePath)) { "C:\Win11\Win11Upgrade.log" } else { $Env:LogFilePath }

# Construct the parameter set dynamically
$Params = @{
    TargetBuildNumber = $TargetBuildNumber
    # LogFilePath       = $LogFilePath
}

if ($InPlaceUpgrade) { $Params["InPlaceUpgrade"] = $true }
if ($AllowAfter_4AM) { $Params["AllowAfter_4AM"] = $true }
if ($SuppressReboot) { $Params["SuppressReboot"] = $true }
if ($UnsupportedHardware) { $Params["UnsupportedHardware"] = $true }
if ($SuppressReboot) { $Params["SuppressReboot"] = $true }
    
# Call the Update-Win11 function with the constructed parameters
Update-Win11 @Params
#>