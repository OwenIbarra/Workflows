# Collects system performance data (CPU, memory, disk, and network). The results can optionally be saved to a WYSIWYG custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Collects system performance data (CPU, memory, disk, and network). The results can optionally be saved to a WYSIWYG custom field.
.DESCRIPTION
    Collects system performance data (CPU, memory, disk, and network). The results can optionally be saved to a WYSIWYG custom field.
.EXAMPLE
    -DaysSinceLastReboot "7" -DurationToPerformTests "5" -NumberOfEvents "5" -WysiwygCustomField "WYSIWYG" -DisplayUserMessage
    
    Sending message to all users.
    ExitCode: 0
    Sending message to session Console, display time 150
    Async message sent to session Console
    Sending message to session 31C5CE94259D4006A9E4#0, display time 150
    Async message sent to session 31C5CE94259D4006A9E4#0

    [Alert] This computer was last started on 8/27/2024 at 5:21 PM which was 11.2 days ago.

    Collecting event logs.
    Searching for performance counter localizations.
    Collecting performance metrics for 5 minutes.
    WARNING: The data in one of the performance counter samples is not valid. View the Status property for each 
    PerformanceCounterSample object to make sure it contains valid data.
    WARNING: The data in one of the performance counter samples is not valid. View the Status property for each 
    PerformanceCounterSample object to make sure it contains valid data.
    WARNING: The data in one of the performance counter samples is not valid. View the Status property for each 
    PerformanceCounterSample object to make sure it contains valid data.
    WARNING: The data in one of the performance counter samples is not valid. View the Status property for each 
    PerformanceCounterSample object to make sure it contains valid data.
    WARNING: The data in one of the performance counter samples is not valid. View the Status property for each 
    PerformanceCounterSample object to make sure it contains valid data.

    ### 12th Gen Intel(R) Core(TM) i9-12900H 2.918 GHz ###
    CPU Average % CPU Minimum % CPU Maximum %
    ------------- ------------- -------------
    1.09%         0.27%         1.89%

    ### Memory Usage ###
    Total Memory Installed: 4 GB
    RAM Average % RAM Minimum % RAM Maximum %
    ------------- ------------- -------------
    68.51%        68.39%        68.68%

    ### Top 5 CPU Processes ###
    Process Name       Average CPU % Used Minimum CPU % Used Maximum CPU % Used
    ------------       ------------------ ------------------ ------------------
    msmpeng            0.85%              0.13%              1.59%             
    svchost            0.1%               0.03%              0.21%             
    mssense            0.09%              0%                 0.16%             
    ninjarmmagent      0.03%              0%                 0.05%             
    teamviewer_service 0.02%              0%                 0.03%

    ### Top 5 RAM Processes ###
    Process Name Average RAM % Used Minimum RAM % Used Maximum RAM % Used
    ------------ ------------------ ------------------ ------------------
    svchost      5.42%              5.37%              5.44%             
    msmpeng      3.37%              3.3%               3.5%              
    powershell   1.79%              1.62%              1.91%             
    mssense      1.61%              1.59%              1.62%             
    sensendr     0.67%              0.67%              0.67%

    ### Network Usage ###
    NetworkAdapter          : Ethernet
    MacAddress              : 00-17-FB-00-00-04
    Type                    : Wired
    Average Sent & Received : 0.01 Mbps
    Minimum Sent & Received : 0.01 Mbps
    Maximum Sent & Received : 0.02 Mbps

    ### Disk Usage ###
    DriveLetter FreeSpace         TotalSpace PhysicalDisk                  MediaType   Average IOPS Minimum IOPS Maximum IOPS
    ----------- ---------         ---------- ------------                  ---------   ------------ ------------ ------------
            C   27.31 GB (55.2%)  49.47 GB   NVMe PC801 NVMe SK hynix 2TB  SSD         47.04 IOPS   2.02 IOPS    112.24 IOPS

    ### Top 5 IO Processes (Network & Disk Combined) ###
    Process Name  Average IO Used Minimum IO Used Maximum IO Used
    ------------  --------------- --------------- ---------------
    svchost       0.0718 Mbps     0.0027 Mbps     0.1742 Mbps    
    system        0.0409 Mbps     0.0323 Mbps     0.0502 Mbps    
    ninjarmmagent 0.0335 Mbps     0.0174 Mbps     0.0464 Mbps    
    registry      0.0169 Mbps     0.0021 Mbps     0.0521 Mbps    
    msmpeng       0.015 Mbps      0.0063 Mbps     0.0264 Mbps

    Running WinSAT Assessements.
    More info: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/hh825488(v=win.10)
    ExitCode: 0
    Retrieving WinSAT assessment data.
    Successfully retrieved assessment data.

    ### WinSAT Scores ###
    CPUScore D3DScore DiskScore GraphicsScore MemoryScore
    -------- -------- --------- ------------- -----------
         9.1      9.9       9.7           8.3         9.1

    Attempting to set Custom Field 'WYSIWYG'.
    Successfully set Custom Field 'WYSIWYG'!

    ### Last 5 errors in Application, Security, Setup and System Log. ###
    LogName      : Application
    ProviderName : Microsoft-Windows-Security-SPP
    Id           : 8198
    TimeCreated  : 11/18/2024 4:19:19 PM
    Message      : License Activation (slui.exe) failed with the following error code:
                hr=0x80004005
                Command-line arguments:
                RuleId=eeba1977-569e-4571-b639-7623d8bfecc0;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f1605
                9f;SkuId=2de67392-b7a7-462a-b1ca-108dd189f588;NotificationInterval=1440;Trigger=TimerEvent

    LogName      : System
    ProviderName : Microsoft-Windows-Time-Service
    Id           : 34
    TimeCreated  : 11/18/2024 6:07:36 AM
    Message      : The time service has detected that the system time needs to be  changed by 0 seconds. The time service 
                will not change the system time by more than 54000 seconds. Verify that your time and time zone are 
                correct, and that the time source VM IC Time Synchronization Provider is working properly.

    LogName      : Application
    ProviderName : Microsoft-Windows-Security-SPP
    Id           : 8198
    TimeCreated  : 11/17/2024 4:19:19 PM
    Message      : License Activation (slui.exe) failed with the following error code:
                hr=0x80004005
                Command-line arguments:
                RuleId=eeba1977-569e-4571-b639-7623d8bfecc0;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f1605
                9f;SkuId=2de67392-b7a7-462a-b1ca-108dd189f588;NotificationInterval=1440;Trigger=TimerEvent

    LogName      : System
    ProviderName : Microsoft-Windows-Time-Service
    Id           : 34
    TimeCreated  : 11/17/2024 10:53:51 AM
    Message      : The time service has detected that the system time needs to be  changed by 0 seconds. The time service 
                will not change the system time by more than 54000 seconds. Verify that your time and time zone are 
                correct, and that the time source VM IC Time Synchronization Provider is working properly.

    LogName      : Application
    ProviderName : Microsoft-Windows-Security-SPP
    Id           : 8198
    TimeCreated  : 11/16/2024 4:19:52 PM
    Message      : License Activation (slui.exe) failed with the following error code:
                hr=0x80004005
                Command-line arguments:
                RuleId=eeba1977-569e-4571-b639-7623d8bfecc0;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f1605
                9f;SkuId=2de67392-b7a7-462a-b1ca-108dd189f588;NotificationInterval=1440;Trigger=TimerEvent

    LogName      : Application
    ProviderName : Microsoft-Windows-Defrag
    Id           : 264
    TimeCreated  : 11/16/2024 12:09:28 PM
    Message      : The storage optimizer couldn't complete slab consolidation on System (C:) because: The slab 
                consolidation operation was aborted because an insufficient number of slabs could be reclaimed (based 
                on the limits specified in the registry). (0x89000028)

    LogName      : Application
    ProviderName : Microsoft-Windows-Security-SPP
    Id           : 8198
    TimeCreated  : 11/15/2024 4:09:12 PM
    Message      : License Activation (slui.exe) failed with the following error code:
                hr=0x80004005
                Command-line arguments:
                RuleId=eeba1977-569e-4571-b639-7623d8bfecc0;Action=AutoActivate;AppId=55c92734-d682-4d71-983e-d6ec3f1605
                9f;SkuId=2de67392-b7a7-462a-b1ca-108dd189f588;NotificationInterval=1440;Trigger=UserLogon;SessionId=2

    LogName      : System
    ProviderName : Service Control Manager
    Id           : 7000
    TimeCreated  : 11/15/2024 11:58:50 AM
    Message      : The luafv service failed to start due to the following error: 
                This driver has been blocked from loading

    LogName      : System
    ProviderName : Service Control Manager
    Id           : 7043
    TimeCreated  : 11/15/2024 11:58:39 AM
    Message      : The Windows Defender Advanced Threat Protection Service service did not shut down properly after 
                receiving a preshutdown control.

    LogName      : System
    ProviderName : Service Control Manager
    Id           : 7031
    TimeCreated  : 11/15/2024 11:43:58 AM
    Message      : The Microsoft Intune Management Extension service terminated unexpectedly.  It has done this 1 time(s). 
                    The following corrective action will be taken in 60000 milliseconds: Restart the service.

    Sending message to all users.
    ExitCode: 0
    Sending message to session Console, display time 3600
    Async message sent to session Console
    Sending message to session 31C5CE94259D4006A9E4#0, display time 3600
    Async message sent to session 31C5CE94259D4006A9E4#0

PARAMETER: -DisplayUserMessage
    Display a message to the end-user informing them that you are collecting performance metrics and that they should not restart the computer.

PARAMETER: -DaysSinceLastReboot "7"
    Specify the number of days by which the system should have been rebooted.

PARAMETER: -DurationToPerformTests "5"
    The duration (in minutes) for which the performance tests should be executed.

PARAMETER: -NumberOfEvents "5"
    The number of error events to retrieve from the Application, Security, Setup, and System event logs.

PARAMETER: -WysiwygCustomField "ReplaceMeWithAnyWYSIWYGCustomField"
    Optionally specify the name of a WYSIWYG custom field to store the formatted performance data.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Removed internet speedtest
#>

[CmdletBinding()]
param (
    [Parameter()]
    $DaysSinceLastReboot,
    [Parameter()]
    [Float]$DurationToPerformTests = 5,
    [Parameter()]
    $NumberOfEvents,
    [Parameter()]
    [String]$WysiwygCustomField,
    [Parameter()]
    [Switch]$DisplayUserMessage = [System.Convert]::ToBoolean($env:displayUserMessage)
)

begin {
    # If script form variables are used, replace command line parameters with their values.
    if ($env:daysSinceLastReboot -and $env:daysSinceLastReboot -notlike "null") { $DaysSinceLastReboot = $env:daysSinceLastReboot }
    if ($env:durationToPerformTests -and $env:durationToPerformTests -notlike "null") { $DurationToPerformTests = $env:durationToPerformTests }
    if ($env:numberOfEvents -and $env:numberOfEvents -notlike "null") { $NumberOfEvents = $env:numberOfEvents }
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WysiwygCustomField = $env:wysiwygCustomFieldName }

    # Validate the 'Days Since Last Reboot' input.
    if ($DaysSinceLastReboot) {
        try {
            $ErrorActionPreference = "Stop"
            # Attempt to cast the value to a floating-point number.
            $DaysSinceLastReboot = [float]$DaysSinceLastReboot
            $ErrorActionPreference = "Continue"
        }
        catch {
            # If the conversion fails, display an error message and exit the script.
            Write-Host -Object "[Error] The 'Days Since Last Reboot' value of '$DaysSinceLastReboot' is invalid. Please provide a positive whole number or 0."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Ensure the value is a whole number (i.e., not a fraction).
    if ($DaysSinceLastReboot -and ($DaysSinceLastReboot % 1) -ne 0) {
        Write-Host -Object "[Error] The 'Days Since Last Reboot' value of '$DaysSinceLastReboot' is invalid. Please provide a positive whole number or 0."
        exit 1
    }

    # Ensure the value is non-negative (greater than or equal to 0).
    if ($DaysSinceLastReboot -and $DaysSinceLastReboot -lt 0) {
        Write-Host -Object "[Error] The 'Days Since Last Reboot' value of '$DaysSinceLastReboot' is invalid. Please provide a positive whole number or 0."
        exit 1
    }

    # Validate the 'Duration To Perform Tests' input.
    if (!$DurationToPerformTests) {
        Write-Host -Object "[Error] Please provide the duration for which you would like to perform the tests using the 'Duration To Perform Tests' box."
        exit 1
    }

    # Ensure the duration is a whole number (i.e., not a fraction).
    if ($DurationToPerformTests -and ($DurationToPerformTests % 1) -ne 0) {
        Write-Host -Object "[Error] The 'Duration To Perform Tests' value of '$DurationToPerformTests' is invalid."
        Write-Host -Object "[Error] Please provide a positive whole number that's greater than 0 and less than or equal to 60."
        exit 1
    }

    # Ensure the duration is between 1 and 60.
    if ($DurationToPerformTests -and ($DurationToPerformTests -lt 1 -or $DurationToPerformTests -gt 60)) {
        Write-Host -Object "[Error] The 'Duration To Perform Tests' value of '$DurationToPerformTests' is invalid."
        Write-Host -Object "[Error] Please provide a positive whole number that's greater than 0 and less than or equal to 60."
        exit 1
    }

    # Validate the 'Number of Events' input.
    if ($NumberOfEvents) {
        try {
            $ErrorActionPreference = "Stop"
            # Attempt to cast the value to a floating-point number.
            $NumberOfEvents = [float]$NumberOfEvents
            $ErrorActionPreference = "Continue"
        }
        catch {
            # If the conversion fails, display an error message and exit the script.
            Write-Host -Object "[Error] The 'Number of Events' value of '$NumberOfEvents' is invalid. Please provide a positive whole number or 0."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Ensure the value is a whole number (i.e., not a fraction).
    if ($NumberOfEvents -and ($NumberOfEvents % 1) -ne 0) {
        Write-Host -Object "[Error] The 'Number of Events' value of '$NumberOfEvents' is invalid. Please provide a positive whole number or 0."
        exit 1
    }

    # Ensure the value is non-negative (greater than or equal to 0).
    if ($NumberOfEvents -and $NumberOfEvents -lt 0) {
        Write-Host -Object "[Error] The 'Number of Events' value of '$NumberOfEvents' is invalid. Please provide a positive whole number or 0."
        exit 1
    }

    function Test-IsServer {
        # Determine the method to retrieve the operating system information based on PowerShell version

        try {
            $OS = if ($PSVersionTable.PSVersion.Major -lt 3) {
                Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            }
            else {
                Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            }
        }
        catch {
            Write-Host -Object "[Error] Failed to identity if this device is a workstation or server."
            throw $_
        }
    
        # Check if the ProductType is "3" or "2", which indicates that the system is a server
        if ($OS.ProductType -eq "3" -or $OS.ProductType -eq "2") {
            return $true
        }
    }

    # Check if the script is running on a server.
    try {
        $IsServer = Test-IsServer
    }
    catch {
        Write-Host -Object "[Error] Unable to identify device type."
        Write-Host -Object "[Error] $($_.Exception.Message)`n"
        $ExitCode = 1
    }

    if ($IsServer -and $DisplayUserMessage) {
        # Attempt to check if the RDS role is installed.
        try {
            # Retrieve the RDS role feature and check if it is installed.
            $RDSRole = Get-WindowsFeature -Name RDS-RD-Server | Where-Object { $_.Installed }
        }
        catch {
            # If an error occurs during the check, output an error message and exit the script.
            Write-Host -Object "[Error] Unable to check if the RDS role is installed."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        # If the RDS role is installed, output an error message and exit the script.
        if ($RDSRole) {
            Write-Host -Object "[Error] This script doesn't support sending a message on RDS servers because the message would show for all logged-in users, potentially creating a source of confusion."
            exit 1
        }
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Utility function for downloading files.
    function Invoke-Download {
        param(
            [Parameter()]
            [String]$URL,
            [Parameter()]
            [String]$Path,
            [Parameter()]
            [int]$Attempts = 3,
            [Parameter()]
            [Switch]$SkipSleep
        )

        # Display the URL being used for the download
        Write-Host -Object "URL '$URL' was given."
        Write-Host -Object "Downloading the file..."

        # Determine the supported TLS versions and set the appropriate security protocol
        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Warn the user if TLS 1.2 and 1.3 are not supported, which may cause the download to fail
            Write-Warning "TLS 1.2 and/or TLS 1.3 are not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        # Initialize the attempt counter
        $i = 1
        While ($i -le $Attempts) {
            # If SkipSleep is not set, wait for a random time between 3 and 15 seconds before each attempt
            if (!($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
        
            # Provide a visual break between attempts
            if ($i -ne 1) { Write-Host "" }
            Write-Host "Download Attempt $i"

            # Temporarily disable progress reporting to speed up script performance
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                if ($PSVersionTable.PSVersion.Major -lt 4) {
                    # For older versions of PowerShell, use WebClient to download the file
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($URL, $Path)
                }
                else {
                    # For PowerShell 4.0 and above, use Invoke-WebRequest with specified arguments
                    $WebRequestArgs = @{
                        Uri                = $URL
                        OutFile            = $Path
                        MaximumRedirection = 10
                        UseBasicParsing    = $True
                    }

                    Invoke-WebRequest @WebRequestArgs
                }

                # Verify if the file was successfully downloaded
                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch {
                # Handle any errors that occur during the download attempt
                Write-Warning "An error has occurred while downloading!"
                Write-Warning $_.Exception.Message

                # If the file partially downloaded, delete it to avoid corruption
                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            # Restore the original progress preference setting
            $ProgressPreference = $PreviousProgressPreference
            # If the file was successfully downloaded, exit the loop
            if ($File) {
                $i = $Attempts
            }
            else {
                # Warn the user if the download attempt failed
                Write-Warning "File failed to download."
                Write-Host ""
            }

            # Increment the attempt counter
            $i++
        }

        # Final check: if the file still doesn't exist, report an error and exit
        if (!(Test-Path $Path)) {
            Write-Host -Object "[Error] Failed to download file."
            Write-Host -Object "Please verify the URL of '$URL'."
            exit 1
        }
        else {
            # If the download succeeded, return the path to the downloaded file
            return $Path
        }
    }

    function Set-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            $Value,
            [Parameter()]
            [String]$DocumentName,
            [Parameter()]
            [Switch]$Piped
        )
        # Remove the non-breaking space character
        if ($Type -eq "WYSIWYG") {
            $Value = $Value -replace 'Â ', '&nbsp;'
        }
        
        # Measure the number of characters in the provided value
        $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters
    
        # Throw an error if the value exceeds the character limit of 200,000 characters
        if ($Piped -and $Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
    
        if (!$Piped -and $Characters -ge 45000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 45,000 characters.")
        }
        
        # Initialize a hashtable for additional documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # Define a list of valid field types
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
    
        # Warn the user if the provided type is not valid
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # Define types that require options to be retrieved
        $NeedsOptions = "Dropdown"
    
        # If the property is being set in a document or field and the type needs options, retrieve them
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # Throw an error if there was an issue retrieving the property options
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
            
        # Process the property value based on its type
        switch ($Type) {
            "Checkbox" {
                # Convert the value to a boolean for Checkbox type
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Convert the value to a Unix timestamp for Date or Date Time type
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Convert the dropdown value to its corresponding GUID
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
            
                # Throw an error if the value is not present in the dropdown options
                if (!($Selection)) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                }
            
                $NinjaValue = $Selection
            }
            default {
                # For other types, use the value as is
                $NinjaValue = $Value
            }
        }
            
        # Set the property value in the document if a document name is provided
        if ($DocumentName) {
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            try {
                # Otherwise, set the standard property value
                if ($Piped) {
                    $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
                }
                else {
                    $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1
                }
            }
            catch {
                Write-Host -Object "[Error] Failed to set custom field."
                throw $_.Exception.Message
            }
        }
            
        # Throw an error if setting the property failed
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }

    $StartedDateTime = Get-Date
}
process {
    # Check if the script is being run with elevated (Administrator) privileges.
    # If not, display an error message and exit the script.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the lock file exists to prevent multiple instances of the script from running.
    # If it exists, read the process ID from the lock file and check if the process is still running.
    if (Test-Path -Path "$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt" -ErrorAction SilentlyContinue) {
        try {
            Write-Host -Object "Process lock file found at '$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt'. Checking if the process is still running."

            # Retrieve the process ID from the lock file.
            $OtherScript = Get-Content -Path "$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt" -ErrorAction Stop

            # Check if the process ID exists, indicating the script is already running.
            if (Get-Process -Id $OtherScript -ErrorAction SilentlyContinue) {
                Write-Host -Object "[Error] This script is already running in another process with the process id (PID) '$OtherScript'."
                exit 1
            }
        }
        catch {
            # If there is an error accessing the lock file, display an error message and exit.
            Write-Host -Object "[Error] Unable to access the lock file at '$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Attempt to write the current process ID to the lock file, preventing multiple instances of the script from running.
    try {
        [System.Diagnostics.Process]::GetCurrentProcess().Id | Out-File -FilePath "$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt" -Force -ErrorAction Stop
    }
    catch {
        # If the lock file cannot be created, display an error message and exit.
        Write-Host -Object "[Error] Failed to create lock file at '$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt'."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    $TotalMessageTime = $($DurationToPerformTests * 60 / 2)
    $TotalCollectionTime = $DurationToPerformTests

    if ($DisplayUserMessage) {
        # Define arguments for the 'msg.exe' command to display a system message to the user.
        $MSGArguments = @(
            "*"
            "/TIME:$TotalMessageTime"
            "/V"
            "System performance metrics are currently being collected. Collection should complete in approximately $TotalCollectionTime minutes and the results will be sent to your IT Administrator. Please do not restart the computer until this collection has completed."
        )

        # Generate unique log file names for capturing the stdout and stderr of the 'msg.exe' process.
        $FirstMsgStandardOutLog = "$env:TEMP\$(New-Guid)_1STMSG_stdout.log"
        $FirstMsgStandardErrLog = "$env:TEMP\$(New-Guid)_1STMSG_stderr.log"


        # Attempt to display the system message to all users.
        try {
            Write-Host -Object "Sending message to all users."

            # Start the 'msg.exe' process with the arguments defined above.
            # The process will run in the background without opening a new window (-NoNewWindow).
            # Standard output and error will be redirected to log files.
            # -Wait ensures the script waits for the process to finish before proceeding.
            # -PassThru allows us to capture the process object and access its exit code.
            $FirstMsgProcess = Start-Process -FilePath "$env:SystemRoot\System32\msg.exe" -ArgumentList $MSGArguments -Wait -NoNewWindow -PassThru -RedirectStandardOutput $FirstMsgStandardOutLog -RedirectStandardError $FirstMsgStandardErrLog -ErrorAction Stop
        }
        catch {
            # If the 'msg.exe' process fails to start, output an error message and exit with a failure code.
            Write-Host -Object "[Error] Failed to send message to all users."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        # Output the exit code of the 'msg.exe' process.
        Write-Host -Object "ExitCode: $($FirstMsgProcess.ExitCode)"

        # If the exit code is non-zero (indicating an error occurred), display an error message.
        if ($FirstMsgProcess.ExitCode -ne 0) {
            Write-Host -Object "[Error] ExitCode does not indicate success."
        }

        # Check if the standard output log file exists.
        if (Test-Path -Path $FirstMsgStandardOutLog -ErrorAction SilentlyContinue) {
            # Display the contents of the stdout log.
            Get-Content -Path $FirstMsgStandardOutLog -Encoding Oem -ErrorAction SilentlyContinue | Write-Host

            try {
                # Attempt to delete the stdout log file after displaying its contents.
                Remove-Item -Path $FirstMsgStandardOutLog -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to remove standard output log at '$FirstMsgStandardOutLog'"
                exit 1
            }
        }

        # Check if the standard error log file exists.
        if (Test-Path -Path $FirstMsgStandardErrLog -ErrorAction SilentlyContinue) {
            # Read the contents of the stderr log into a variable.
            $FirstMessageErrors = Get-Content -Path $FirstMsgStandardErrLog -Encoding Oem -ErrorAction SilentlyContinue

            # Attempt to delete the stderr log file after reading its contents.
            try {
                Remove-Item -Path $FirstMsgStandardErrLog -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to remove standard error log at '$FirstMsgStandardErrLog'"
                exit 1
            }
        }

        # If there were any errors captured in the stderr log, display them and exit with an error code.
        if ($FirstMessageErrors) {
            Write-Host -Object "[Error] Sending message to all users."
            
            $FirstMsgStandardErrLog | ForEach-Object {
                Write-Host -Object "[Error] $_"
            }

            exit 1
        }

        # If the 'msg.exe' process exit code is non-zero, exit the script with an error code.
        if ($FirstMsgProcess.ExitCode -ne 0) {
            exit 1
        }
    }

    Write-Host -Object ""

    # Get the last reboot time of the system.
    try {
        $LastStartTime = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object -ExpandProperty LastBootUpTime
    }
    catch {
        Write-Host -Object "[Error] Failed to get last start up time."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    # If the 'DaysSinceLastReboot' parameter is set, calculate the time difference since the last reboot.
    if ($DaysSinceLastReboot -ge 0) {
        $TimeDifference = New-TimeSpan -Start $LastStartTime -End (Get-Date)

        # If the time since the last reboot exceeds the limit, display an alert to the user.
        if ($TimeDifference.TotalDays -gt $DaysSinceLastReboot) {
            Write-Host -Object "[Alert] This computer was last started on $($LastStartTime.ToShortDateString()) at $($LastStartTime.ToShortTimeString()) which was $([math]::Round($TimeDifference.TotalDays,2)) days ago."
            $ExceededLastStartupLimit = $True
        }
    }

    # Initialize an empty list to store event logs.
    $EventLogs = New-Object System.Collections.Generic.List[object]

    # Define XML queries for Application, Security, Setup, and System event logs that have error level events (Level=2).
    [xml]$ApplicationXML = @"
<QueryList>
  <Query Id="0" Path="Application">
    <Select Path="Application">*[System[(Level=2)]]</Select>
  </Query>
</QueryList>
"@

    [xml]$SecurityLogs = @"
<QueryList>
  <Query Id="0" Path="Application">
    <Select Path="Security">*[System[(Level=2)]]</Select>
  </Query>
</QueryList>
"@

    [xml]$SetupLogs = @"
<QueryList>
  <Query Id="0" Path="Application">
    <Select Path="Setup">*[System[(Level=2)]]</Select>
  </Query>
</QueryList>
"@

    [xml]$SystemLogs = @"
<QueryList>
  <Query Id="0" Path="Application">
    <Select Path="System">*[System[(Level=2)]]</Select>
  </Query>
</QueryList>
"@

    # If the 'NumberOfEvents' parameter is set, collect the specified number of error logs from each log category.
    if ($NumberOfEvents) {
        Write-Host -Object "`nCollecting event logs."

        # Collect logs from each category and store them in the EventLogs list.
        Get-WinEvent -MaxEvents $NumberOfEvents -FilterXml $ApplicationXML -ErrorAction SilentlyContinue -ErrorVariable EventLogErrors | ForEach-Object { $EventLogs.Add($_) }
        Get-WinEvent -MaxEvents $NumberOfEvents -FilterXml $SecurityLogs -ErrorAction SilentlyContinue -ErrorVariable EventLogErrors | ForEach-Object { $EventLogs.Add($_) }
        Get-WinEvent -MaxEvents $NumberOfEvents -FilterXml $SetupLogs -ErrorAction SilentlyContinue -ErrorVariable EventLogErrors | ForEach-Object { $EventLogs.Add($_) }
        Get-WinEvent -MaxEvents $NumberOfEvents -FilterXml $SystemLogs -ErrorAction SilentlyContinue -ErrorVariable EventLogErrors | ForEach-Object { $EventLogs.Add($_) }

        # If any errors occurred during log collection, display warnings with the error details.
        if ($EventLogErrors) {
            $EventLogErrors | ForEach-Object {
                Write-Warning -Message "$($_.Exception.Message)"
            }
        }

        # If no error logs were found, display a warning message.
        if ($EventLogs.Count -eq 0) {
            Write-Warning -Message "No error events were found in the event log."
        }
        else {
            $EventLogs = $EventLogs | Select-Object LogName, ProviderName, Id, TimeCreated, Message | Sort-Object -Property TimeCreated -Descending
        }
    }

    # Display a message to the user indicating the start of the search for performance counter localizations.
    Write-Host -Object "Searching for performance counter localizations."

    # Attempt to retrieve the "Counter" property from the CurrentLanguage registry key, which contains the localized performance counter names.
    # If the retrieval fails, catch the error, display an error message, and exit the script.
    try {
        $CurrentLanguageKey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\CurrentLanguage" -Name "Counter" -ErrorAction Stop | Select-Object -ExpandProperty Counter
    }
    catch {
        Write-Host -Object "[Error] Failed to retrieve performance counter localizations."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Initialize an empty hash table to store the performance counter localizations.
    $LocalizationCounterTable = @{}

    # Loop through the array of performance counters in the registry.
    # The counter array consists of alternating key-value pairs (even indexes are keys, odd indexes are values),
    # so this loop increments by 2 to match each key with its corresponding value.
    for ($i = 0; $i -lt $CurrentLanguageKey.Length; $i += 2) {
        $LocalizationCounterTable[$CurrentLanguageKey[$i]] = $CurrentLanguageKey[$i + 1]
    }

    # Define the paths for various performance counters using the localized counter names from the hash table.
    # These paths are dynamically created by retrieving the localized names for each counter ID.
    $OverallProcessCounterPath = "\$($LocalizationCounterTable['238'])(*)\$($LocalizationCounterTable['6'])"
    $OverallMemoryCounterPath = "\$($LocalizationCounterTable['4'])\$($LocalizationCounterTable['1406'])"
    $ProcessorCounterPath = "\$($LocalizationCounterTable['230'])(*)\$($LocalizationCounterTable['142'])"
    $MemoryCounterPath = "\$($LocalizationCounterTable['230'])(*)\$($LocalizationCounterTable['1478'])"
    $IOUsageCounterPath = "\$($LocalizationCounterTable['230'])(*)\$($LocalizationCounterTable['1424'])"
    $DiskUsageCounterPath = "\$($LocalizationCounterTable['234'])(*)\$($LocalizationCounterTable['212'])"
    $NetworkUsageCounterPath = "\$($LocalizationCounterTable['510'])(*)\$($LocalizationCounterTable['388'])"

    # Notify the user that performance metrics are being collected for the specified duration.
    Write-Host -Object "Collecting performance metrics for $DurationToPerformTests minutes."

    # Collect performance metrics (CPU, memory, disk, and network usage) at a 60-second interval for the specified duration.
    $PerformanceMetrics = Get-Counter -MaxSamples $DurationToPerformTests -SampleInterval 60 -Counter $OverallProcessCounterPath, $OverallMemoryCounterPath,
    $ProcessorCounterPath, $MemoryCounterPath, $IOUsageCounterPath, $DiskUsageCounterPath, $NetworkUsageCounterPath -ErrorAction SilentlyContinue -ErrorVariable PerformanceMetricErrors

    # Extract performance metrics for CPU, memory, I/O, disk, and network usage from the collected data.
    $OverallProcessorUsage = $PerformanceMetrics | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.Path -match "$([Regex]::Escape($($LocalizationCounterTable['6'])))$" }
    $OverallMemoryUsage = $PerformanceMetrics | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.Path -match "$([Regex]::Escape($($LocalizationCounterTable['1406'])))$" }
    $ProcessorUsage = $PerformanceMetrics | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.Path -match "$([Regex]::Escape($($LocalizationCounterTable['142'])))$" }
    $MemoryUsage = $PerformanceMetrics | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.Path -match "$([Regex]::Escape($($LocalizationCounterTable['1478'])))$" }
    $IOUsage = $PerformanceMetrics | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.Path -match "$([Regex]::Escape($($LocalizationCounterTable['1424'])))$" }
    $DiskUsage = $PerformanceMetrics | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.Path -match "$([Regex]::Escape($($LocalizationCounterTable['212'])))$" }
    $NetworkUsage = $PerformanceMetrics | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.Path -match "$([Regex]::Escape($($LocalizationCounterTable['388'])))$" }

    # If there were errors during the collection of performance metrics, display a warning message for each error.
    if ($PerformanceMetricErrors) {
        $PerformanceMetricErrors | ForEach-Object {
            Write-Warning -Message "$($_.Exception.Message)"
        }
    }

    # Ensure that performance metrics for CPU, memory, I/O, disk, and network usage were successfully retrieved.
    # If any of the metrics are missing, display an error message and exit the script.
    if (!$OverallProcessorUsage -or !$OverallMemoryUsage -or !$ProcessorUsage -or !$MemoryUsage -or !$IOUsage -or !$DiskUsage -or !$NetworkUsage) {
        Write-Host -Object "[Error] Failed to retrieve performance metrics."
        exit 1
    }

    # Retrieve CPU information such as name and clock speed (in GHz).
    try {
        $CPU = "$(Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty Name) $((Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -ExpandProperty MaxClockSpeed)/1000) GHz"

        # Retrieve the total amount of installed physical memory (RAM) in bytes and convert it to GB.
        $TotalMemoryBytes = Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop | Measure-Object -Property Capacity -Sum | Select-Object -ExpandProperty Sum
        $TotalMemoryGB = "$($TotalMemoryBytes/1GB) GB"
    }
    catch {
        Write-Host -Object "[Error] Unable to get CPU or Memory details."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    # Display the CPU information.
    Write-Host -Object "`n### $CPU ###"

    # Filter and sort the relevant CPU performance metrics for the "_total" instance (overall system usage).
    $RelevantMetrics = $OverallProcessorUsage | Where-Object { $_.InstanceName -eq "_total" } | Sort-Object CookedValue

    # Calculate average, minimum, and maximum CPU usage.
    $CPUPerformance = [PSCustomObject]@{
        Avg = [math]::Round((($RelevantMetrics | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum) / $DurationToPerformTests), 2)
        Min = [math]::Round(($RelevantMetrics | Select-Object -ExpandProperty CookedValue -First 1), 2)
        Max = [math]::Round(($RelevantMetrics | Select-Object -ExpandProperty CookedValue -Last 1), 2)
    }

    # Format the CPU performance metrics for display.
    $FormattedCPUPerformance = [PSCustomObject]@{
        "CPU Average %" = "$($CPUPerformance.Avg)%"
        "CPU Minimum %" = "$($CPUPerformance.Min)%"
        "CPU Maximum %" = "$($CPUPerformance.Max)%"
    }

    # Display the formatted CPU performance metrics.
    ($FormattedCPUPerformance | Format-Table -AutoSize | Out-String).Trim() | Write-Host

    # Display memory usage header.
    Write-Host -Object "`n### Memory Usage ###"
    Write-Host -Object "Total Memory Installed: $TotalMemoryGB"

    # Filter and sort the relevant memory usage metrics.
    $RelevantMetrics = $OverallMemoryUsage | Sort-Object CookedValue

    # Calculate average, minimum, and maximum memory usage.
    $MemoryPerformance = [PSCustomObject]@{
        Avg = [math]::Round((($RelevantMetrics | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum) / $DurationToPerformTests), 2)
        Min = [math]::Round(($RelevantMetrics | Select-Object -ExpandProperty CookedValue -First 1), 2)
        Max = [math]::Round(($RelevantMetrics | Select-Object -ExpandProperty CookedValue -Last 1), 2)
    }

    # Format the memory performance metrics for display.
    $OverallMemoryMetrics = [PSCustomObject]@{
        "RAM Average %" = "$($MemoryPerformance.Avg)%"
        "RAM Minimum %" = "$($MemoryPerformance.Min)%"
        "RAM Maximum %" = "$($MemoryPerformance.Max)%"
    }

    # Display the formatted memory performance metrics.
    ($OverallMemoryMetrics | Format-Table -AutoSize | Out-String).Trim() | Write-Host

    # Display the header for the top 5 CPU processes.
    Write-Host "`n### Top 5 CPU Processes ###"

    # Get a unique list of all process names excluding the "_total" instance.
    $AllProcessNames = $ProcessorUsage | Where-Object { $_.InstanceName -ne "_total" } | Sort-Object InstanceName -Unique | Select-Object -ExpandProperty InstanceName

    # Initialize an empty list to store process metrics.
    $Processes = New-Object -TypeName System.Collections.Generic.List[object]

    # Loop through each process name to calculate the CPU usage (min, max, avg) for each process.
    foreach ($ProcessName in $AllProcessNames) {
        $RelevantMetrics = $ProcessorUsage | Where-Object { $_.InstanceName -eq $ProcessName }

        # Group metrics by timestamp and calculate the total CPU usage for each timestamp.
        $GroupedMetrics = $RelevantMetrics | Group-Object Timestamp | Select-Object @{Name = "InstanceName"; Expression = { $ProcessName } }, @{Name = "CookedValue"; Expression = { $_.Group | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum } } | Sort-Object CookedValue
        
        # Add the CPU usage metrics (min, max, avg) for each process to the list.
        $Processes.Add(
            [PSCustomObject]@{
                "InstanceName" = $ProcessName
                "Min"          = $GroupedMetrics | Select-Object -ExpandProperty CookedValue -First 1
                "Max"          = $GroupedMetrics | Select-Object -ExpandProperty CookedValue -Last 1
                "Avg"          = ($GroupedMetrics | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum) / $DurationToPerformTests
            }
        )
    }

    # Sort the processes by average CPU usage in descending order and select the top 5.
    $Top5CPUProcesses = $Processes | Sort-Object "Avg" -Descending | Select-Object -First 5

    # Format the top 5 CPU processes for display.
    $FormattedProcesses = $Top5CPUProcesses | ForEach-Object {
        [PSCustomObject]@{
            "Process Name"       = $_.InstanceName
            "Average CPU % Used" = "$([math]::Round($_.Avg, 2))%"
            "Minimum CPU % Used" = "$([math]::Round($_.Min, 2))%"
            "Maximum CPU % Used" = "$([math]::Round($_.Max, 2))%"
        }
    } 

    # Display the formatted CPU process usage metrics.
    ($FormattedProcesses | Format-Table -AutoSize | Out-String).Trim() | Write-Host

    # Display the header for the top 5 RAM processes.
    Write-Host -Object "`n### Top 5 RAM Processes ###"

    # Get a unique list of process names that are not "_total" or "memory compression".
    $AllMemoryProcessNames = $MemoryUsage | Where-Object { $_.InstanceName -ne "_total" -and $_.InstanceName -ne "memory compression" } | Sort-Object InstanceName -Unique | Select-Object -ExpandProperty InstanceName

    # Initialize an empty list to store memory process metrics.
    $MemoryProcesses = New-Object -TypeName System.Collections.Generic.List[object]

    # Loop through each process to calculate the memory usage (min, max, avg) for each process.
    foreach ($ProcessName in $AllMemoryProcessNames) {
        $RelevantMetrics = $MemoryUsage | Where-Object { $_.InstanceName -eq $ProcessName }

        # Group metrics by timestamp and calculate the total memory usage for each timestamp.
        $GroupedMetrics = $RelevantMetrics | Group-Object Timestamp | Select-Object @{Name = "InstanceName"; Expression = { $ProcessName } }, @{Name = "CookedValue"; Expression = { $_.Group | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum } } | Sort-Object CookedValue
        
        # Add the memory usage metrics (min, max, avg) for each process to the list.
        $MemoryProcesses.Add(
            [PSCustomObject]@{
                "InstanceName" = $ProcessName
                "Min"          = $GroupedMetrics | Select-Object -ExpandProperty CookedValue -First 1
                "Max"          = $GroupedMetrics | Select-Object -ExpandProperty CookedValue -Last 1
                "Avg"          = ($GroupedMetrics | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum) / $DurationToPerformTests
            }
        )
    }

    # Sort the processes by average memory usage in descending order and select the top 5.
    $Top5RAMProcesses = $MemoryProcesses | Sort-Object "Avg" -Descending | Select-Object -First 5 | ForEach-Object {
        if (!$TotalMemoryBytes) {
            return
        }

        [PSCustomObject]@{
            "InstanceName" = $_.InstanceName
            "Min"          = $_.Min / $TotalMemoryBytes * 100
            "Max"          = $_.Max / $TotalMemoryBytes * 100
            "Avg"          = $_.Avg / $TotalMemoryBytes * 100
        }
    }

    # Format the top 5 RAM processes for display.
    $FormattedMemoryProcesses = $Top5RAMProcesses | ForEach-Object {
        if (!$TotalMemoryBytes) {
            return
        }

        [PSCustomObject]@{
            "Process Name"       = $_.InstanceName
            "Average RAM % Used" = "$([math]::Round($_.Avg, 2))%"
            "Minimum RAM % Used" = "$([math]::Round($_.Min, 2))%"
            "Maximum RAM % Used" = "$([math]::Round($_.Max, 2))%"
        }
    }
    
    # Display the formatted memory process usage metrics.
    ($FormattedMemoryProcesses | Format-Table -AutoSize | Out-String).Trim() | Write-Host

    # Display the header for network usage.
    Write-Host -Object "`n### Network Usage ###"

    # Get a unique list of network interfaces and initialize an empty list for storing network metrics.
    $NetworkInterfaces = $NetworkUsage | Sort-Object InstanceName -Unique | Select-Object -ExpandProperty InstanceName
    $NetworkInterfaceUsage = New-Object -TypeName System.Collections.Generic.List[object]

    # Loop through each network interface to calculate the network usage (min, max, avg) for each interface.
    foreach ($NetworkInterface in $NetworkInterfaces) {
        $RelevantMetrics = $NetworkUsage | Where-Object { $_.InstanceName -eq $NetworkInterface } | Sort-Object CookedValue

        try {
            # Correct the network interface name if necessary to match the system's adapter description.
            if (!(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.InterfaceDescription -eq $NetworkInterface })) {
                $NetworkInterface = $NetworkInterface -replace '\[', '(' -replace '\]', ')'
            }

            # Retrieve the network adapter details and determine if it's wired, Wi-Fi, or another type.
            $NetAdapter = Get-NetAdapter -ErrorAction Stop | Where-Object { $_.InterfaceDescription -eq $NetworkInterface } | Select-Object -First 1
            switch -Wildcard ($NetAdapter.MediaType) {
                "802.3" { $AdapterType = "Wired" }
                "*802.11" { $AdapterType = "Wi-Fi" }
                default { $AdapterType = "Other" }
            }
        }
        catch {
            Write-Host -Object "[Error] Failed to get details on the network interface '$NetworkInterface'."
            Write-Host -Object "[Error] $($_.Exception.Message)`n"
            $ExitCode = 1
            continue
        }

        # Add the network adapter usage metrics to the list.
        $NetworkInterfaceUsage.Add(
            [PSCustomObject]@{
                "NetworkAdapter" = $NetworkInterface
                "MacAddress"     = $NetAdapter.MacAddress
                "Type"           = $AdapterType
                "Min"            = $RelevantMetrics | Select-Object -ExpandProperty CookedValue -First 1
                "Max"            = $RelevantMetrics | Select-Object -ExpandProperty CookedValue -Last 1
                "Avg"            = ($RelevantMetrics | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum) / $DurationToPerformTests
            }
        )
    }

    # Format the network usage metrics for display.
    $FormattedNetworkUsage = $NetworkInterfaceUsage | Sort-Object "Avg" -Descending | ForEach-Object {
        [PSCustomObject]@{
            "NetworkAdapter"          = $_.NetworkAdapter
            "MacAddress"              = $_.MacAddress
            "Type"                    = $_.Type
            "Average Sent & Received" = "$([math]::Round(($_.Avg / 1MB * 8), 2)) Mbps"
            "Minimum Sent & Received" = "$([math]::Round(($_.Min / 1MB * 8), 2)) Mbps"
            "Maximum Sent & Received" = "$([math]::Round(($_.Max / 1MB * 8), 2)) Mbps"
        }
    }
    
    # Display the formatted network usage metrics.
    ($FormattedNetworkUsage | Format-List | Out-String).Trim() | Write-Host

    # Display the header for disk usage.
    Write-Host -Object "`n### Disk Usage ###"

    # Get a unique list of relevant disks and initialize an empty list for storing disk metrics.
    $RelevantDisks = $DiskUsage | Where-Object { $_.InstanceName -ne "_total" } | Sort-Object InstanceName -Unique | Select-Object -ExpandProperty InstanceName
    $DiskMetrics = New-Object -TypeName System.Collections.Generic.List[object]

    try {
        $AllDiskNumbers = Get-Partition -ErrorAction Stop | Select-Object -ExpandProperty DiskNumber -Unique
    }
    catch {
        Write-Host -Object "[Error] Unable to retrieve disk numbers."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    # Loop through each disk to calculate the disk usage (min, max, avg) for each disk.
    foreach ($RelevantDisk in $RelevantDisks) {
        $RelevantMetrics = $DiskUsage | Where-Object { $_.InstanceName -eq $RelevantDisk } | Sort-Object CookedValue

        # Parse the disk number and drive letter from the instance name.
        $DiskNumber = $RelevantDisk -split '\s' | Where-Object { $_ -match "^[0-9]$" }
        $DriveLetters = ($RelevantDisk -split '\s' | Where-Object { $_ -match "^[A-z]:$" }) -replace ':'

        # Retrieve the physical disk based on the provided DiskNumber.
        $PhysicalDisk = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceId -eq $DiskNumber }

        # Check if the disk number is part of the list of all disk numbers.
        if ($AllDiskNumbers -and $AllDiskNumbers -notcontains $DiskNumber) {

            # If the physical disk has a FriendlyName (meaning it was found), warn that no partitions were found on this disk.
            if ($PhysicalDisk.FriendlyName) {
                Write-Warning -Message "No partitions found on disk '$($PhysicalDisk.FriendlyName)'."
            }
            else {
                # If the physical disk has no FriendlyName, display a warning message using the DiskNumber.
                Write-Warning -Message "No partitions found on disk '$DiskNumber'."
            }
     
            Write-Host -Object ""

            # Continue to the next iteration in the loop, skipping the remaining code for this disk number.
            continue
        }

        # Attempt to retrieve the partitions for the specified disk number.
        try {
            $Partitions = Get-Partition -DiskNumber $DiskNumber -ErrorAction Stop
        }
        catch {
            # If an error occurs while getting the partitions, display an error message.
            Write-Host -Object "[Error] Accessing Partitions on disk '$DiskNumber'"

            # Display the exception message from the caught error.
            Write-Host -Object "[Error] $($_.Exception.Message)`n"

            # Set the exit code to indicate an error occurred.
            $ExitCode = 1

            # Continue to the next iteration in the loop, skipping further actions for this disk number.
            continue
        }

        # Retrieve partition information and add the disk usage metrics to the list.
        foreach ($DriveLetter in $DriveLetters) {
            $Partitions | Where-Object { $_.DriveLetter -eq $DriveLetter } | ForEach-Object {
                try {
                    $FreeSpace = Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $DriveLetter } | Select-Object -ExpandProperty SizeRemaining
                    $TotalSize = Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq $DriveLetter } | Select-Object -ExpandProperty Size
                }
                catch {
                    Write-Host -Object "[Error] Unable to determine the total size or free space of drive '$DriveLetter'."
                    Write-Host -Object "[Error] $($_.Exception.Message)`n"
                    $ExitCode = 1
                    continue
                }

                $FreeSpaceGB = [math]::Round(($FreeSpace / 1GB), 2)
                $FreeSpacePercent = [math]::Round(($FreeSpace / $TotalSize * 100), 2)
                $TotalSpaceGB = [math]::Round(($TotalSize / 1GB), 2)

                # Add the disk metrics to the list.
                $DiskMetrics.Add(
                    [PSCustomObject]@{
                        "DriveLetter"      = $_.DriveLetter
                        "FreeSpaceGB"      = $FreeSpaceGB
                        "FreeSpacePercent" = $FreeSpacePercent
                        "TotalSpace"       = "$TotalSpaceGB GB"
                        "PhysicalDisk"     = $PhysicalDisk | Select-Object -ExpandProperty FriendlyName
                        "MediaType"        = $PhysicalDisk | Select-Object -ExpandProperty MediaType
                        "Min"              = $RelevantMetrics | Select-Object -ExpandProperty CookedValue -First 1
                        "Max"              = $RelevantMetrics | Select-Object -ExpandProperty CookedValue -Last 1
                        "Avg"              = ($RelevantMetrics | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum) / $DurationToPerformTests
                    }
                )
            }
        }
    }

    # Add the disk metrics to the list.
    $FormattedDiskMetrics = $DiskMetrics | Sort-Object "Avg" -Descending | ForEach-Object {
        [PSCustomObject]@{
            "DriveLetter"  = $_.DriveLetter
            "FreeSpace"    = "$($_.FreeSpaceGB) GB ($($_.FreeSpacePercent)%)"
            "TotalSpace"   = $_.TotalSpace
            "PhysicalDisk" = $_.PhysicalDisk
            "MediaType"    = $_.MediaType
            "Average IOPS" = "$([math]::Round(($_.Avg), 2)) IOPS"
            "Minimum IOPS" = "$([math]::Round(($_.Min), 2)) IOPS"
            "Maximum IOPS" = "$([math]::Round(($_.Max), 2)) IOPS"
        }
    }
    
    # Display the formatted disk usage metrics.
    ($FormattedDiskMetrics | Format-Table | Out-String).Trim() | Write-Host

    # Display the header for top 5 I/O processes (network and disk combined).
    Write-Host -Object "`n### Top 5 IO Processes (Network & Disk Combined) ###"

    # Get a unique list of I/O process names excluding the "_total" instance.
    $AllIOProcessNames = $IOUsage | Where-Object { $_.InstanceName -ne "_total" } | Sort-Object InstanceName -Unique | Select-Object -ExpandProperty InstanceName
    $IOProcesses = New-Object -TypeName System.Collections.Generic.List[object]

    # Loop through each process to calculate the I/O usage (min, max, avg) for each process.
    foreach ($ProcessName in $AllIOProcessNames) {
        $RelevantMetrics = $IOUsage | Where-Object { $_.InstanceName -eq $ProcessName }

        # Group metrics by timestamp and calculate the total I/O usage for each timestamp.
        $GroupedMetrics = $RelevantMetrics | Group-Object Timestamp | Select-Object @{Name = "InstanceName"; Expression = { $ProcessName } }, @{Name = "CookedValue"; Expression = { $_.Group | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum } } | Sort-Object CookedValue
        
        # Add the I/O usage metrics to the list.
        $IOProcesses.Add(
            [PSCustomObject]@{
                "InstanceName" = $ProcessName
                "Min"          = $GroupedMetrics | Select-Object -ExpandProperty CookedValue -First 1
                "Max"          = $GroupedMetrics | Select-Object -ExpandProperty CookedValue -Last 1
                "Avg"          = ($GroupedMetrics | Measure-Object -Property CookedValue -Sum | Select-Object -ExpandProperty Sum) / $DurationToPerformTests
            }
        )
    }

    # Sort the I/O processes by average I/O usage and select the top 5.
    $Top5IOProcesses = $IOProcesses | Sort-Object "Avg" -Descending | Select-Object -First 5

    # Format the top 5 I/O processes for display.
    $FormattedIOProcesses = $Top5IOProcesses | ForEach-Object {
        [PSCustomObject]@{
            "Process Name"    = $_.InstanceName
            "Average IO Used" = "$([math]::Round(($_.Avg / 1MB * 8), 4)) Mbps"
            "Minimum IO Used" = "$([math]::Round(($_.Min / 1MB * 8), 4)) Mbps"
            "Maximum IO Used" = "$([math]::Round(($_.Max / 1MB * 8), 4)) Mbps"
        }
    } 
    
    # Display the formatted I/O process usage metrics.
    ($FormattedIOProcesses | Format-Table -AutoSize | Out-String).Trim() | Write-Host

    # Inform the user that WinSAT assessments are running.
    Write-Host -Object "`nRetrieving WinSAT assessment data."
    Write-Host -Object "More info: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-8.1-and-8/hh825488(v=win.10)"

    # Retrieve the WinSAT assessment scores.
    try {
        $WinSatScores = Get-CimInstance -ClassName Win32_WinSAT -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] Unable to retrieve WinSat assessment results."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    # Handle the different possible states of the WinSAT assessment.
    switch ($WinSatScores.WinSATAssessmentState) {
        0 { Write-Host -Object "[Error] WinSAT assessment data is not available on this computer" ; $ExitCode = 1 }
        1 { Write-Host -Object "Successfully retrieved assessment data." }
        2 { Write-Warning -Message "The WinSAT assessment data does not match the current computer configuration." }
        3 { Write-Host -Object "[Error] WinSAT assessment data is not available on this computer" ; $ExitCode = 1 }
        4 { Write-Host -Object "[Error] The WinSAT assessment data is not valid!" ; $ExitCode = 1 }
        default {
            Write-Host -Object "[Error] WinSAT assessment data is not available on this computer" ; $ExitCode = 1
        }
    }    

    # If the WinSAT assessment state is valid, display the assessment scores.
    $ValidAssessmentStates = "1", "2"
    if ($ValidAssessmentStates -contains $WinSatScores.WinSATAssessmentState) {
        Write-Host -Object "`n### WinSAT Scores ###"
        ($WinSatScores | Format-Table -Property CPUScore, D3DScore, DiskScore, GraphicsScore, MemoryScore | Out-String).Trim() | Write-Host
    }

    # If the WYSIWYG custom field is given, proceed to set and format the custom field.
    if ($WysiwygCustomField) {
        try {
            # Inform the user that the custom field is being set.
            Write-Host "`nAttempting to set Custom Field '$WysiwygCustomField'."

            $CompletedDateTime = Get-Date

            # Initialize the custom field value as a list of strings.
            $CustomFieldValue = New-Object System.Collections.Generic.List[String]

            # Convert the formatted CPU processes table to HTML and add custom formatting.
            $CPUProcessMetricTable = $FormattedProcesses | ConvertTo-Html -Fragment
            $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
            $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<table>", "<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Top 5 CPU Processes</b></caption>"
            $CPUProcessMetricTable = $CPUProcessMetricTable -replace "Average CPU % Used", "<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average CPU % Used"
            $CPUProcessMetricTable = $CPUProcessMetricTable -replace "Minimum CPU % Used", "<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum CPU % Used"
            $CPUProcessMetricTable = $CPUProcessMetricTable -replace "Maximum CPU % Used", "<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum CPU % Used"

            # Highlight rows in the CPU table based on CPU usage thresholds (warnings and danger levels).
            $Top5CPUProcesses | ForEach-Object {
                if ($_.Avg -ge 20 -and $_.Avg -lt 50) { $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }
                if ($_.Min -ge 20 -and $_.Min -lt 50) { $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }
                if ($_.Max -ge 20 -and $_.Max -lt 50) { $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }

                if ($_.Avg -ge 50) { $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
                if ($_.Min -ge 50) { $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
                if ($_.Max -ge 50) { $CPUProcessMetricTable = $CPUProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
            }

            # Convert the formatted RAM processes table to HTML and add custom formatting.
            $RAMProcessMetricTable = $FormattedMemoryProcesses | ConvertTo-Html -Fragment
            $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
            $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<table>", "<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Top 5 RAM Processes</b></caption>"
            $RAMProcessMetricTable = $RAMProcessMetricTable -replace "Average RAM % Used", "<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average RAM % Used"
            $RAMProcessMetricTable = $RAMProcessMetricTable -replace "Minimum RAM % Used", "<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum RAM % Used"
            $RAMProcessMetricTable = $RAMProcessMetricTable -replace "Maximum RAM % Used", "<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum RAM % Used"

            # Highlight rows in the RAM table based on RAM usage thresholds (warnings and danger levels).
            $Top5RAMProcesses | ForEach-Object {
                if ($_.Avg -ge 10 -and $_.Avg -lt 30) { $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }
                if ($_.Min -ge 10 -and $_.Min -lt 30) { $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }
                if ($_.Max -ge 10 -and $_.Max -lt 30) { $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }

                if ($_.Avg -ge 30) { $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
                if ($_.Min -ge 30) { $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
                if ($_.Max -ge 30) { $RAMProcessMetricTable = $RAMProcessMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
            }

            # Convert the formatted I/O processes table to HTML and add custom formatting.
            $IOProcessesMetricTable = $FormattedIOProcesses | ConvertTo-Html -Fragment
            $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
            $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<table>", "<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Top 5 IO Processes (Network & Disk Combined)</b></caption>"
            $IOProcessesMetricTable = $IOProcessesMetricTable -replace "Average IO Used", "<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average IO Used"
            $IOProcessesMetricTable = $IOProcessesMetricTable -replace "Minimum IO Used", "<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum IO Used"
            $IOProcessesMetricTable = $IOProcessesMetricTable -replace "Maximum IO Used", "<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum IO Used"

            # Highlight rows in the I/O table based on I/O usage thresholds (warnings and danger levels).
            $Top5IOProcesses | ForEach-Object {
                if ($_.Avg -ge 1250000 -and $_.Avg -lt 12500000) { $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }
                if ($_.Min -ge 1250000 -and $_.Min -lt 12500000) { $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }
                if ($_.Max -ge 1250000 -and $_.Max -lt 12500000) { $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='warning'><td>$($_.InstanceName)" }

                if ($_.Avg -ge 12500000) { $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
                if ($_.Min -ge 12500000) { $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
                if ($_.Max -ge 12500000) { $IOProcessesMetricTable = $IOProcessesMetricTable -replace "<tr><td>$($_.InstanceName)", "<tr class='danger'><td>$($_.InstanceName)" }
            }

            # Convert the formatted network usage table to HTML and add custom formatting.
            $NetworkUsageMetricTable = $FormattedNetworkUsage | ConvertTo-Html -Fragment
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<table>", "<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Network Usage</b></caption>"
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "Average Sent & Received", "<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average Sent & Received"
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "Minimum Sent & Received", "<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum Sent & Received"
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "Maximum Sent & Received", "<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum Sent & Received"

            # Add network type icons for wired, Wi-Fi, and other network interfaces.
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<th><b>Type</b></th>", "<th><b><i class='fa-solid fa-network-wired'></i>&nbsp;&nbsp;Type</b></th>"
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<td>Wired</td>", "<td><i class='fa-solid fa-ethernet'></i>&nbsp;&nbsp;Wired</td>"
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<td>Wi-Fi</td>", "<td><i class='fa-solid fa-wifi'></i>&nbsp;&nbsp;Wi-Fi</td>"
            $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<td>Other</td>", "<td><i class='fa-solid fa-circle-question'></i>&nbsp;&nbsp;Other</td>"

            # Highlight network interfaces based on network usage thresholds and interface types.
            $NetworkInterfaceUsage | ForEach-Object {
                if ($_.Avg -ge 1250000 -and $_.Avg -lt 12500000) { $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<tr><td>$($_.NetworkAdapter)", "<tr class='warning'><td>$($_.NetworkAdapter)" }
                if ($_.Min -ge 1250000 -and $_.Min -lt 12500000) { $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<tr><td>$($_.NetworkAdapter)", "<tr class='warning'><td>$($_.NetworkAdapter)" }
                if ($_.Max -ge 1250000 -and $_.Max -lt 12500000) { $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<tr><td>$($_.NetworkAdapter)", "<tr class='warning'><td>$($_.NetworkAdapter)" }

                if ($_.Avg -ge 12500000) { $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<tr><td>$($_.NetworkAdapter)", "<tr class='danger'><td>$($_.NetworkAdapter)" }
                if ($_.Min -ge 12500000) { $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<tr><td>$($_.NetworkAdapter)", "<tr class='danger'><td>$($_.NetworkAdapter)" }
                if ($_.Max -ge 12500000) { $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<tr><td>$($_.NetworkAdapter)", "<tr class='danger'><td>$($_.NetworkAdapter)" }

                # Highlight Wi-Fi or "Other" types as warnings.
                if ($_.Type -eq "Wi-Fi" -or $_.Type -eq "Other") {
                    $NetworkUsageMetricTable = $NetworkUsageMetricTable -replace "<tr><td>$($_.NetworkAdapter)", "<tr class='warning'><td>$($_.NetworkAdapter)"
                }
            }

            # Convert the formatted disk usage table to HTML and add custom formatting.
            $DiskMetricTable = $FormattedDiskMetrics | ConvertTo-Html -Fragment
            $DiskMetricTable = $DiskMetricTable -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
            $DiskMetricTable = $DiskMetricTable -replace "<table>", "<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Disk Usage</b></caption>"
            $DiskMetricTable = $DiskMetricTable -replace "Average IOPS", "<i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average IOPS"
            $DiskMetricTable = $DiskMetricTable -replace "Minimum IOPS", "<i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum IOPS"
            $DiskMetricTable = $DiskMetricTable -replace "Maximum IOPS", "<i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum IOPS"

            # Highlight rows in the disk usage table based on drive type and available space thresholds.
            $DiskMetrics | ForEach-Object {
                if ($_.MediaType -ne "SSD" -and $_.MediaType -ne "Unspecified") {
                    $DiskMetricTable = $DiskMetricTable -replace "<tr><td>$($_.DriveLetter)", "<tr class='danger'><td>$($_.DriveLetter)"
                }

                if ($_.FreeSpaceGB -lt 100) {
                    $DiskMetricTable = $DiskMetricTable -replace "<tr><td>$($_.DriveLetter)", "<tr class='warning'><td>$($_.DriveLetter)"
                }

                if ($_.FreeSpaceGB -lt 10) {
                    $DiskMetricTable = $DiskMetricTable -replace "<tr class='warning'><td>$($_.DriveLetter)", "<tr class='danger'><td>$($_.DriveLetter)"
                }
            }

            # Handle WinSAT assessment data if it's valid and add the WinSAT scores to the table.
            $ValidAssessmentStates = "1", "2"
            if ($ValidAssessmentStates -contains $WinSatScores.WinSATAssessmentState) {
                $WinSATMetricTable = $WinSatScores | Select-Object -Property CPUScore, D3DScore, DiskScore, GraphicsScore, MemoryScore | ConvertTo-Html -Fragment
                $WinSATMetricTable = $WinSATMetricTable -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
                $WinSATMetricTable = $WinSATMetricTable -replace "<table>", "<br><table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>WinSAT Scores</b></caption>"

                # Highlight rows in the WinSAT table based on score thresholds.
                if ($WinSatScores.CPUScore -lt 7 -or $WinSatScores.D3DScore -lt 7 -or $WinSatScores.DiskScore -lt 7 -or $WinSatScores.GraphicsScore -lt 7 -or $WinSatScores.MemoryScore -lt 7) {
                    $WinSATMetricTable = $WinSATMetricTable -replace "<tr><td>", "<tr class='warning'><td>"
                }

                if ($WinSatScores.CPUScore -lt 4 -or $WinSatScores.D3DScore -lt 4 -or $WinSatScores.DiskScore -lt 4 -or $WinSatScores.GraphicsScore -lt 4 -or $WinSatScores.MemoryScore -lt 4) {
                    $WinSATMetricTable = $WinSATMetricTable -replace "<tr class='warning'><td>", "<tr class='danger'><td>"
                }
            }
            else {
                # If WinSAT data is not available, display a message.
                $WinSATMetricTable = "<p style='margin-top: 0px'>The WinSAT assessment data is either invalid or not available for this computer.</p>"
            }

            # Create the HTML content for the performance metrics section.
            $HTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-gauge-high'></i>&nbsp;&nbsp;System Performance Metrics</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        <table style='border: 0px; justify-content: space-evenly; white-space: nowrap;'>
            <tbody>
                <tr>
                    <td style='border: 0px; white-space: nowrap; padding-left: 0px;'>
                        <p class='card-text'><b>Start Date and Time</b><br>$($StartedDateTime.ToShortDateString()) $($StartedDateTime.ToShortTimeString())</p>
                    </td>
                    <td style='border: 0px; white-space: nowrap;'>
                        <p class='card-text'><b>Completed Date and Time</b><br>$($CompletedDateTime.ToShortDateString()) $($CompletedDateTime.ToShortTimeString())</p>
                    </td>
                </tr>
            </tbody>
        </table>
        <p id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$($LastStartTime.ToShortDateString()) $($LastStartTime.ToShortTimeString())</p>
        <p><b>$CPU</b></p>
        <table style='border: 0px;'>
            <tbody>
                <tr>
                    <td style='border: 0px; white-space: nowrap'>
                        <div class='stat-card' style='display: flex;'>
                            <div class='stat-value' id='cpuOverallAvg' style='color: #008001;'>$($FormattedCPUPerformance."CPU Average %")</div>
                            <div class='stat-desc'><i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average CPU % Used</div>
                        </div>
                    </td>
                    <td style='border: 0px; white-space: nowrap'>
                        <div class='stat-card' style='display: flex;'>
                            <div class='stat-value' id='cpuOverallMin' style='color: #008001;'>$($FormattedCPUPerformance."CPU Minimum %")</div>
                            <div class='stat-desc'><i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum CPU % Used</div>
                        </div>
                    </td>
                    <td style='border: 0px; white-space: nowrap'>
                        <div class='stat-card' style='display: flex;'>
                            <div class='stat-value' id='cpuOverallMax' style='color: #008001;'>$($FormattedCPUPerformance."CPU Maximum %")</div>
                            <div class='stat-desc'><i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum CPU % Used</div>
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        <p><b>Total Memory: $TotalMemoryGB</b></p>
        <table style='border: 0px;'>
            <tbody>
                <tr>
                    <td style='border: 0px; white-space: nowrap'>
                        <div class='stat-card' style='display: flex;'>
                            <div class='stat-value' id='ramOverallAvg' style='color: #008001;'>$($OverallMemoryMetrics."RAM Average %")</div>
                            <div class='stat-desc'><i class='fa-solid fa-arrow-down-up-across-line'></i>&nbsp;&nbsp;Average RAM % Used</div>
                        </div>
                    </td>
                    <td style='border: 0px; white-space: nowrap'>
                        <div class='stat-card' style='display: flex;'>
                            <div class='stat-value' id='ramOverallMin' style='color: #008001;'>$($OverallMemoryMetrics."RAM Minimum %")</div>
                            <div class='stat-desc'><i class='fa-solid fa-arrows-down-to-line'></i>&nbsp;&nbsp;Minimum RAM % Used</div>
                        </div>
                    </td>
                    <td style='border: 0px; white-space: nowrap'>
                        <div class='stat-card' style='display: flex;'>
                            <div class='stat-value' id='ramOverallMax' style='color: #008001;'>$($OverallMemoryMetrics."RAM Maximum %")</div>
                            <div class='stat-desc'><i class='fa-solid fa-arrows-up-to-line'></i>&nbsp;&nbsp;Maximum RAM % Used</div>
                        </div>
                    </td>
                </tr>
            </tbody>
        </table>
        $CPUProcessMetricTable
        <br>
        $RAMProcessMetricTable
        <br>
        $NetworkUsageMetricTable
        <br>
        $DiskMetricTable
        <br>
        $IOProcessesMetricTable
        $(if($ValidAssessmentStates -notcontains $WinSatScores.WinSATAssessmentState) {"<p style='margin-bottom: 0px'><b>WinSAT Scores</b></p>"})
        $WinSATMetricTable
    </div>
</div>"
            # Modify the last startup time section based on whether the startup limit was exceeded or not.
            if ($ExceededLastStartupLimit) {
                $HTMLCard = $HTMLCard -replace "id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$($LastStartTime.ToShortDateString()) $($LastStartTime.ToShortTimeString())", "id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$($LastStartTime.ToShortDateString()) $($LastStartTime.ToShortTimeString())&nbsp;&nbsp;<i class='fa-solid fa-circle-exclamation' style='color: #D53948;'></i>"
            }
            elseif ($DaysSinceLastReboot -ge 0) {
                $HTMLCard = $HTMLCard -replace "id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$($LastStartTime.ToShortDateString()) $($LastStartTime.ToShortTimeString())", "id='lastStartup' class='card-text'><b>Last Startup Time</b><br>$($LastStartTime.ToShortDateString()) $($LastStartTime.ToShortTimeString())&nbsp;&nbsp;<i class='fa-solid fa-circle-check' style='color: #008001;'></i>"
            }

            # Highlight CPU performance metrics based on threshold values (color coding).
            if ($CPUPerformance.Avg -ge 60 -and $CPUPerformance.Avg -lt 90) { $HTMLCard = $HTMLCard -replace "id='cpuOverallAvg' style='color: #008001;'", "id='cpuOverallAvg' style='color: #FAC905;'" }
            if ($CPUPerformance.Min -ge 60 -and $CPUPerformance.Min -lt 90) { $HTMLCard = $HTMLCard -replace "id='cpuOverallMin' style='color: #008001;'", "id='cpuOverallMin' style='color: #FAC905;'" }
            if ($CPUPerformance.Max -ge 60 -and $CPUPerformance.Max -lt 90) { $HTMLCard = $HTMLCard -replace "id='cpuOverallMax' style='color: #008001;'", "id='cpuOverallMax' style='color: #FAC905;'" }

            if ($CPUPerformance.Avg -ge 90) { $HTMLCard = $HTMLCard -replace "id='cpuOverallAvg' style='color: #008001;'", "id='cpuOverallAvg' style='color: #D53948;'" }
            if ($CPUPerformance.Min -ge 90) { $HTMLCard = $HTMLCard -replace "id='cpuOverallMin' style='color: #008001;'", "id='cpuOverallMin' style='color: #D53948;'" }
            if ($CPUPerformance.Max -ge 90) { $HTMLCard = $HTMLCard -replace "id='cpuOverallMax' style='color: #008001;'", "id='cpuOverallMax' style='color: #D53948;'" }

            # Highlight RAM performance metrics based on threshold values (color coding).
            if ($MemoryPerformance.Avg -ge 60 -and $MemoryPerformance.Avg -lt 90) { $HTMLCard = $HTMLCard -replace "id='ramOverallAvg' style='color: #008001;'", "id='ramOverallAvg' style='color: #FAC905;'" }
            if ($MemoryPerformance.Min -ge 60 -and $MemoryPerformance.Min -lt 90) { $HTMLCard = $HTMLCard -replace "id='ramOverallMin' style='color: #008001;'", "id='ramOverallMin' style='color: #FAC905;'" }
            if ($MemoryPerformance.Max -ge 60 -and $MemoryPerformance.Max -lt 90) { $HTMLCard = $HTMLCard -replace "id='ramOverallMax' style='color: #008001;'", "id='ramOverallMax' style='color: #FAC905;'" }

            if ($MemoryPerformance.Avg -ge 90) { $HTMLCard = $HTMLCard -replace "id='ramOverallAvg' style='color: #008001;'", "id='ramOverallAvg' style='color: #D53948;'" }
            if ($MemoryPerformance.Min -ge 90) { $HTMLCard = $HTMLCard -replace "id='ramOverallMin' style='color: #008001;'", "id='ramOverallMin' style='color: #D53948;'" }
            if ($MemoryPerformance.Max -ge 90) { $HTMLCard = $HTMLCard -replace "id='ramOverallMax' style='color: #008001;'", "id='ramOverallMax' style='color: #D53948;'" }

            # Add the created HTML card to the custom field.
            $CustomFieldValue.Add($HTMLCard)

            # Check if there are any event logs to display.
            if ($NumberOfEvents -gt 0 -and $EventLogs.Count -gt 0) {
                # Convert the event logs into an HTML fragment for displaying in the output.
                $EventLogTableMetrics = $EventLogs | ConvertTo-Html -Fragment

                # Apply custom styles to the HTML table headers.
                $EventLogTableMetrics = $EventLogTableMetrics -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"

                # Set specific column widths for better presentation.
                $EventLogTableMetrics = $EventLogTableMetrics -replace "<th><b>LogName", "<th style='width: 100px'><b>Log Name"
                $EventLogTableMetrics = $EventLogTableMetrics -replace "<th><b>ProviderName", "<th style='width: 250px'><b>Provider Name"
                $EventLogTableMetrics = $EventLogTableMetrics -replace "<th><b>Id", "<th style='width: 75px'><b>Id"
                $EventLogTableMetrics = $EventLogTableMetrics -replace "<th><b>TimeCreated", "<th style='width: 175px'><b>Time Created"
            }
            elseif ($NumberOfEvents -gt 0) {
                # If no events were found, display a message instead of the table.
                $EventLogTableMetrics = "<p style='margin-top: 0px'>No error events were found in the event log.</p>"
            }

            # If event logs exist, create a card to display them.
            if ($NumberOfEvents -gt 0) {
                # Create the HTML structure for the event log card.
                $EventLogCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-book'></i>&nbsp;&nbsp;Recent Error Events</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        $EventLogTableMetrics
    </div>
</div>"
                # Add the event log card to the custom field value.
                $CustomFieldValue.Add($EventLogCard)
            }

            # Check if the HTML content exceeds the character limit (45,000 characters).
            $HTMLCharacters = $CustomFieldValue | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters
            if ($HTMLCharacters -ge 43000) {
                Write-Host -Object "The current character count is '$HTMLCharacters'."
                Write-Warning "45,000 Character Limit has been reached! Trimming output until the character limit is satisfied..."
                    
                # Truncate the output if it exceeds the limit.
                $i = 0
                $Attempts = 0
                [array]$NewEventLogTable = $EventLogTableMetrics
                $TrimStart = Get-Date
                do {
                    # Recreate the custom field output
                    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
                    if (!$NumberOfEvents -or !$NumberOfEvents -gt 0 -or !$EventLogs.Count -gt 0) {
                        Write-Host -Object "[Error] No events to trim."
                        exit 1
                    }

                    # Add the main performance metrics card to the custom field.
                    $CustomFieldValue.Add($HTMLCard)
    
                    # Reverse the event log array so that the last entry is at the top.
                    [array]::Reverse($NewEventLogTable)
                    # Delete rows until the character count is reduced.
                    if ($NewEventLogTable[$i] -match '<tr><td>' -or $NewEventLogTable[$i] -match '<tr class=') {
                        $NewEventLogTable[$i] = $null
                    }
                    $i++
                    
                    # Reverse the array back to its original order.
                    [array]::Reverse($NewEventLogTable)

                    # Rebuild the event log card with the truncated log.
                    $EventLogCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-book'></i>&nbsp;&nbsp;Recent Error Events</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        $NewEventLogTable
    </div>
</div>"

                    # Add a truncation notice and the truncated event log card.
                    $CustomFieldValue.Add("<h1>This info has been truncated to accommodate the 45,000 character limit.</h1>")
                    $CustomFieldValue.Add($EventLogCard)

                    # Check the character count again; repeat if still too long.
                    $HTMLCharacters = $CustomFieldValue | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters
                    $ElapsedTime = (Get-Date) - $TrimStart
                    if ($ElapsedTime.TotalMinutes -ge 5) {
                        Write-Host -Object "[Error] 5 minute timeout reached. Unable to trim the output to comply with the character limit."
                        exit 1
                    }
                }while ($HTMLCharacters -ge 43000)
            }

            # Set the custom field with the finalized HTML content.
            Set-NinjaProperty -Name $WysiwygCustomField -Value $CustomFieldValue -Type "WYSIWYG"
            Write-Host "Successfully set Custom Field '$WysiwygCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # If the $NumberOfEvents variable has a value, proceed to display the event logs.
    if ($NumberOfEvents) {
        # Display a message indicating the number of errors retrieved from the event logs.
        Write-Host -Object "`n### Last $NumberOfEvents errors in Application, Security, Setup and System Log. ###"

        # Format and display the collected event logs in a list format.
        ($EventLogs | Format-List | Out-String).Trim() | Write-Host
    }

    # Try to remove the lock file to ensure no other instance of the script is running.
    try {
        Remove-Item -Path "$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt" -Force -ErrorAction Stop
    }
    catch {
        # If the removal of the lock file fails, catch the exception and display error messages.
        Write-Host -Object "[Error] Failed to remove lock file at '$env:ProgramData\NinjaRMMAgent\SystemPerformance.lock.txt'."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    if ($DisplayUserMessage) {
        # Arguments for sending a message to notify the user that performance metrics have been recorded.
        $MSGArguments = @(
            "*"
            "/TIME:3600"
            "/V"
            "Performance metrics have been recorded and forwarded to your IT Administrator."
        )

        # Display an empty line for better readability in the output.
        Write-Host -Object ""

        # Generate unique file paths for stdout and stderr logs in the TEMP directory.
        $SecondMsgStandardOutLog = "$env:TEMP\$(New-Guid)_2NDMSG_stdout.log"
        $SecondMsgStandardErrLog = "$env:TEMP\$(New-Guid)_2NDMSG_stderr.log"

        # Start the process of sending a message to the users using msg.exe.
        try {
            Write-Host -Object "Sending message to all users."

            # Start the 'msg.exe' process with the provided arguments and capture stdout and stderr into log files.
            # -Wait ensures the script waits until the process completes.
            # -PassThru returns the process object so that the exit code can be captured.
            $SecondMsgProcess = Start-Process -FilePath "$env:SystemRoot\System32\msg.exe" -ArgumentList $MSGArguments -Wait -NoNewWindow -PassThru -RedirectStandardOutput $SecondMsgStandardOutLog -RedirectStandardError $SecondMsgStandardErrLog -ErrorAction Stop
        }
        catch {
            # If the process fails to start, output an error message and exit the script with an error code.
            Write-Host -Object "[Error] Failed to send message to all users."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        # Output the exit code of the msg.exe process.
        Write-Host -Object "ExitCode: $($SecondMsgProcess.ExitCode)"

        # If the exit code is non-zero (indicating an error), display an error message.
        if ($SecondMsgProcess.ExitCode -ne 0) {
            Write-Host -Object "[Error] ExitCode does not indicate success."
        }

        # Check if the standard output log file exists.
        if (Test-Path -Path $SecondMsgStandardOutLog -ErrorAction SilentlyContinue) {
            # Display the contents of the stdout log.
            Get-Content -Path $SecondMsgStandardOutLog -Encoding Oem -ErrorAction SilentlyContinue | Write-Host

            # Attempt to delete the stdout log file after displaying its contents.
            try {
                Remove-Item -Path $SecondMsgStandardOutLog -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to remove standard output log at '$SecondMsgStandardOutLog'"
                exit 1
            }
        }

        # Check if the standard error log file exists.
        if (Test-Path -Path $SecondMsgStandardErrLog -ErrorAction SilentlyContinue) {
            # Read the contents of the stderr log into a variable.
            $SecondMessageErrors = Get-Content -Path $SecondMsgStandardErrLog -Encoding Oem -ErrorAction SilentlyContinue

            # Attempt to delete the stderr log file after reading its contents.
            try {
                Remove-Item -Path $SecondMsgStandardErrLog -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to remove standard error log at '$SecondMsgStandardErrLog'"
                exit 1
            }
        }

        # If any errors were found in the stderr log, display them and exit with an error code.
        if ($SecondMessageErrors) {
            Write-Host -Object "[Error] Sending message to all users."
        
            # Iterate over each error and display it.
            $SecondMessageErrors | ForEach-Object {
                Write-Host -Object "[Error] $_"
            }

            exit 1
        }

        # If the msg.exe process exit code is non-zero, exit the script with an error code.
        if ($SecondMsgProcess.ExitCode -ne 0) {
            exit 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}
