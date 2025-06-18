# Retrieves the overall battery health and optionally saves the results to a WYSIWYG custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieves the overall battery health and optionally saves the results to a WYSIWYG custom field.
.DESCRIPTION
    Retrieves the overall battery health and optionally saves the results to a WYSIWYG custom field.
.EXAMPLE
    -WYSIWYGCustomField "WYSIWYG"

    Creating the battery health report.
    Battery life report saved to file path C:\Windows\Temp\batteryhealthreport.xml.
    Created the battery health report.
    Retrieving the report results.
    Retrieved the results.

    Parsing the system information.
    Parsing the battery specifications.
    Parsing the battery capacity history.
    Parsing the battery duration history.
    Parsing the recent battery usage history.

    Formatting the battery capacity history to be human-readable.
    Formatting the battery usage history to be human-readable.
    Formatting the recent usage history to be human-readable.

    Formatting the results for the WYSIWYG Custom Field 'WYSIWYGCustomField'.
    Creating the system information HTML card.
    Creating the installed batteries HTML card.
    Creating the battery capacity history HTML card.
    Creating the battery usage HTML card.
    Creating the recent usage HTML card.
    Assembling the final WYSIWYG Value
    Attempting to set the Custom Field 'WYSIWYG'.
    Successfully set the Custom Field 'WYSIWYG'!

    ### System Information ###
    ReportTime        : 12/16/2024 4:12 PM
    SystemProductName : Dell Inc. Precision 3571
    BIOS              : 1.27.0 9/27/2024
    OSBuild           : 26100.1.amd64fre.ge_release.240331-1435
    ConnectedStandby  : Supported

    ### Installed Batteries ###
    Name                    : DELL 0P3TJK9
    Manufacturer            : SMP
    SerialNumber            : 1
    Chemistry               : LiP
    UsableBatteryPercentage : 70.29%
    DesignCapacity          : 64007 mWh
    FullChargeCapacity      : 44992 mWh
    CycleCount              :  -

    ### Battery Capacity History ###
    Date       FullChargeCapacity DesignCapacity
    ----       ------------------ --------------
    12/15/2024 44992 mWh          64007 mWh
    12/9/2024  44992 mWh          64007 mWh
    5/26/2024  48929 mWh          64007 mWh
    2/4/2024   51565 mWh          64007 mWh
    1/7/2024   52850 mWh          64007 mWh
    12/24/2023 55681 mWh          64007 mWh
    12/10/2023 56057 mWh          64007 mWh
    10/1/2023  56787 mWh          64007 mWh
    8/27/2023  58532 mWh          64007 mWh
    7/30/2023  60709 mWh          64007 mWh
    7/16/2023  61052 mWh          64007 mWh
    4/30/2023  64007 mWh          64007 mWh
    4/2/2023   64007 mWh          64007 mWh

    ### Battery Usage ###
    StartDate  BatteryActive  BatteryConnectedStandby ACActive       ACConnectedStandby
    ---------  -------------  ----------------------- --------       ------------------
    12/15/2024  -             14s                      -             21h 59m 12s
    12/14/2024  -             13s                      -             21h 59m 12s
    12/13/2024 30m             -                      7h 10m 27s     16h 19m 12s
    12/12/2024  -             1h 59m 59s               -             21h 59m 17s
    12/11/2024 1h 58m 34s     13s                     2h 1m 20s      22h 17m 16s
    12/10/2024  -             1h 59m 52s               -             23h 28m 55s
    12/9/2024   -             1h 59m 39s               -             21h 59m 22s
    12/8/2024   -             1h 59m 59s               -             11h 59m 16s

    ### Recent Power Usage ###
    StartTime              State            Source  PercentageRemaining CapacityRemaining
    ---------              -----            ------  ------------------- -----------------
    12/16/2024 9:37:35 AM  Active           AC      34.9%               15702 mWh
    12/16/2024 9:00:35 AM  Active           Battery 100%                44992 mWh
    12/16/2024 8:17:21 AM  Active           AC      100%                44992 mWh
    12/15/2024 11:01:15 AM ConnectedStandby AC      81.18%              36526 mWh
    12/15/2024 9:00:59 AM  Suspend                  98.78%              44445 mWh
    12/15/2024 9:00:54 AM  ConnectedStandby Battery 98.95%              44521 mWh
    12/15/2024 9:00:44 AM  Suspend                  99.39%              44718 mWh
    12/15/2024 9:00:35 AM  ConnectedStandby Battery 100%                44992 mWh
    12/15/2024 9:00:33 AM  Suspend                  100%                44992 mWh
    12/14/2024 11:01:13 AM ConnectedStandby AC      77.4%               34823 mWh
    12/14/2024 9:00:50 AM  Suspend                  98.99%              44536 mWh
    12/14/2024 9:00:45 AM  ConnectedStandby Battery 99.16%              44612 mWh
    12/14/2024 9:00:40 AM  Suspend                  99.43%              44734 mWh
    12/14/2024 9:00:32 AM  ConnectedStandby Battery 100%                44992 mWh
    12/14/2024 9:00:30 AM  Suspend                  100%                44992 mWh
    12/13/2024 4:26:48 PM  ConnectedStandby AC      100%                44992 mWh
    12/13/2024 12:18:07 PM Active           AC      98.85%              44475 mWh
    12/13/2024 11:53:51 AM ConnectedStandby AC      92.09%              41435 mWh
    12/13/2024 11:53:20 AM Active           AC      91.86%              41329 mWh
    12/13/2024 11:44:16 AM ConnectedStandby AC      86.82%              39064 mWh
    12/13/2024 10:39:38 AM Active           AC      32.91%              14805 mWh
    12/13/2024 10:37:50 AM ConnectedStandby AC      32.91%              14805 mWh
    12/13/2024 9:30:34 AM  Active           AC      32.94%              14820 mWh
    12/13/2024 9:00:32 AM  Active           Battery 100%                44992 mWh
    12/13/2024 8:11:03 AM  Active           AC      100%                44992 mWh
    12/12/2024 11:01:09 AM ConnectedStandby AC      81.99%              36890 mWh
    12/12/2024 11:00:31 AM Suspend                  81.59%              36708 mWh
    12/12/2024 9:00:31 AM  ConnectedStandby Battery 100%                44992 mWh
    12/11/2024 1:01:56 PM  ConnectedStandby AC      100%                44992 mWh
    12/11/2024 11:00:33 AM Active           AC      50.37%              22663 mWh
    12/11/2024 9:01:58 AM  Active           Battery 97.47%              43852 mWh
    12/11/2024 9:00:48 AM  Suspend                  99.43%              44734 mWh
    12/11/2024 9:00:34 AM  ConnectedStandby Battery 100%                44992 mWh
    12/11/2024 9:00:33 AM  Suspend                  100%                44992 mWh
    12/11/2024 6:41:48 AM  ConnectedStandby AC      100%                44992 mWh
    12/10/2024 11:01:19 AM ConnectedStandby AC      79.53%              35781 mWh
    12/10/2024 11:00:35 AM Suspend                  78.99%              35538 mWh
    12/10/2024 9:00:54 AM  ConnectedStandby Battery 99.26%              44658 mWh
    12/10/2024 9:00:49 AM  Suspend                  99.43%              44734 mWh
    12/10/2024 9:00:37 AM  ConnectedStandby Battery 100%                44992 mWh
    12/10/2024 9:00:34 AM  Suspend                  100%                44992 mWh
    12/10/2024 7:30:51 AM  ConnectedStandby AC      100%                44992 mWh
    12/9/2024 5:13:22 PM   ConnectedStandby AC      100%                44992 mWh

PARAMETER: -WYSIWYGCustomField "ReplaceMeWithTheNameOfAWysiwygCustomField"
    Optionally, save the results to a WYSIWYG custom field.

.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$WYSIWYGCustomField
)

begin {
    # If script form variables are used, replace the commandline parameters with their value.
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WYSIWYGCustomField = $env:wysiwygCustomFieldName }

    # Attempt to retrieve the battery information using the appropriate command.
    try {
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            $CurrentBattery = Get-WmiObject -Class Win32_Battery -ErrorAction Stop
        }
        else {
            $CurrentBattery = Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop
        }
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] No battery detected on the system."
        exit 1
    }

    # Check if no battery information was retrieved.
    if (!$CurrentBattery) {
        # Inform the user that no battery was detected and exit with an error code.
        Write-Host -Object "[Error] No battery detected on the system."
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
            Write-Host -Object "[Error] Unable to validate whether or not this device is a server."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        # Check if the ProductType is "2", which indicates that the system is a domain controller or is a server
        if ($OS.ProductType -eq "2" -or $OS.ProductType -eq "3") {
            return $true
        }
    }

    # Function to convert time spans into a human-friendly string.
    function Get-FriendlyTimeSpan {
        param(
            [Parameter(Mandatory = $True)]
            [TimeSpan]$TimeSpan
        )
    
        # Check if the provided TimeSpan is less than 1 second.
        # Throw an exception if the TimeSpan is too short.
        if ($TimeSpan -le [TimeSpan]::FromMilliseconds(999)) {
            throw [System.ArgumentOutOfRangeException]::New("The provided time span is less than 0 seconds. Please specify a longer duration.")
        }
    
        # Build a human-readable representation of the TimeSpan.
        $FriendlyTimeSpan = $Null
        if ($TimeSpan.Days) { $FriendlyTimeSpan = "$($TimeSpan.Days)d" }
        if ($TimeSpan.Hours) { $FriendlyTimeSpan = "$FriendlyTimeSpan $($TimeSpan.Hours)h" }
        if ($TimeSpan.Minutes) { $FriendlyTimeSpan = "$FriendlyTimeSpan $($TimeSpan.Minutes)m" }
        if ($TimeSpan.Seconds) { $FriendlyTimeSpan = "$FriendlyTimeSpan $($TimeSpan.Seconds)s" }
    
        # Check if the conversion failed and no output was generated.
        if (!$FriendlyTimeSpan) {
            throw [System.FormatException]::New("Failed to convert the time span '$TimeSpan' into a human-friendly format.")
        }
    
        # Return the trimmed friendly TimeSpan string (removes any leading or trailing whitespace).
        $FriendlyTimeSpan.Trim()
    }

    # Function to parse ISO 8601 duration strings and convert them into a TimeSpan object
    function Get-ISO8601Duration {
        param(
            [Parameter()]
            [String]$Duration
        )

        # Validate that the duration starts with the 'P' designator
        if ($Duration -notmatch "^P") {
            throw [System.IO.InvalidDataException]::New("An invalid duration of '$Duration' was given. ISO 8601 durations require durations to start with the P designator. https://en.wikipedia.org/wiki/ISO_8601#Durations")
        }

        # Ensure the duration contains numeric characters
        if ($Duration -notmatch "[0-9]") {
            throw [System.IO.InvalidDataException]::New("An invalid duration of '$Duration' was given. ISO 8601 durations require numeric characters. https://en.wikipedia.org/wiki/ISO_8601#Durations")
        }

        # Validate that only allowed characters are present in the duration string
        if ($Duration -match "[^0-9PYMDTHS.,]") {
            throw [System.IO.InvalidDataException]::New("An invalid duration of '$Duration' was given. ISO 8601 non-alternative duration format can only contain the following characters '0-9PYMDTHS.,'. https://en.wikipedia.org/wiki/ISO_8601#Durations")
        }
    
        # Define patterns to match date and time components of ISO 8601 duration
        $DateFormat = "P.*(([0-9]+Y)+|([0-9]+M)+|([0-9]+D)+)"
        $TimeFormat = "P.*T(([0-9]+H)+|([0-9]+M)+|([0-9]+S)+)"

        # Ensure that the duration contains either valid date or time components
        if ($Duration -notmatch $DateFormat -and $Duration -notmatch $TimeFormat) {
            throw [System.IO.InvalidDataException]::New("An invalid duration of '$Duration' was given. The ISO 8601 non-alternative duration format should look like 'PnYnMnDTnHnMnS' where n is a number. https://en.wikipedia.org/wiki/ISO_8601#Durations")
        }

        # Extract the date part of the duration (e.g., "PnYnMnD")
        if ($Duration -match $DateFormat) {
            $Date = $Duration -replace ',', '.' -replace 'T.*'
        }

        # Extract the time part of the duration (e.g., "TnHnMnS")
        if ($Duration -match $TimeFormat) {
            $Time = $Duration -replace ',', '.' -replace '.*T'
        }

        # If both date and time components are missing, throw an error
        if (!$Date -and !$Time) {
            throw [System.IO.InvalidDataException]::New("Failed to extract the date and time sections from '$Duration'.")
        }

        # Parse date components: years, months, and days
        if ($Date -match '[0-9.,]+Y') { $YearsGiven = $Matches[0] -replace "Y" }
        if ($Date -match '[0-9.,]+M') { $MonthsGiven = $Matches[0] -replace "M" }
        if ($Date -match '[0-9.,]+D') { $DaysGiven = $Matches[0] -replace "D" }

        # Parse time components: hours, minutes, and seconds
        if ($Time -match '[0-9.,]+H') { $HoursGiven = $Matches[0] -replace "H" }
        if ($Time -match '[0-9.,]+M') { $MinutesGiven = $Matches[0] -replace "M" }
        if ($Time -match '[0-9.,]+S') { $SecondsGiven = $Matches[0] -replace "S" }

        # If no components were extracted, throw an error
        if (!$YearsGiven -and !$MonthsGiven -and !$DaysGiven -and !$HoursGiven -and !$MinutesGiven -and !$SecondsGiven) {
            throw [System.IO.InvalidDataException]::New("Failed to extract the years, months, days, hours, minutes, or seconds from '$Duration'.")
        }

        try {
            # Calculate the total duration in seconds
            if ($YearsGiven) { $TotalSeconds = ([double]$YearsGiven * 31557600) }
            if ($MonthsGiven) { $TotalSeconds = ([double]$TotalSeconds + ([double]$MonthsGiven * 2630016)) }
            if ($DaysGiven) { $TotalSeconds = ([double]$TotalSeconds + ([double]$DaysGiven * 86400)) }

            if ($HoursGiven) { $TotalSeconds = ([double]$TotalSeconds + ([double]$HoursGiven * 3600)) }
            if ($MinutesGiven) { $TotalSeconds = ([double]$TotalSeconds + ([double]$MinutesGiven * 60)) }
            if ($SecondsGiven) { $TotalSeconds = ([double]$TotalSeconds + [double]$SecondsGiven) }
        }
        catch {
            # Catch and re-throw any calculation errors
            throw $_
        }

        try {
            # Create and return a TimeSpan object representing the total duration
            New-TimeSpan -Seconds $TotalSeconds -ErrorAction Stop
        }
        catch {
            # Catch and re-throw any errors during TimeSpan creation
            throw $_
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
            $Value = $Value -replace ' ', '&nbsp;'
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

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the current user is running the script with elevated privileges.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run this with Administrator privileges."
        exit 1
    }

    # Check if this script is running on Windows Server.
    if (Test-IsServer) {
        Write-Host -Object "[Error] The powercfg battery report is not available on Windows Server. Please run this on a workstation."
        exit 1
    }

    # Set file paths for the battery report and log files.
    $BatteryReport = "$env:TEMP\batteryhealthreport.xml"
    $StandardOutputLog = "$(New-Guid)-stdout-batteryreport.log"
    $StandardErrorLog = "$(New-Guid)-stderr-batteryreport.log"

    # Define the arguments that will be passed to powercfg.exe to generate the battery report.
    $PowerCfgArguments = @(
        "/BATTERYREPORT"
        "/XML"
        "/OUTPUT"
        $BatteryReport
    )

    # Define the parameters for starting the powercfg.exe process, including output redirection.
    $PowerCfgProcessArguments = @{
        FilePath               = "$env:SYSTEMROOT\System32\powercfg.exe"
        ArgumentList           = $PowerCfgArguments
        RedirectStandardOutput = $StandardOutputLog
        RedirectStandardError  = $StandardErrorLog
        PassThru               = $True
        NoNewWindow            = $True
        Wait                   = $True
    }

    Write-Host -Object "Creating the battery health report."
    # Attempt to run the powercfg.exe process with the specified arguments.
    try {
        $PowerCfgProcess = Start-Process @PowerCfgProcessArguments -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to generate battery health report."
        exit 1
    }

    # Check the exit code of the powercfg.exe process. A non-zero exit code may indicate an error.
    if ($PowerCfgProcess.ExitCode -ne 0) {
        Write-Host -Object "Exit Code: $($PowerCfgProcess.ExitCode)"
        Write-Host -Object "The exit code does not indicate success."
        $ExitCode = $PowerCfgProcess.ExitCode
    }

    # If the standard output log file exists, attempt to read it.
    if (Test-Path -Path $StandardOutputLog -ErrorAction SilentlyContinue) {
        try {
            $StandardOutput = Get-Content -Path $StandardOutputLog -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to read the standard output log."
            $ExitCode = 1
        }

        if ($StandardOutput) {
            $StandardOutput | Write-Host
        }
    }

    # Attempt to remove the standard output log after reading it.
    if (Test-Path -Path $StandardOutputLog -ErrorAction SilentlyContinue) {
        try {
            Remove-Item -Path $StandardOutputLog -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove the standard output log."
            $ExitCode = 1
        }
    }

    # If the standard error log file exists, attempt to read it.
    if (Test-Path -Path $StandardErrorLog -ErrorAction SilentlyContinue) {
        try {
            $StandardError = Get-Content -Path $StandardErrorLog -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to read the standard error log."
            $ExitCode = 1
        }

        # If there's any standard error content, print each line as an error and set exit code to 1.
        if ($StandardError) {
            $StandardError | ForEach-Object {
                if ($_ -and $_.Trim()) {
                    Write-Host -Object "[Error] $_"
                    $ExitCode = 1
                }
            }
        }
    }

    # Attempt to remove the standard error log after reading it.
    if (Test-Path -Path $StandardErrorLog -ErrorAction SilentlyContinue) {
        try {
            Remove-Item -Path $StandardErrorLog -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove the standard error log."
            $ExitCode = 1
        }
    }

    # Check if the battery report XML file was created successfully.
    if (!$(Test-Path -Path $BatteryReport)) {
        Write-Host -Object "[Error] Failed to generate the battery health report at '$BatteryReport'."
        exit 1
    }
    else {
        Write-Host -Object "Created the battery health report."
    }

    Write-Host -Object "Retrieving the report results."
    # Attempt to load the battery report XML content into a variable.
    try {
        [xml]$BatteryHealthReport = Get-Content -Path "$BatteryReport" -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to retrieve the report results."
        exit 1
    }

    # Attempt to remove the battery report file after reading it.
    try {
        Remove-Item -Path $BatteryReport -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to remove the battery report at '$BatteryReport'."
        $ExitCode = 1
    }

    # Check if the battery report is empty.
    if (!$BatteryHealthReport) {
        Write-Host -Object "[Error] The report was empty. Failed to retrieve the report results."
        exit 1
    }
    else {
        Write-Host -Object "Retrieved the results."
    }

    Write-Host -Object "`nParsing the system information."
    # Extract system information from the battery health report XML.
    $SystemManufacturer = $BatteryHealthReport.BatteryReport.SystemInformation.SystemManufacturer
    $SystemProductName = $BatteryHealthReport.BatteryReport.SystemInformation.SystemProductName
    $BIOSVersion = $BatteryHealthReport.BatteryReport.SystemInformation.BIOSVersion
    $BIOSDate = Get-Date $BatteryHealthReport.BatteryReport.SystemInformation.BIOSDate -ErrorAction SilentlyContinue

    # Determine if Connected Standby is supported based on the report's data.
    $ConnectedStandby = switch ($BatteryHealthReport.BatteryReport.SystemInformation.ConnectedStandby) {
        1 { "Supported" }
        default {
            "Not Supported"
        }
    }

    # Attempt to parse the report time and convert it to a readable format.
    try {
        $ReportTime = Get-Date $BatteryHealthReport.BatteryReport.ReportInformation.LocalScanTime
        $ReportTime = "$($ReportTime.ToShortDateString()) $($ReportTime.ToShortTimeString())"
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to retrieve the timestamp for the report."
        $ExitCode = 1
    }
    
    # Create a custom object to store the extracted system information
    $SystemInformation = [PSCustomObject]@{
        ReportTime        = $ReportTime
        SystemProductName = "$SystemManufacturer $SystemProductName"
        BIOS              = if ($BIOSDate) { "$BIOSVersion $($BIOSDate.ToShortDateString())" }else { "$BIOSVersion" }
        OSBuild           = $BatteryHealthReport.BatteryReport.SystemInformation.OSBuild
        ConnectedStandby  = $ConnectedStandby
    }

    Write-Host -Object "Parsing the battery specifications."

    # Create a list to hold battery information objects.
    $Batteries = New-Object System.Collections.Generic.List[Object]

    # Iterate through each battery entry in the battery report.
    $BatteryHealthReport.BatteryReport.Batteries.Battery | ForEach-Object {
        # Calculate the usable battery percentage if both design capacity and full charge capacity are present.
        $UsablePercent = if ($_.DesignCapacity -and $_.FullChargeCapacity) {
            try {
                # Perform a mathematical calculation to determine the percentage.
                [math]::Round((($($_.FullChargeCapacity) / $($_.DesignCapacity) * 100)), 2)
            }
            catch {
                Write-Host -Object "[Error] Failed to calculate usable battery percentage for the battery $($_.Id) $($_.SerialNumber)"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                $ExitCode = 1
            }
        }

        # Add a custom object representing the current battery's details to the $Batteries list.
        $Batteries.Add(
            [PSCustomObject]@{
                Name                    = $_.Id
                Manufacturer            = $_.Manufacturer
                SerialNumber            = $_.SerialNumber
                Chemistry               = $_.Chemistry
                UsableBatteryPercentage = if ($UsablePercent) { "$UsablePercent%" }else { " - " }
                DesignCapacity          = "$($_.DesignCapacity) mWh"
                FullChargeCapacity      = "$($_.FullChargeCapacity) mWh"
                CycleCount              = if ($_.CycleCount -eq 0) { " - " }else { $_.CycleCount }
            }
        )
    }

    # Print a message indicating the parsing of battery capacity history.
    Write-Host -Object "Parsing the battery capacity history."

    # Create a list to hold battery capacity history objects.
    $BatteryCapacityHistory = New-Object System.Collections.Generic.List[Object]

    # Iterate through each history entry, converting the date and capturing capacities.
    $HistoryEntries = $BatteryHealthReport.BatteryReport.History.HistoryEntry | ForEach-Object {
        try {
            [PSCustomObject]@{
                Date               = (Get-Date $_.LocalEndDate -ErrorAction Stop)
                FullChargeCapacity = $_.FullChargeCapacity
                DesignCapacity     = $_.DesignCapacity
            }
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to get the date for the history entry dated '$($_.LocalEndDate)'"
            $ExitCode = 1
            return
        }
    }

    # Add unique history entries based on FullChargeCapacity to the battery capacity history list.
    $HistoryEntries | Sort-Object -Property FullChargeCapacity -Unique | ForEach-Object {
        $BatteryCapacityHistory.Add(
            $_
        )
    }

    # If there are at least 3 entries, add the most recent one (sorted by date) to the list.
    if (($HistoryEntries | Measure-Object | Select-Object -ExpandProperty Count) -ge 3) {
        $BatteryCapacityHistory.Add(($HistoryEntries | Sort-Object Date | Select-Object -Last 1))
    }

    # Add the oldest entry to the list.
    $BatteryCapacityHistory.Add(($HistoryEntries | Sort-Object Date | Select-Object -First 1))

    Write-Host -Object "Parsing the battery duration history."

    # Iterate through each history entry to compute battery usage durations.
    $BatteryUsageEntries = $BatteryHealthReport.BatteryReport.History.HistoryEntry | ForEach-Object {
        # Convert the stored start date to a DateTime object.
        try {
            $HistoryStartDate = Get-Date $_.LocalStartDate -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to get the start date for the history entry dated '$($_.LocalStartDate)' with the end date of '$($_.LocalEndDate)'"
            $ExitCode = 1
            return
        }

        # Convert the stored end date to a DateTime object.
        try {
            $HistoryEndDate = Get-Date $_.LocalEndDate -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to get the end date for the history entry dated '$($_.LocalEndDate)' with the start date of '$($_.LocalStartDate)'"
            $ExitCode = 1
            return
        }

        # Calculate the timespan between the start and end dates.
        try {
            $HistoryTimeSpan = New-TimeSpan -Start $HistoryStartDate -End $HistoryEndDate -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to get time span for the history entry that started on '$HistoryStartDate' and ended on '$HistoryEndDate'."
            $ExitCode = 1
            return
        }

        # If the duration is more than one day, skip this entry as it's not needed.
        if ($HistoryTimeSpan.TotalDays -gt 1) {
            return
        }

        # Convert ActiveDcTime to a PowerShell time span if possible.
        try {
            $BatteryActiveDuration = Get-ISO8601Duration -Duration $_.ActiveDcTime -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to translate the active battery duration for '$($_.ActiveDcTime)' on '$($HistoryStartDate.ToShortDateString()) $($HistoryStartDate.ToShortTimeString())'."
            $ExitCode = 1
        }

        # Convert CsDcTime (Connected Standby on battery) to a PowerShell time span if possible.
        try {
            $BatteryConnectedDuration = Get-ISO8601Duration -Duration $_.CsDcTime -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to translate the battery connected standby duration for '$($_.CsDcTime)' on '$($HistoryStartDate.ToShortDateString()) $($HistoryStartDate.ToShortTimeString())'."
            $ExitCode = 1
        }

        # Convert ActiveAcTime (Active time on AC) to a PowerShell time span if possible.
        try {
            $ACActiveDuration = Get-ISO8601Duration -Duration $_.ActiveAcTime -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to translate the active AC duration for '$($_.ActiveAcTime)' on '$($HistoryStartDate.ToShortDateString()) $($HistoryStartDate.ToShortTimeString())'."
            $ExitCode = 1
        }

        # Convert CsAcTime (Connected Standby on AC) to a PowerShell time span if possible.
        try {
            $ACConnectedStandby = Get-ISO8601Duration -Duration $_.CsAcTime -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to translate the AC connected standby duration for '$($_.CsAcTime)' on '$($HistoryStartDate.ToShortDateString()) $($HistoryStartDate.ToShortTimeString())'."
            $ExitCode = 1
        }

        # Return a custom object representing this history entry's duration details.
        [PSCustomObject]@{
            StartDate               = $HistoryStartDate
            EndDate                 = $HistoryEndDate
            BatteryActive           = $BatteryActiveDuration
            BatteryConnectedStandby = $BatteryConnectedDuration
            ACActive                = $ACActiveDuration
            ACConnectedStandby      = $ACConnectedStandby
        }
    }

    Write-Host -Object "Parsing the recent battery usage history."

    # Filter recent usage entries to exclude those with an EntryType of "ReportGenerated".
    # For each entry, convert the timestamp, determine the power source, and calculate the percentage remaining.
    $RecentUsageEntries = $BatteryHealthReport.BatteryReport.RecentUsage.UsageEntry | Where-Object { $_.EntryType -ne "ReportGenerated" } | ForEach-Object {
        # Attempt to convert the LocalTimeStamp to a DateTime object.
        try {
            $StartTime = Get-Date $_.LocalTimeStamp
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to get the timestamp for the battery usage entry dated '$($_.LocalTimeStamp)'"
            $ExitCode = 1
            return
        }

        # Determine the power source: AC if 'AC' is 1, otherwise Battery.
        $Source = switch ($_.AC) {
            1 { "AC" }
            default { "Battery" }
        }

        # If the entry type is "Suspend", there's no source (set to $Null).
        if ($_.EntryType -eq "Suspend") {
            $Source = $Null
        }

        # Calculate the percentage of battery remaining.
        try {
            $PercentageRemaining = [math]::Round((($_.ChargeCapacity / $_.FullChargeCapacity) * 100), 2)
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to calculate battery percentage remaining from the battery usage entry dated '$StartTime'"
            $ExitCode = 1
        }

        # Return a custom object with the processed information for this usage entry.
        [PSCustomObject]@{
            StartTime           = $StartTime
            State               = $_.EntryType
            Source              = $Source
            PercentageRemaining = "$PercentageRemaining%"
            CapacityRemaining   = "$($_.ChargeCapacity) mWh"
        }
    }

    Write-Host -Object "`nFormatting the battery capacity history to be human-readable."

    # Convert each battery capacity history entry into a custom object with human-readable date and capacities.
    $BatteryCapacityHistoryTable = $BatteryCapacityHistory | Sort-Object -Property Date -Descending | ForEach-Object {
        [PSCustomObject]@{
            Date               = $_.Date.ToShortDateString()
            FullChargeCapacity = "$($_.FullChargeCapacity) mWh"
            DesignCapacity     = "$($_.DesignCapacity) mWh"
        }
    }

    Write-Host -Object "Formatting the battery usage history to be human-readable."

    # Convert each battery usage entry into a human-readable format.
    $BatteryUsageTable = $BatteryUsageEntries | Sort-Object -Property StartDate -Descending | ForEach-Object {
        # If BatteryActive is greater than ~1 second, attempt to convert it to a friendly time span.
        if ($_.BatteryActive -and $_.BatteryActive -gt [TimeSpan]::FromMilliseconds(999)) {
            try {
                $BatteryActive = Get-FriendlyTimeSpan -TimeSpan $_.BatteryActive -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to get a human-readable string for the battery active duration of '$($_.BatteryActive)' for $($_.StartDate.ToShortDateString())."
                $BatteryActive = " - "
                $ExitCode = 1
            }
        }
        else {
            $BatteryActive = " - "
        }

        # If BatteryConnectedStandby is greater than ~1 second, convert it to a friendly time span.
        if ($_.BatteryConnectedStandby -and $_.BatteryConnectedStandby -gt [TimeSpan]::FromMilliseconds(999)) {
            try {
                $BatteryConnectedStandby = Get-FriendlyTimeSpan -TimeSpan $_.BatteryConnectedStandby -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to get a human-readable string for the battery connected standby duration of '$($_.BatteryConnectedStandby)' for $($_.StartDate.ToShortDateString())."
                $BatteryConnectedStandby = " - "
                $ExitCode = 1
            }
        }
        else {
            $BatteryConnectedStandby = " - "
        }

        # If ACActive is greater than ~1 second, convert it to a friendly time span.
        if ($_.ACActive -and $_.ACActive -gt [TimeSpan]::FromMilliseconds(999)) {
            try {
                $ACActive = Get-FriendlyTimeSpan -TimeSpan $_.ACActive -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to get a human-readable string for the AC active duration of '$($_.ACActive)' for $($_.StartDate.ToShortDateString())."
                $ACActive = " - "
                $ExitCode = 1
            }
        }
        else {
            $ACActive = " - "
        }

        # If ACConnectedStandby is greater than ~1 second, convert it to a friendly time span.
        if ($_.ACConnectedStandby -and $_.ACConnectedStandby -gt [TimeSpan]::FromMilliseconds(999)) {
            try {
                $ACConnectedStandby = Get-FriendlyTimeSpan -TimeSpan $_.ACConnectedStandby -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to get a human-readable string for the AC connected standby duration of '$($_.ACConnectedStandby)' for $($_.StartDate.ToShortDateString())."
                $ACActive = " - "
                $ExitCode = 1
            }
        }
        else {
            $ACConnectedStandby = " - "
        }

        # Return a custom object representing the formatted usage information.
        [PSCustomObject]@{
            StartDate               = $_.StartDate.ToShortDateString()
            BatteryActive           = $BatteryActive
            BatteryConnectedStandby = $BatteryConnectedStandby
            ACActive                = $ACActive
            ACConnectedStandby      = $ACConnectedStandby
        }
    }

    Write-Host -Object "Formatting the recent usage history to be human-readable."
    # Convert each recent usage entry into a human-readable format, including date and time.
    $RecentUsageEntryTable = $RecentUsageEntries | Sort-Object -Property StartTime -Descending | ForEach-Object {
        [PSCustomObject]@{
            StartTime           = "$($_.StartTime.ToShortDateString()) $($_.StartTime.ToLongTimeString())"
            State               = $_.State
            Source              = $_.Source
            PercentageRemaining = $_.PercentageRemaining
            CapacityRemaining   = $_.CapacityRemaining
        }
    }

    if ($WYSIWYGCustomField) {
        Write-Host -Object "`nFormatting the results for the WYSIWYG Custom Field 'WYSIWYGCustomField'."

        Write-Host -Object "Creating the system information HTML card."

        # Build an HTML card displaying system information details using the previously collected data.
        $SystemInformationHTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-computer'></i>&nbsp;&nbsp;System Information</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        <p><b>Report Time</b><br>$($SystemInformation.ReportTime)</p>
        <p><b>System Product Name</b><br>$($SystemInformation.SystemProductName)</p>
        <p><b>BIOS</b><br>$($SystemInformation.BIOS)</p>
        <p><b>OS Build</b><br>$($SystemInformation.OSBuild)</p>
        <p><b>Connected Standby</b><br>$($SystemInformation.ConnectedStandby)</p>
    </div>
</div>"

        Write-Host -Object "Creating the installed batteries HTML card."

        # Initialize a counter to label each battery.
        $i = 1
        # Build an HTML card that displays a table of all installed batteries and their properties.
        $InstalledBatteriesHTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-car-battery'></i>&nbsp;&nbsp;Installed Batteries</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        <table>
            <colgroup>
                <col style='width: 15em;' />
                $($Batteries | ForEach-Object {"<col style='width: 14em;' />`n"})
            </colgroup>
            <thead>
                <tr>
                    <td> </td>
                    $($Batteries | ForEach-Object {"<td><b>Battery $i</b></td>`n"; $i++})
                </tr>
            </thead>
            <tr>
                <td><b>Name</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.Name)</td>`n"})
            </tr>
            <tr>
                <td><b>Manufacturer</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.Manufacturer)</td>`n"})
            </tr>
            <tr>
                <td><b>Serial Number</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.SerialNumber)</td>`n"})
            </tr>
            <tr>
                <td><b>Chemistry</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.Chemistry)</td>`n"})
            </tr>
            <tr>
                <td><b>Usable Battery Percentage</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.UsableBatteryPercentage)</td>`n"})
            </tr>
            <tr>
                <td><b>Design Capacity</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.DesignCapacity)</td>`n"})
            </tr>
            <tr>
                <td><b>Full Charge Capacity</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.FullChargeCapacity)</td>`n"})
            </tr>
            <tr>
                <td><b>Cycle Count</b></td>
                $($Batteries | ForEach-Object {"<td>$($_.CycleCount)</td>`n"})
            </tr>
        </table>
    </div>
</div>"

        Write-Host -Object "Creating the battery capacity history HTML card."
        # Convert the battery capacity history table into an HTML fragment and format table headers in bold.
        $BatteryCapacityHistoryHTMLTable = $BatteryCapacityHistoryTable | ConvertTo-Html -Fragment
        $BatteryCapacityHistoryHTMLTable = $BatteryCapacityHistoryHTMLTable -replace '<th>', '<th><b>' -replace '</th>', '</b></th>'
        
        # If battery capacity history data exists, create a detailed HTML card with a line chart.
        if ($BatteryCapacityHistory) {
            $BatteryCapacityHistoryHTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-magnifying-glass-chart'></i>&nbsp;&nbsp;Battery Capacity History</div>
    </div>
    <div class='card-body'>
        <div class='row'>
            <table class='charts-css line show-data-axes show-5-secondary-axes show-labels'>
                <tbody style='height: 27em; padding-left: 4.5em; padding-right: 4.5em'>
                $(
                    $PreviousCapacityPercentage = 0.99
                    $BatteryCapacityHistory | Sort-Object Date | ForEach-Object {
                        try {
                            $CurrentCapacityPercentage = [math]::Round(($_.FullChargeCapacity / $_.DesignCapacity),2)
                            if($CurrentCapacityPercentage -eq 1){
                                $CurrentCapacityPercentage = 0.99
                            }
                        }catch{
                            Write-Host -Object "[Error] $($_.Exception.Message)"
                            Write-Host -Object "[Error] Failed to calculate the capacity percentage for '$($_.Date.ToShortDateString)'."
                            return
                        }
                        "<tr>
                            <th scope='row'>$($_.Date.ToString("MM-dd yyyy"))</th>
                            <td style='--start: $PreviousCapacityPercentage; --end: $CurrentCapacityPercentage'><span class='data'>$($_.FullChargeCapacity) mWh</span></td>
                        </tr>`n"
                        $PreviousCapacityPercentage = $CurrentCapacityPercentage
                    }
                )
                </tbody>
            </table>
        </div>
        <div class='row'>
            $BatteryCapacityHistoryHTMLTable
        </div>
    </div>
</div>"
        }

        # If no battery capacity history data is available, show a message indicating unavailability.
        if (!$BatteryCapacityHistory) {
            $BatteryCapacityHistoryHTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-magnifying-glass-chart'></i>&nbsp;&nbsp;Battery Capacity History</div>
    </div>
    <div class='card-body'>
        <p class='card-text'>Information not available or not found.</p>
    </div>
</div>"
        }
        
        Write-Host -Object "Creating the battery usage HTML card."
        # If battery usage entries exist, generate a card that includes a chart and a table of usage information.
        if ($BatteryUsageEntries) {
            $BatteryUsageHTMLTable = $BatteryUsageTable | ConvertTo-Html -Fragment

            # Remove and replace parts of the generated HTML to create a custom table layout and headings.
            $BatteryUsageHTMLTable = $BatteryUsageHTMLTable -replace "<colgroup>.*", ""
            $BatteryUsageHTMLTable = $BatteryUsageHTMLTable -replace "<tr><th>.*", "<thead>
    <tr>
        <th></th>
        <th style='text-align: center' colspan='2'><b>Battery Duration</b></th>
        <th style='text-align: center' colspan='2'><b>AC Duration</b></th>
    </tr>
    <tr>
        <th><b>Date</b></th>
        <th><b>Active</b></th>
        <th><b>Connected Standby</b></th>
        <th><b>Active</b></th>
        <th><b>Connected Standby</b></th>
    </tr>
</thead>
<tbody>"
            $BatteryUsageHTMLTable = $BatteryUsageHTMLTable -replace "</table>", "</tbody>`n</table>"

            $BatteryUsageHTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-magnifying-glass-chart'></i>&nbsp;&nbsp;Battery Usage</div>
    </div>
    <div class='card-body'>
        <div class='row'>
            <table class='charts-css column show-data-axes show-5-secondary-axes show-heading show-labels show-data-on-hover'>
                <caption><b>Battery Duration</b></caption>
                <tbody>
                    $($BatteryUsageEntries | ForEach-Object {
                        # Initialize variables for duration calculations.
                        $TotalBatteryDuration = $null
                        $FriendlyTimeSpan = $null
                        $TotalBatteryPercent = $null

                        try{
                            # Calculate the total battery duration and its percentage of a 24-hour period.
                            $TotalBatteryDuration = ($_.BatteryActive + $_.BatteryConnectedStandby)
                            $TotalBatteryPercent = [math]::Round(($TotalBatteryDuration.TotalHours / 24), 2)
                        }catch{
                            Write-Host -Object "[Error] $($_.Exception.Message)"
                            Write-Host -Object "[Error] Failed to calculate the percentage of online hours for the battery duration graph for '$($_.StartDate.ToShortDateString())'."
                            $ExitCode = 1
                            return
                        }

                        try{
                            # Convert the total battery duration to a friendly time span string if it's more than ~1 second.
                            if($TotalBatteryDuration -and $TotalBatteryDuration -gt [TimeSpan]::FromMilliseconds(999)){
                                $FriendlyTimeSpan = Get-FriendlyTimeSpan -TimeSpan $TotalBatteryDuration
                            }else{
                                $FriendlyTimeSpan = " - "
                            }
                        }catch{
                            Write-Host -Object "[Error] $($_.Exception.Message)"
                            Write-Host -Object "[Error] Failed to create a friendly time span for '$($_.StartDate.ToShortDateString())'."
                            $ExitCode = 1
                            return
                        }

                        # Create a table row for each usage entry with a visual representation of battery duration.
                        "<tr>
                            <th scope='row'>$($_.StartDate.ToString("MM-dd"))</th>
                            <td style='--size: $TotalBatteryPercent'><span class='data'>$FriendlyTimeSpan</span></td>
                        </tr>`n"
                    })               
                </tbody>
            </table>
        </div>
        <div class='row'>
            $BatteryUsageHTMLTable   
        </div>
    </div>
</div>"
        }

        # If there are no battery usage entries, display a message indicating no available information.
        if (!$BatteryUsageEntries) {
            $BatteryUsageHTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-magnifying-glass-chart'></i>&nbsp;&nbsp;Battery Usage</div>
    </div>
    <div class='card-body'>
        <p class='card-text'>Information not available or not found.</p>
    </div>
</div>"
        }
        
        Write-Host -Object "Creating the recent usage HTML card."

        # Convert the recent usage entries into an HTML fragment, formatting headers in bold.
        $RecentUsageEntryHTMLTable = $RecentUsageEntryTable | ConvertTo-Html -Fragment
        $RecentUsageEntryHTMLTable = $RecentUsageEntryHTMLTable -replace '<th>', '<th><b>' -replace '</th>', '</b></th>'

        # Build an HTML card displaying the recent battery usage history in a table format.
        $RecentUsageHTMLCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-magnifying-glass-chart'></i>&nbsp;&nbsp;Recent Usage</div>
    </div>
    <div class='card-body'>
        $RecentUsageEntryHTMLTable
    </div>
</div>"

        Write-Host -Object "Assembling the final WYSIWYG Value"

        # Combine all the previously created HTML cards into a final WYSIWYG value.
        $WYSIWYGValue = "<div class='d-wrap'>
    <div class='row'>
        <div class='d-flex flex-wrap'>
            <div class='column d-flex flex-wrap align-content-stretch'>
                $SystemInformationHTMLCard
            </div>
            <div class='column'>
                $InstalledBatteriesHTMLCard
            </div>
        </div>
    </div>
    <div class='row'>
        <div class='d-flex flex-wrap'>
            $BatteryCapacityHistoryHTMLCard
            $BatteryUsageHTMLCard
            $RecentUsageHTMLCard
        </div>
    </div>
</div>"

        try {
            # Attempt to set the WYSIWYG custom field with the assembled HTML content.
            Write-Host "Attempting to set the Custom Field '$WYSIWYGCustomField'."
            Set-NinjaProperty -Name $WYSIWYGCustomField -Value $WYSIWYGValue
            Write-Host "Successfully set the Custom Field '$WYSIWYGCustomField'!"
        }
        catch {
            # If there's an error, print it and set the exit code to 1.
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # The following code block:
    # 1. Prints headings and data in a human-readable format for:
    #    - System Information
    #    - Installed Batteries
    #    - Battery Capacity History
    #    - Battery Usage
    #    - Recent Power Usage
    # 2. Each section is introduced with a heading (e.g., "### System Information ###").
    # 3. Data is formatted using Format-List or Format-Table, converted to a string via Out-String,
    #    trimmed to remove extra whitespace, and then printed using Write-Host.
    Write-Host -Object "`n### System Information ###"
    ($SystemInformation | Format-List | Out-String).Trim() | Write-Host 
    Write-Host -Object "`n### Installed Batteries ###"
    ($Batteries | Format-List | Out-String).Trim() | Write-Host
    Write-Host -Object "`n### Battery Capacity History ###"
    ($BatteryCapacityHistoryTable | Format-Table | Out-String).Trim() | Write-Host
    Write-Host -Object "`n### Battery Usage ###"
    ($BatteryUsageTable | Format-Table | Out-String).Trim() | Write-Host
    Write-Host -Object "`n### Recent Power Usage ###"
    ($RecentUsageEntryTable | Format-Table | Out-String).Trim() | Write-Host

    exit $ExitCode
}
end {
    
    
    
}
