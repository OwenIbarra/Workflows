# Alert on new scheduled tasks created in the last X hours.
#Requires -Version 5.1

<#
.SYNOPSIS
    Alert on new scheduled tasks created in the last X hours.

.DESCRIPTION
    This script will query the Windows Event Log for new scheduled tasks created in the last X hours. It will save the results to a multiline custom field and/or a WYSIWYG custom field.
    This does require the Microsoft-Windows-TaskScheduler/Operational event log to be enabled first before results can be retrieved.
    If enabled the default maximum log size is 10MB and the default retention method is Overwrite oldest events as needed.

.PARAMETER Hours
    The number of hours to look back for new scheduled tasks.

.PARAMETER MultilineCustomField
    The name of the multiline custom field to save the results to.

.PARAMETER WYSIWYGCustomField
    The name of the WYSIWYG custom field to save the results to.

.PARAMETER EnableEventLog
    Enable the Microsoft-Windows-TaskScheduler/Operational event log if it is not already enabled.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$CreatedInLastXHours,

    [Parameter()]
    [string]$MultilineCustomField,

    [Parameter()]
    [string]$WYSIWYGCustomField,

    [Parameter()]
    [switch]$EnableEventLog
)
begin {

    # Check which Script Variables are used
    if ($env:createdInLastXHours -and $env:createdInLastXHours -notlike "null") {
        if ($env:createdInLastXHours -match '\D') {
            Write-Host "[Error] CreatedInLastXHours must be an integer."
            exit 1
        }
        [int]$CreatedInLastXHours = $env:createdInLastXHours
    }
    if ($env:multilineCustomField -and $env:multilineCustomField -notlike "null") {
        $MultilineCustomField = $env:multilineCustomField
    }
    if ($env:WYSIWYGCustomField -and $env:wysiwygCustomField -notlike "null") {
        $WYSIWYGCustomField = $env:wysiwygCustomField
    }
    if ($env:enableEventLog -and $env:enableEventLog -like "true") {
        $EnableEventLog = $true
    }

    # Check if CreatedInLastXHours is not 0 nor negative
    if ($CreatedInLastXHours -le 0) {
        Write-Host "[Error] CreatedInLastXHours must be greater than 0."
        exit 1
    }

    # Define the event log name, selected date, and event ID to query
    $EventLogName = 'Microsoft-Windows-TaskScheduler/Operational'
    $SelectedDate = $($(Get-Date).AddHours(0 - $CreatedInLastXHours))
    $EventID = 106

    # Check if the event log is enabled
    try {
        $EventLogEnabled = Get-WinEvent -ListLog $EventLogName -ErrorAction Stop
    }
    catch {
        Write-Host "[Error] Failed to retrieve event log '$EventLogName'."
        Write-Host $_.Exception.Message
        exit 1
    }

    # If the event log is not found, exit the script
    if ($EventLogEnabled.IsEnabled) {
        Write-Host "[Info] Event log '$EventLogName' is enabled."
    }
    else {
        # Enable the event log if the switch is provided
        if ($EnableEventLog) {
            Write-Host "[Info] Enabling event log '$EventLogName'."
            try {
                $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $EventLogName
                $log.IsEnabled = $true
                $log.SaveChanges()
            }
            catch {
                Write-Host "[Error] Failed to enable event log '$EventLogName'."
                exit 1
            }
        }
        else {
            Write-Host "[Error] Event log '$EventLogName' is not enabled."
            exit 1
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

    $ExitCode = 0
}

process {
    # Get the scheduled tasks from the event log
    try {
        $EventLogEntries = Get-WinEvent -FilterHashtable @{
            LogName = $EventLogName
            ID      = $EventID
        } -ErrorAction Stop | Where-Object { $_.TimeCreated -ge $SelectedDate }
    }
    catch {
        Write-Host "[Error] Failed to retrieve event log '$EventLogName'."
        Write-Host $_.Exception.Message
        exit 1
    }

    # If there are no scheduled tasks, exit the script
    if (-not $EventLogEntries) {
        Write-Host "[Info] No scheduled tasks created in the last $CreatedInLastXHours hours."
        exit 0
    }

    # Get the details of the scheduled tasks
    $ScheduledTasks = $EventLogEntries | ForEach-Object {
        $_Event = $_

        if ($_Event) {
            # Get the task path and name from the event properties
            $TaskPath = $_Event | Select-Object -ExpandProperty Properties | Select-Object -ExpandProperty Value -First 1 # First property value is the task path
            # Get the parent path of the task
            $ParentPath = ("$TaskPath" -split '\\' | Select-Object -SkipLast 1) -join '\'
            # If the task path is empty, set the parent path to the root
            if ($ParentPath -eq "") { $ParentPath = "\" }
            # Get the task name from the task path
            $TaskName = "$TaskPath" -split '\\' | Select-Object -Last 1
            if ($TaskName -like "" -or $ParentPath -like "") { 
                Write-Host "[Error] Failed to get task path or name from event:"
                Write-Host $TaskPath
            }
            else {
                # Get the scheduled task details
                $Task = Get-ScheduledTask -TaskPath "$ParentPath" -TaskName "$TaskName" -ErrorAction SilentlyContinue
                # Get the last run time of the scheduled task
                $LastRunTime = try {
                    Get-ScheduledTaskInfo -TaskPath "$ParentPath" -TaskName "$TaskName" -ErrorAction Stop | Select-Object -ExpandProperty LastRunTime 
                }
                catch { [datetime]::MinValue }

                # Return the scheduled task details
                [PSCustomObject]@{
                    TimeCreated      = $_Event.TimeCreated
                    TaskName         = $TaskName
                    TaskCreationDate = $(if ($Task.Date) { $Task.Date } else { $_Event.TimeCreated })
                    TaskPath         = $TaskPath | Select-Object -First 1
                    TaskLastRunTime  = $(if ($LastRunTime.Year -lt 2000) { "Never" } else { $LastRunTime }) # If the last run time is before 2000, it has never run
                }
            }
        }
    }

    # Sort the scheduled tasks by TimeCreated in descending order
    $ScheduledTasks = $ScheduledTasks | Sort-Object -Property TimeCreated -Descending

    # Output the scheduled tasks to the multiline custom field
    if ($MultilineCustomField) {
        try {
            Write-Host "[Info] Attempting to set Custom Field '$MultilineCustomField'."
            $ScheduledTasks | Format-List | Out-String -Width 4000 | Set-NinjaProperty -Name $MultilineCustomField -Type "MultiLine" -Piped
            Write-Host "[Info] Successfully set Custom Field '$MultilineCustomField'!"
        }
        catch {
            Write-Host "[Error] Failed to set multiline custom field."
            $ExitCode = 1
        }
    }

    # Output the scheduled tasks to the WYSIWYG custom field
    if ($WYSIWYGCustomField) {
        try {
            Write-Host "[Info] Attempting to set Custom Field '$WYSIWYGCustomField'."
            Set-NinjaProperty -Name $WYSIWYGCustomField -Value $($ScheduledTasks | ConvertTo-Html -Fragment) -Type "WYSIWYG" -Piped
            Write-Host "[Info] Successfully set Custom Field '$WYSIWYGCustomField'!"
        }
        catch {
            Write-Host "[Error] Failed to set WYSIWYG custom field."
            $ExitCode = 1
        }
    }

    # Output the scheduled tasks to the Activity Feed
    $ScheduledTasks | Format-List | Out-String -Width 4000 | Write-Host

    exit $ExitCode
}

end {
    
    
    
}
