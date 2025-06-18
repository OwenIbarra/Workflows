# Search for specific events in Event Viewer based on the event log they were in, the source of the event, or the specific event IDs used. One of these three options is required for the search.
#Requires -Version 5.1

<#
.SYNOPSIS
    Search for specific events in Event Viewer based on the event log they were in, the source of the event, or the specific event IDs used. One of these three options is required for the search.
.DESCRIPTION
    Search for specific events in Event Viewer based on the event log they were in, the source of the event, or the specific event IDs used. One of these three options is required for the search.
.EXAMPLE
    -EventLogName "Application"
    
    Matching Events Found!

    LogName      : Application
    ProviderName : Microsoft-Windows-Security-SPP
    Id           : 16384
    TimeCreated  : 4/4/2024 10:00:48 AM
    Message      : Successfully scheduled Software Protection service for re-start at 2024-04-04T21:19:48Z. Reason: Rul...

    LogName      : Application
    ProviderName : Microsoft-Windows-Security-SPP
    Id           : 16394
    TimeCreated  : 4/4/2024 10:00:17 AM
    Message      : Offline downlevel migration succeeded.

    LogName      : Application
    ProviderName : Microsoft-Windows-Security-SPP
    Id           : 16384
    TimeCreated  : 4/4/2024 9:59:59 AM
    Message      : Successfully scheduled Software Protection service for re-start at 2024-04-04T21:19:59Z. Reason: Rul...

PARAMETER: -EventLogName "Application"
    Specify the name of the Event Log from which to retrieve events.

PARAMETER: -EventLogSource "Microsoft-Windows-Kernel-General"
    Determines the source of the events to retrieve.

PARAMETER: -EventLogMessage "Alert"
    Filters events by the text contained in the event's message.

PARAMETER: -EventIDs "12, 13, 6008"
    A comma-separated list of event IDs to include in the search.

PARAMETER: -excludeEventIDs "13"
    A comma-separated list of event IDs to exclude from the search.

PARAMETER: -StartDate "12/24/2021"
    Defines the start date and time for the event search. Events logged before this time will not be included in the results.

PARAMETER: -EndDate "12/29/2021"
    Sets the end date and time for the event search. Events logged after this time will not be included.

PARAMETER: -MultilineCustomField "replaceMeWithAcustomFieldName"
    Specify the name of a multiline custom field to optionally store the search results in. Leave blank to not set a multiline field.

PARAMETER: -WysiwygCustomField "replaceMeWithACustomFieldName"
    Specify the name of a WYSIWYG custom field to optionally store the search results in. Leave blank to not set a WYSIWYG field.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$EventLogName,
    [Parameter()]
    [String]$EventLogSource,
    [Parameter()]
    [String]$EventLogMessage,
    [Parameter()]
    [String]$EventIDs,
    [Parameter()]
    [String]$ExcludeEventIDs,
    [Parameter()]
    [datetime]$StartDate,
    [Parameter()]
    [datetime]$EndDate,
    [Parameter()]
    [String]$MultilineCustomField,
    [Parameter()]
    [String]$WysiwygCustomField
)

begin {
    # Set parameters using dynamic script variables.
    if ($env:eventLogName -and $env:eventLogName -notlike "null") { $EventLogName = $env:eventLogName }
    if ($env:eventLogSource -and $env:eventLogSource -notlike "null") { $EventLogSource = $env:eventLogSource }
    if ($env:eventLogMessage -and $env:eventLogMessage -notlike "null") { $EventLogMessage = $env:eventLogMessage }
    if ($env:eventIds -and $env:eventIds -notlike "null") { $EventIDs = $env:eventIds }
    if ($env:excludeEventIds -and $env:excludeEventIds -notlike "null") { $ExcludeEventIDs = $env:excludeEventIds }
    if ($env:eventStart -and $env:eventStart -notlike "null") { $StartDate = $env:eventStart }
    if ($env:eventEnd -and $env:eventEnd -notlike "null") { $EndDate = $env:eventEnd }
    if ($env:multilineCustomFieldName -and $env:multilineCustomFieldName -notlike "null") { $MultilineCustomField = $env:multilineCustomFieldName }
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WysiwygCustomField = $env:wysiwygCustomFieldName }

    # Check if both StartDate and EndDate are provided and if StartDate is earlier than EndDate
    if (($StartDate -and $EndDate) -and $StartDate -gt $EndDate) {
        Write-Host -Object "[Error] Start date cannot be earlier than end date!"
        exit 1
    }

    # Verify that WysiwygField and MultiLineField are not the same, exiting with an error if they are.
    if ($WysiwygCustomField -and $MultilineCustomField -and ($WysiwygCustomField -eq $MultilineCustomField)) {
        Write-Host -Object "[Error] Wysiwyg Field and Multiline Field are the same! Custom fields cannot be the same type."
        Write-Host -Object "https://ninjarmm.zendesk.com/hc/en-us/articles/18601842971789-Custom-Fields-by-Type-and-Functionality"
        exit 1
    }

    # Ensure that at least one of Event ID, Event Log Name, or Event Source is provided for the query
    if (!$EventIDs -and !$EventLogName -and !$EventLogSource) {
        Write-Host -Object "[Error] You must provide either an Event ID, Event Log Name or Event Source."
        exit 1
    }

    # Trimming trailing spaces.
    if ($EventLogName) {
        $EventLogName = $EventLogName.Trim()
    }

    # Retrieve and sort all event log names available on the system
    $EventLogNamesOnSystem = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Sort-Object LogName
    # Check if the provided EventLogName exists in the system's event logs
    if ($EventLogName -and ($EventLogNamesOnSystem).LogName -notcontains $EventLogName) {
        # If not found, print an error message and a list of valid event log names, then exit the script
        Write-Host -Object "[Error] Event Log '$EventLogName' doesn't exist! See the list below for valid event log names."
        Write-Host -Object "### Valid Event Log Names ###"
        $EventLogNamesOnSystem | Select-Object -ExpandProperty LogName | Write-Host
        exit 1 
    }

    $InvalidEventSourceCharacters = "[\\/<>&`"%\|']"
    if ($EventLogSource) {
        if ($EventLogSource -match $InvalidEventSourceCharacters) {
            Write-Host -Object "[Error] Event Log Source '$EventLogSource' contains an invalid character!"
            exit 1
        }

        if ($EventLogSource.Length -gt 255) {
            Write-Host -Object "[Error] Event Log Source '$EventLogSource' is too large to be an event source!"
            exit 1
        }

        # Trims the event log source for trailing spaces
        $EventLogSource = $EventLogSource.Trim()
    }

    # Prepare a list to hold valid event IDs to search for
    $EventIdsToSearch = New-Object System.Collections.Generic.List[int]
    # Process the input event IDs, removing any that are not purely numerical
    if ($EventIDs -and $EventIDs -match ",") {
        # If multiple event IDs are provided and separated by commas, split them
        $EventIDs -split "," | ForEach-Object {
            $EventId = $_.Trim()
            # Validate each event ID to ensure it's numerical
            if ($EventId -match '[a-zA-Z]|\W') {
                # If not, print an error and skip adding this ID to the list
                Write-Host "[Error] Event ID '$EventId' is not a valid event id. Removing it from the search."
                $ExitCode = 1
                return
            }
            # Check size of event id
            if ([long]$EventId -gt 65535 -or [long]$EventId -lt 0) {
                Write-Host "[Error] Event ID '$EventId' is not a valid event id. Event ID's must be less than or equal to 65535 and greater than or equal to 0. Removing it from the search."
                $ExitCode = 1
                return
            }
             
            # Add the validated event ID to the list
            $EventIdsToSearch.Add($EventId)
        }
    }
    elseif ($EventIDs) {
        $EventId = $EventIDs.Trim()
        # Handle a single event ID input
        if ($EventId -match '[a-zA-Z]|\W') {
            Write-Host "[Error] Event ID '$EventId' is not a valid event id. Removing it from the search."
            $ExitCode = 1
        }
        elseif ([long]$EventId -gt 65535 -or [long]$EventId -lt 0) {
            Write-Host "[Error] Event ID '$EventId' is not a valid event id. Event ID's must be less than or equal to 65535 and greater than or equal to 0. Removing it from the search."
            $ExitCode = 1
        }
        else {
            $EventIdsToSearch.Add($EventId)
        }
    }
 
    # Prepare a list to hold event IDs that should be excluded from the search
    $EventsToExclude = New-Object System.Collections.Generic.List[int]
     
    # Similar process for excluded event IDs as regular event IDs
    if ($ExcludeEventIDs -and $ExcludeEventIDs -match ",") {
        $ExcludeEventIDs -split "," | ForEach-Object {
            $ExcludeEventId = $_.Trim()
            if ($ExcludeEventId -match '[a-zA-Z]|\W') {
                Write-Host "[Error] Event ID '$ExcludeEventId' is not a valid event id. Removing it from the exclusions."
                $ExitCode = 1
                return
            }
 
            if ([long]$ExcludeEventId -gt 65535 -or [long]$ExcludeEventId -lt 0) {
                Write-Host "[Error] Event ID '$ExcludeEventId' is not a valid event id. Event ID's must be less than or equal to 65535 and greater than or equal to 0. Removing it from the exclusions."
                $ExitCode = 1
                return
            }
             
            $EventsToExclude.Add($ExcludeEventId)
        }
    }
    elseif ($ExcludeEventIDs) {
        $ExcludeEventId = $ExcludeEventIDs.Trim()
        if ($ExcludeEventId -match '[a-zA-Z]|\W') {
            Write-Host "[Error] Event ID '$ExcludeEventId' is not a valid event id. Removing it from the exclusions."
            $ExitCode = 1
        }
        elseif ([long]$ExcludeEventId -gt 65535 -or [long]$ExcludeEventId -lt 0) {
            Write-Host "[Error] Event ID '$ExcludeEventId' is not a valid event id. Event ID's must be less than or equal to 65535 and greater than or equal to 0. Removing it from the exclusions."
            $ExitCode = 1
        }
        else {
            $EventsToExclude.Add($ExcludeEventId)
        }
    }
 
    # Check if there are any event IDs to exclude and if the list of event IDs to search for is not empty.
    if ($EventsToExclude.Count -gt 0 -and $EventIdsToSearch.Count -gt 0) {
        $EventsToExclude | ForEach-Object {
            # Check if the current event ID from the exclusion list is also in the list of event IDs to search for.
            if ($EventIdsToSearch -contains $_) {
                Write-Warning "Event ID $_ has been specified for both inclusion and exclusion. It will be excluded."
            }
        }
    }
 
    # Check if there's no valid event ID, log name, or log source provided and exit if true
    if ($EventIdsToSearch.Count -eq 0 -and !$EventLogName -and !$EventLogSource) {
        Write-Host "[Error] No valid Event ID given and no Event Log Name or Event Log Source given."
        exit 1
    }

    # Handy function to set a custom field.
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
            [String]$DocumentName
        )

        $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value with $Characters characters is greater than or equal to 200,000 characters.")
        }
    
        # If we're requested to set the field value for a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
    
        # This is a list of valid fields that can be set. If no type is given, it will be assumed that the input doesn't need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
    
        # The field below requires additional information to be set
        $NeedsOptions = "Dropdown"
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
    
        # If an error is received it will have an exception property, the function will exit with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
    
        # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, the given value will be matched with a GUID.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
    
                if (-not $Selection) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown")
                }
    
                $NinjaValue = $Selection
            }
            default {
                # All the other types shouldn't require additional work on the input.
                $NinjaValue = $Value
            }
        }
    
        # We'll need to set the field differently depending on if its a field in a Ninja Document or not.
        if ($DocumentName) {
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
    
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
    # Check if the script is running with elevated (Administrator) privileges
    if (!(Test-IsElevated)) {
        # If not, display an error message and exit with status code 1
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Prepare a list to hold event log names to search for
    $EventLogNamesToSearch = New-Object System.Collections.Generic.List[string]

    # If no event log name was required we'll search all the event
    if (!$EventLogName) {
        $EventLogNamesOnSystem | Where-Object { $_.RecordCount -gt 0 } | Select-Object -ExpandProperty LogName | ForEach-Object {
            $EventLogNamesToSearch.Add($_)
        }
    }
    else {
        $EventLogNamesToSearch.Add($EventLogName)
    }

    # Create XML object.
    [xml]$XML = New-Object System.Xml.XmlDocument

    # Add QueryList element to xml.
    $QueryList = $XML.CreateElement("QueryList")
    $QueryList = $XML.AppendChild($QueryList)

    # Create query element and nest it under QueryList.
    $Query = $XML.CreateElement("Query")
    $Query.SetAttribute("Id", "0")
    $Query = $QueryList.AppendChild($Query)
    

    # Foreach event log to search we're going to create a select element.
    $EventLogNamesToSearch | ForEach-Object {
        # We'll start each loop by selecting the query element to add to.
        $Query = $XML.SelectSingleNode("//Query")

        # The select element starts off with the event log to search.
        $Select = $XML.CreateElement("Select")
        $Select.SetAttribute("Path", "$_")
        
        # Reset the inner text between runnings
        $XMLInnerText = $Null

        # The inner text of each element (<Element1>InnerText</Element1>) will need to be built differently depending on the parameters.
        if ($EventLogSource) {
            $XMLInnerText = "*[System[Provider[@Name='$EventLogSource']]]"
        }
        
        # If we're given a select number of event id's to search we'll filter them here.
        if ($EventIdsToSearch.Count -gt 0) {
            $EventIDSearchText = $Null
            $EventIdsToSearch | ForEach-Object {
                # We may have been given one event id or more than one.
                if ($EventIDSearchText) {
                    $EventIDSearchText = "$EventIDSearchText or EventID=$_"
                }
                else {
                    $EventIDSearchText = "EventID=$_"
                }
            }

            # We'll replace the two ending brackets with our given search text
            if ($XMLInnerText) {
                $XMLInnerText = $XMLInnerText -replace ']]$', " and ($EventIDSearchText)]]"
            }
            else {
                $XMLInnerText = "*[System[($EventIDSearchText)]]"
            }
        }

        # If we're also asked to filter based on the date the event was created we'll create the filter text here.
        if ($StartDate -or $EndDate) {
            $DateFilter = $Null 
            if ($StartDate) {
                $XMLstartDate = Get-Date $StartDate -Format "yyyy-MM-ddTHH:mm:ss"
                # PowerShell will convert the < or > symbol for us when we go to save to the xml.
                $DateFilter = "@SystemTime>='$XMLstartDate'"
            }

            # We may or may not have been given a start date.
            if ($EndDate -and $DateFilter) {
                $XMLendDate = Get-Date $EndDate -Format "yyyy-MM-ddTHH:mm:ss"
                $DateFilter = "$DateFilter and @SystemTime<='$XMLendDate'"
            }
            elseif ($EndDate) {
                $XMLendDate = Get-Date $EndDate -Format "yyyy-MM-ddTHH:mm:ss"
                $DateFilter = "@SystemTime<='$XMLendDate'"
            }

            # Replace the last two closing brackets and add our filter text.
            if($XMLInnerText){
                $XMLInnerText = $XMLInnerText -replace ']]$', " and TimeCreated[$DateFilter]]]"
            }else{
                $XMLInnerText = "*[System[TimeCreated[$DateFilter]]]"
            }
        }

        # If no filters were given (other than the event log name) we'll need to select everything in that log
        if(!$XMLInnerText){
            $XMLInnerText = "*"
        }

        # Save our filter text to the select statement
        $Select.InnerText = $XMLInnerText

        # Append our select statement to our xml file
        $Query.AppendChild($Select) | Out-Null
    }

    # Search for matching events using the XML filter
    $MatchingEvents = Get-WinEvent -FilterXml $XML -ErrorAction SilentlyContinue

    # Exclude events based on the excluded event IDs if any are specified
    if ($EventsToExclude.Count -gt 0) {
        $MatchingEvents = $MatchingEvents | Where-Object { $EventsToExclude -notcontains $_.ID }
    }

    # Exclude events that do not match the keywords you specified.
    if ($EventLogMessage) {
        $MatchingEvents = $MatchingEvents | Where-Object { $_.Message -like "*$EventLogMessage*" }
    }

    # If the event log message is larger than 100 characters trim it and add ...
    if ($MatchingEvents) {
        $MatchingEvents = $MatchingEvents | Select-Object LevelDisplayName, LogName, ProviderName, Id, TimeCreated, @{
            Name       = 'Message'
            Expression = {
                $Characters = $_.Message | Measure-Object -Character | Select-Object -ExpandProperty Characters
                if ($Characters -gt 100) {
                    "$(($_.Message).SubString(0,100))(...)"
                }
                else {
                    $_.Message
                }
            }
        }

        # Sort the object by newest event to oldest
        $MatchingEvents = $MatchingEvents | Sort-Object TimeCreated -Descending
    }

    # Set a Wysiwyg custom field if any matching events are found and it was requested.
    if ($WysiwygCustomField -and $MatchingEvents) {
        try {
            Write-Host "Attempting to set Custom Field '$WysiwygCustomField'."

            # Prepare the custom field output.
            $CustomFieldValue = New-Object System.Collections.Generic.List[string]

            # Convert the matching events into an html report.
            $htmlTable = $MatchingEvents | Select-Object -Property LevelDisplayName, LogName, ProviderName, Id, TimeCreated, Message | ConvertTo-Html -Fragment
            
            # Set color coding
            $htmlTable = $htmlTable -replace "<tr><td>Verbose</td>", "<tr class=`"other`"><td>Verbose</td>"
            $htmlTable = $htmlTable -replace "<tr><td>Warning</td>", "<tr class=`"warning`"><td>Warning</td>"
            $htmlTable = $htmlTable -replace "<tr><td>Error</td>", "<tr class=`"danger`"><td>Error</td>"
            $htmlTable = $htmlTable -replace "<tr><td>Critical Error</td>", "<tr class=`"danger`"><td>Critical Error</td>"

            # Remove Level Display Name
            $LevelDisplayNames = $MatchingEvents | Select-Object -Property LevelDisplayName -Unique
            $LevelDisplayNames | ForEach-Object {
                $htmlTable = $htmlTable -replace "<td>$([Regex]::Escape($_.LevelDisplayName))</td>"
            }
            $htmlTable = $htmlTable -replace "<th>LevelDisplayName</th>"

            # Add the newly created html into the custom field output.
            $CustomFieldValue.Add($htmlTable)

            # Check that the output complies with the hard character limits.
            $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
            if ($Characters -ge 199500) {
                Write-Warning "200,000 Character Limit has been reached! Trimming output until the character limit is satisified..."
                
                # If it doesn't comply with the limits we'll need to recreate it with some adjustments.
                $i = 0
                do {
                    # Recreate the custom field output starting with a warning that we truncated the output.
                    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
                    $CustomFieldValue.Add("<h1>This info has been truncated to accommodate the 200,000 character limit.</h1>")

                    # The custom field information is sorted from newest to oldest. We'll remove the oldest first by flipping the array upside down.
                    [array]::Reverse($htmlTable)
                    # If the next entry is a row we'll delete it.
                    if ($htmlTable[$i] -match '<tr><td>' -or $htmlTable[$i] -match '<tr class=') {
                        $htmlTable[$i] = $null
                    }
                    $i++
                    # We'll flip the array back to right side up.
                    [array]::Reverse($htmlTable)

                    # Add it back to the output.
                    $CustomFieldValue.Add($htmlTable)

                    # Check that we now comply with the character limit. If not restart the do loop.
                    $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
                }while ($Characters -ge 199500)
            }

            # Set the custom field.
            Set-NinjaProperty -Name $WysiwygCustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$WysiwygCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # Set a multiline custom field if any matching events are found and it was requested.
    if ($MultilineCustomField -and $MatchingEvents) {
        try {
            Write-Host "Attempting to set Custom Field '$MultilineCustomField'."
            $CustomFieldValue = New-Object System.Collections.Generic.List[string]

            # We don't want to edit the matching Events array if we have to truncate later so we'll create a duplicate here.
            $CustomFieldList = $MatchingEvents | Select-Object -Property LogName, ProviderName, Id, TimeCreated, Message

            # Format the matching items into a nice list with the relevant properties.
            $CustomFieldValue.Add(($CustomFieldList | Format-List -Property LogName, ProviderName, Id, TimeCreated, Message | Out-String))
            
            # Check that the output complies with the hard character limits.
            $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
            if ($Characters -ge 9500) {
                Write-Warning "10,000 Character Limit has been reached! Trimming output until the character limit is satisified..."
                
                # If it doesn't comply with the limits we'll need to recreate it with some adjustments.
                $i = 0
                do {
                    # Recreate the custom field output starting with a warning that we truncated the output.
                    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
                    $CustomFieldValue.Add("This info has been truncated to accommodate the 10,000 character limit.")
                    
                    # The custom field information is sorted from newest to oldest. We'll remove the oldest events first by flipping the array upside down.
                    [array]::Reverse($CustomFieldList)

                    # Remove the next item which in this case will be the oldest item.
                    $CustomFieldList[$i] = $null
                    $i++

                    # We'll flip the array back to right side up.
                    [array]::Reverse($CustomFieldList)

                    # Add it back to the output.
                    $CustomFieldValue.Add(($CustomFieldList | Format-List -Property LogName, ProviderName, Id, TimeCreated, Message | Out-String))

                    # Check that we now comply with the character limit. If not restart the do loop.
                    $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
                }while ($Characters -ge 9500)
            }

            Set-NinjaProperty -Name $MultilineCustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$MultilineCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # If any matching events were found output them into the activity log.
    if ($MatchingEvents) {
        Write-Host "Matching Events Found!"
        $MatchingEvents | Format-List LogName, ProviderName, Id, TimeCreated, Message | Out-String | Write-Host
    }
    else {
        Write-Host "No matching events found!"
    }

    exit $ExitCode
}
end {
    
    
    
}
