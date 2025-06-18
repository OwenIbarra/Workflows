# Verify that running processes are signed and output unsigned.
#Requires -Version 5.1

<#
.SYNOPSIS
    Verify that running processes are signed and output unsigned.
.DESCRIPTION
    Verify that running processes are signed and output unsigned.
    It will exclude processes based on the process name, path, or product name.
    The script will output the unsigned processes to the console and save the results to a Multi-Line custom field and a WYSIWYG custom field if specified.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    Unsigned Processes Found: 2

    Name        : explorer
    Description : Windows Explorer
    Path        : C:\Windows\explorer.exe
    Id          : 1234
    Signed      : NotSigned

    Name        : notepad
    Description : Notepad
    Path        : C:\Windows\notepad.exe
    Id          : 5678
    Signed      : NotSigned

PARAMETER: -ExcludeProcess "explorer.exe"
    Exclude the process explorer.exe from the results.
.EXAMPLE
    -ExcludeProcess "notepad"
    ## EXAMPLE OUTPUT WITH ExcludeProcess ##
    Unsigned Processes Found: 1

    Name        : explorer
    Description : Windows Explorer
    Path        : C:\Windows\explorer.exe
    Id          : 1234
    Signed      : NotSigned

PARAMETER: -ExcludeProcessFromCustomField "ReplaceMeWithAnyTextCustomField"
    Exclude the processes from the custom field specified.
.EXAMPLE
    -ExcludeProcessFromCustomField "ReplaceMeWithAnyTextCustomField"
    ## EXAMPLE OUTPUT WITH ExcludeProcessFromCustomField ##
    Unsigned Processes Found: 2

    Name        : explorer
    Description : Windows Explorer
    Path        : C:\Windows\explorer.exe
    Id          : 1234
    Signed      : NotSigned

    Name        : notepad
    Description : Notepad
    Path        : C:\Windows\notepad.exe
    Id          : 5678
    Signed      : NotSigned

PARAMETER: -SaveResultsToMultilineCustomField "ReplaceMeWithAnyMultilineCustomField"
    Save the results to a Multi-Line custom field specified.
.EXAMPLE
    -SaveResultsToMultilineCustomField "ReplaceMeWithAnyMultilineCustomField"
    ## EXAMPLE OUTPUT WITH ExcludeProcessFromCustomField ##
    Unsigned Processes Found: 2

    Name        : explorer
    Description : Windows Explorer
    Path        : C:\Windows\explorer.exe
    Id          : 1234
    Signed      : NotSigned

    Name        : notepad
    Description : Notepad
    Path        : C:\Windows\notepad.exe
    Id          : 5678
    Signed      : NotSigned

    [Info] Attempting to update Multiline Custom Field(ReplaceMeWithAnyMultilineCustomField)
    [Info] Updated Multiline Custom Field(ReplaceMeWithAnyMultilineCustomField)


PARAMETER: -SaveResultsToWysiwygCustomField "ReplaceMeWithAnyMultilineCustomField"
    Save the results to a WYSIWYG custom field specified.
.EXAMPLE
    -SaveResultsToWysiwygCustomField "ReplaceMeWithAnyWysiwygCustomField"
    ## EXAMPLE OUTPUT WITH ExcludeProcessFromCustomField ##
    Unsigned Processes Found: 2

    Name        : explorer
    Description : Windows Explorer
    Path        : C:\Windows\explorer.exe
    Id          : 1234
    Signed      : NotSigned

    Name        : notepad
    Description : Notepad
    Path        : C:\Windows\notepad.exe
    Id          : 5678
    Signed      : NotSigned

    [Info] Attempting to update Wysiwyg Custom Field(ReplaceMeWithAnyWysiwygCustomField)
    [Info] Updated Wysiwyg Custom Field(ReplaceMeWithAnyWysiwygCustomField)

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [String[]]$ExcludeProcess,
    [String]$ExcludeProcessFromCustomField,
    [String]$SaveResultsToMultilineCustomField,
    [String]$SaveResultsToWysiwygCustomField
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Get-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter()]
            [String]$DocumentName
        )
    
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            throw "PowerShell 3.0 or higher is required to retrieve data from custom fields. https://ninjarmm.zendesk.com/hc/en-us/articles/4405408656013"
        }
    
        # If we're requested to get the field value from a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
    
        # These two types require more information to parse.
        $NeedsOptions = "DropDown", "MultiSelect"
    
        # Grabbing document values requires a slightly different command.
        if ($DocumentName) {
            # Secure fields are only readable when they're a device custom field
            if ($Type -Like "Secure") { throw "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
    
            # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
            Write-Host "Retrieving value from Ninja Document..."
            $NinjaPropertyValue = Ninja-Property-Docs-Get -AttributeName $Name @DocumentationParams 2>&1
    
            # Certain fields require more information to parse.
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            # We'll redirect error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
            $NinjaPropertyValue = Ninja-Property-Get -Name $Name 2>&1
    
            # Certain fields require more information to parse.
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
    
        # If we received some sort of error it should have an exception property and we'll exit the function with that error information.
        if ($NinjaPropertyValue.Exception) { throw $NinjaPropertyValue }
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
    
        # This switch will compare the type given with the quoted string. If it matches, it'll parse it further; otherwise, the default option will be selected.
        switch ($Type) {
            "Attachment" {
                # Attachments come in a JSON format this will convert it into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Checkbox" {
                # Checkbox's come in as a string representing an integer. We'll need to cast that string into an integer and then convert it to a more traditional boolean.
                [System.Convert]::ToBoolean([int]$NinjaPropertyValue)
            }
            "Date or Date Time" {
                # In Ninja Date and Date/Time fields are in Unix Epoch time in the UTC timezone the below should convert it into local time as a date time object.
                $UnixTimeStamp = $NinjaPropertyValue
                $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds($UnixTimeStamp)
                $TimeZone = [TimeZoneInfo]::Local
                [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
            }
            "Decimal" {
                # In ninja decimals are strings that represent a decimal this will cast it into a double data type.
                [double]$NinjaPropertyValue
            }
            "Device Dropdown" {
                # Device Drop-Downs Fields come in a JSON format this will convert it into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Device MultiSelect" {
                # Device Multi-Select Fields come in a JSON format this will convert it into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Dropdown" {
                # Drop-Down custom fields come in as a comma-separated list of GUIDs; we'll compare these with all the options and return just the option values selected instead of a GUID.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Options | Where-Object { $_.GUID -eq $NinjaPropertyValue } | Select-Object -ExpandProperty Name
            }
            "Integer" {
                # Cast's the Ninja provided string into an integer.
                [int]$NinjaPropertyValue
            }
            "MultiSelect" {
                # Multi-Select custom fields come in as a comma-separated list of GUID's we'll compare these with all the options and return just the option values selected instead of a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = ($NinjaPropertyValue -split ',').trim()
    
                foreach ($Item in $Selection) {
                    $Options | Where-Object { $_.GUID -eq $Item } | Select-Object -ExpandProperty Name
                }
            }
            "Organization Dropdown" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location Dropdown" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location MultiSelect" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization MultiSelect" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Time" {
                # Time fields are given as a number of seconds starting from midnight. This will convert it into a date time object.
                $Seconds = $NinjaPropertyValue
                $UTC = ([TimeSpan]::FromSeconds($Seconds)).ToString("hh\:mm\:ss")
                $TimeZone = [TimeZoneInfo]::Local
                $ConvertedTime = [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
    
                Get-Date $ConvertedTime -DisplayHint Time
            }
            default {
                # If no type was given or not one that matches the above types just output what we retrieved.
                $NinjaPropertyValue
            }
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
            [String]$DocumentName
        )
    
        $Characters = $Value | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 10000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than 10,000 characters.")
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
                # Ninjarmm-cli expects the  Date-Time to be in Unix Epoch time so we'll convert it here.
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

    function Set-WysiwygCustomField {
        param (
            [string]$Name,
            [Parameter(ValueFromPipeline = $True)]
            [string]$Value
        )
        end {

            # Set the Custom Field
            # If the value is greater than 10,000 characters, use the Ninja-Property-Set-Piped function
            # Otherwise, use the Ninja-Property-Set function
            $CustomField = $Value | Ninja-Property-Set-Piped -Name $Name 2>&1

            # Check for errors
            if ($CustomField -or $CustomField.Exception) {
                # If the Custom Field was not found, throw an error
                if ($CustomField -like "Unable to find the specified field." -or $CustomField.Exception -like "Unable to find the specified field.") {
                    throw "The Custom field ($Name) was not found"
                }
                # If the Custom Field is read-only, throw an error
                if ($CustomField -like "Unable to update read-only attribute" -or $CustomField.Exception -like "Unable to update read-only attribute") {
                    throw "The Custom field ($Name) is read-only"
                }
                # Catch all other errors and throw the error
                throw $CustomField
            }
        }
    }

    # Predefined values for Success, Danger, and Other
    $ConvertToWysiwygHtmlSuccess = @("Signed", "Valid")
    $ConvertToWysiwygHtmlDanger = @("SignedAndNotTrusted", "NotSigned", "NotTrusted", "HashMismatch")
    $ConvertToWysiwygHtmlOther = @("UnknownError", "Incompatible")
    # Function to convert the output to a WYSIWYG HTML format
    function ConvertTo-WysiwygHtml {
        param(
            [string]$Title,
            [PSObject[]]$Value,
            [string[]]$Success = $ConvertToWysiwygHtmlSuccess,
            [string[]]$Danger = $ConvertToWysiwygHtmlDanger,
            [string[]]$Other = $ConvertToWysiwygHtmlOther
        )
        begin {
            $htmlReport = New-Object System.Collections.Generic.List[String]
            # If used add the Title to the report
            if ($Title) {
                $htmlReport.Add("<h1>$Title</h1>")
            }
        }
        process {
            # Convert the value to HTML
            $htmlTable = $Value | ConvertTo-Html -Fragment
            # Set the class for each row based on the Success, Danger, and Other values
            if ($Success) {
                # For each Success value, find the row in the table and add a class of 'success'
                $Success | ForEach-Object {
                    $Status = $_
                    # Split the table into lines and find the lines that contain the Status
                    $htmlTable -split "`r`n" | Where-Object {
                        # Select only lines that have <tr><td>*>$($Status)<*
                        $_ -like "<tr><td>*>$($Status)<*"
                    } | ForEach-Object {
                        # Escape the line for regex
                        $LineEscaped = [regex]::Escape($_)
                        if ($_ -like "*$Status*") {
                            # Replace the line with the line and add a class of 'success'
                            $htmlTable = $htmlTable -replace $LineEscaped, $($_ -replace "<tr>", "<tr class='success'>")
                        }
                    }
                }
            }
            if ($Danger) {
                # For each Danger value, find the row in the table and add a class of 'danger'
                $Danger | ForEach-Object {
                    $Status = $_
                    # Split the table into lines and find the lines that contain the Status
                    $htmlTable -split "`r`n" | Where-Object {
                        # Select only lines that have <tr><td>*>$($Status)<*
                        $_ -like "<tr><td>*>$($Status)<*"
                    } | ForEach-Object {
                        # Escape the line for regex
                        $LineEscaped = [regex]::Escape($_)
                        if ($_ -like "*$Status*") {
                            # Replace the line with the line and add a class of 'danger'
                            $htmlTable = $htmlTable -replace $LineEscaped, $($_ -replace "<tr>", "<tr class='danger'>")
                        }
                    }
                }
            }
            if ($Other) {
                # For each Other value, find the row in the table and add a class of 'other'
                $Other | ForEach-Object {
                    $Status = $_
                    # Split the table into lines and find the lines that contain the Status
                    $htmlTable -split "`r`n" | Where-Object {
                        # Select only lines that have <tr><td>*>$($Status)<*
                        $_ -like "<tr><td>*>$($Status)<*"
                    } | ForEach-Object {
                        # Escape the line for regex
                        $LineEscaped = [regex]::Escape($_)
                        if ($_ -like "*$Status*") {
                            # Replace the line with the line and add a class of 'other'
                            $htmlTable = $htmlTable -replace $LineEscaped, $($_ -replace "<tr>", "<tr class='other'>")
                        }
                    }
                }
            }
            # Add the Table to the report
            $htmlTable | ForEach-Object { $htmlReport.Add($_) }
        }
        end {
            # Return the HTML report
            $htmlReport | Out-String
        }
    }

    # Update the script variables with the Script Variables if they are not null
    if ($env:excludeProcess -and $env:excludeProcess -notlike "null") {
        $ExcludeProcess = $env:excludeProcess
    }
    if ($env:excludeProcessFromCustomField -and $env:excludeProcessFromCustomField -notlike "null") {
        $ExcludeProcessFromCustomField = $env:excludeProcessFromCustomField
    }
    if ($env:saveResultsToMultilineCustomField -and $env:saveResultsToMultilineCustomField -notlike "null") {
        $SaveResultsToMultilineCustomField = $env:saveResultsToMultilineCustomField
    }
    if ($env:saveResultsToWysiwygCustomField -and $env:saveResultsToWysiwygCustomField -notlike "null") {
        $SaveResultsToWysiwygCustomField = $env:saveResultsToWysiwygCustomField
    }

    # If ExcludeProcess is a comma-separated list, split it into an array
    if ($ExcludeProcess -like '*,*') {
        $ExcludeProcess = $ExcludeProcess -split ',' | ForEach-Object {
            if ($_ -like '*,*') {
                $_ -split ',' | ForEach-Object { "$_".Trim() }
            }
            else { "$_".Trim() }
        }
    }
    # If ExcludeProcessFromCustomField is not null, get a list of processes to exclude from the Custom Field
    if ($ExcludeProcessFromCustomField -and $ExcludeProcessFromCustomField -notlike "null") {
        try {
            # Get the processes to exclude from the Custom Field
            $TempString = $(Get-NinjaProperty -Name $ExcludeProcessFromCustomField)
            # If the Custom Field is empty, throw an error
            if ([string]::IsNullOrWhiteSpace($TempString)) {
                throw "Empty"
            }
            # If the Custom Field is a comma-separated list, split it into an array
            $ExcludeProcess = $TempString -split ',' | ForEach-Object { "$_".Trim() }
        }
        catch {
            # If the Custom Field is empty, output a warning
            if ($_.Exception.Message -like "Empty") {
                Write-Host "[Warn] The Custom Field($ExcludeProcessFromCustomField) is empty"
            }
            else {
                # If the Custom Field is Like empty, output an error
                Write-Host "[Warn] Failed to get processes to exclude from Custom Field($ExcludeProcessFromCustomField)"
            }
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Get processes and if excluding, look at Name, Path/FileName, and ProductName
    $Processes = $(
        if ($ExcludeProcess) {
            # Output excluded processes
            Write-Host "Excluding Processes:"
            $ExcludeProcess | Out-String | Write-Host
            # Get processes and exclude based on Name, Path/FileName, and ProductName
            Get-Process | Where-Object {
                $(
                    $_.Name -notin $ExcludeProcess -and
                    $(
                        if ($_.Path) {
                            Split-Path $_.Path -Leaf
                        }
                        else { $_.FileName }
                    ) -notin $ExcludeProcess -and
                    $_.ProductName -notin $ExcludeProcess
                )
            }
        }
        else {
            # Get all processes if no exclusion is specified
            Get-Process
        }
    )

    # Reduce list to just the paths and get signed status
    $ProcessesWithSigned = $Processes | Sort-Object -Unique -Property Path | ForEach-Object {
        if ($_.Path) {
            # Get the signer certificate
            $Signature = Get-AuthenticodeSignature -FilePath $_.Path

            # Check if the signer certificate is trusted
            $Status = if ($Signature.Status -eq "Valid") {
                "Signed"
            }
            else {
                $Signature.Status
            }

            # Output the process name, description, path, id, and signed status
            [PSCustomObject]@{
                Name        = $_.Name
                Description = $_.Description
                Path        = $_.Path
                Id          = $_.Id
                Signed      = $Status
            }
            $Status = $null
        }
    }

    # Get unsigned processes
    $Unsigned = $ProcessesWithSigned | Where-Object { $_.Signed -notlike "Signed" }
    if ($Unsigned -and $Unsigned.Count) {
        # Output number of processes
        Write-Host "Unsigned Processes Found: $($Unsigned.Count)"
    }
    elseif ($Unsigned) {
        # Handle edge case where $Unsigned isn't an array of items, but is an object alone
        Write-Host "Unsigned Processes Found: 1"
    }
    else {
        # If $Unsigned doesn't have a count and isn't a object, assume there are 0 unsigned processes found
        Write-Host "Unsigned Processes Found: 0"
    }

    # Output unsigned processes for Activity Feed
    $Unsigned | Out-String | Write-Host

    $HasErrors = $false
    # Save results to a Multi-Line custom field
    if ($SaveResultsToMultilineCustomField -and $SaveResultsToMultilineCustomField -notlike "null") {
        try {
            $Unsigned | Out-String | Set-NinjaProperty -Name $SaveResultsToMultilineCustomField
            Write-Host "[Info] Updated Multiline Custom Field($SaveResultsToMultilineCustomField)"
        }
        catch {
            if ($_.Exception.Message -like "*Unable to find the specified field*") {
                Write-Host "[Error] Unable to find and save to the Custom Field ($SaveResultsToMultilineCustomField)"
            }
            else {
                Write-Host "[Error] ninjarmm-cli returned error: $($_.Exception.Message)"
            }
            $HasErrors = $true
        }
    }
    else {
        Write-Host "[Info] Not updating Multiline Custom Field($SaveResultsToWysiwygCustomField) due to not being specified or inaccessible."
    }

    # Save results to a WYSIWYG custom field
    if ($SaveResultsToWysiwygCustomField -and $SaveResultsToWysiwygCustomField -notlike "null") {
        try {
            ConvertTo-WysiwygHtml -Value $Unsigned | Set-WysiwygCustomField -Name $SaveResultsToWysiwygCustomField
            Write-Host "[Info] Updated Wysiwyg Custom Field($SaveResultsToWysiwygCustomField)"
        }
        catch {
            if ($_.Exception.Message -like "*Unable to find the specified field*") {
                Write-Host "[Error] Unable to find and save to the Custom Field ($SaveResultsToWysiwygCustomField)"
            }
            else {
                Write-Host "[Error] ninjarmm-cli returned error: $($_.Exception.Message)"
            }
            $HasErrors = $true
        }
    }
    else {
        Write-Host "[Info] Not updating Wysiwyg Custom Field($SaveResultsToWysiwygCustomField) due to not being specified or inaccessible."
    }
    if ($HasErrors) {
        exit 1
    }
}
end {
    
    
    
}
