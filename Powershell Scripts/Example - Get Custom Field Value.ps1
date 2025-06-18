# This is an example script for retrieving a custom field value. Specify a type to have the custom field value converted to a more PowerShell native type.
#Requires -Version 4

<#
.SYNOPSIS
    This is an example script for retrieving a custom field value. Specify a type to have the custom field value converted to a more PowerShell native type.
.DESCRIPTION
    This is an example script for retrieving a custom field value. Specify a type to have the custom field value converted to a more PowerShell native type.
.EXAMPLE
    -CustomFieldName "date"

    Retrieving value from Custom Field date.
    1697094000
.EXAMPLE
    -CustomFieldName "date" -CustomFieldType "Date"

    Retrieving value from Custom Field date.

    Thursday, October 12, 2023 12:00:00 AM

PARAMETER: -CustomFieldName "NameOfAcustomFieldToOutputIntoActivityLog"
    The name of a custom field that has a value you would like to retrieve.

PARAMETER: -CustomFieldType "ReplaceMeWithFieldType"
    To convert the value into a more PowerShell-native type, simply specify the type. This is optional; leave blank to output whatever was retrieved from ninjarmm-cli.
    Valid options are: "Text", "Attachment", "Checkbox", "Date", "Date And Time", "Decimal", "Device Dropdown", "Device MultiSelect", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Organization Dropdown", "Organization Location Dropdown", "Organization Location MultiSelect", "OrganizationMultiSelect", "Phone", "Secure", "Time", "URL"

PARAMETER: -NinjaDocumentName "Replace Me With A Ninja Document Name"
    Name of a Ninja Document you would like to retrieve these field values from. Leave blank to retrieve values from device custom fields.

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2012 R2
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomFieldName,
    [Parameter()]
    [String]$CustomFieldType,
    [Parameter()]
    [String]$NinjaDocumentName
)

begin {
    # Grab parameters from dynamic script variables.
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomFieldName = $env:customFieldName }
    if ($env:customFieldType -and $env:customFieldType -notlike "null") { $CustomFieldType = $env:customFieldType }
    if ($env:ninjaDocumentName -and $env:ninjaDocumentName -notlike "null") { $NinjaDocumentName = $env:ninjaDocumentName }

    # A custom field name is required.
    if (-not $CustomFieldName) {
        Write-Error "No custom field was specified!"
        exit 1
    }

    # If the custom field type specified is a date or date and time, change it to "Date or Date Time" to be used by the function.
    if ($CustomFieldType -eq "Date" -or $CustomFieldType -eq "Date And Time") {
        $CustomFieldType = "Date or Date Time"
    }

    # Local Admin rights are required to read or write custom fields.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # This function is to make it easier to parse Ninja Custom Fields.
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

        # If we're requested to get the field value from a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }

        # These two types require more information to parse.
        $NeedsOptions = "DropDown","MultiSelect"

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
                # In Ninja Date and Date/Time fields are in Unix Epoch time in the UTC timezone the below should convert it into local time as a datetime object.
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
                # Time fields are given as a number of seconds starting from midnight. This will convert it into a datetime object.
                $Seconds = $NinjaPropertyValue
                $UTC = ([timespan]::fromseconds($Seconds)).ToString("hh\:mm\:ss")
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
}
process {
    # If this script doesn't have Local Admin rights, error out.
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # These are the two default mandatory parameters. We'll 'splat' them later.
    $NinjaPropertyParams = @{
        Name        = $CustomFieldName
        ErrorAction = "Stop"
    }

    # If either of the optional options were given, add it to the parameter list to be 'splatted' later.
    if ($NinjaDocumentName) { $NinjaPropertyParams["DocumentName"] = $NinjaDocumentName }
    if ($CustomFieldType) { $NinjaPropertyParams["Type"] = $CustomFieldType }

    # Log that we are about to attempt reading a custom field.
    Write-Host "Retrieving value from Custom Field $CustomFieldName."

    # Retrieve the value of a custom field using our function with the 'splatted' options.
    try {
        $Result = Get-NinjaProperty @NinjaPropertyParams | Out-String
    }
    catch {
        # If we ran into some sort of error we'll output it here.
        Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
        exit 1
    }

    # Output our results into the activity log.
    Write-Host $Result
}
end {
    
    
    
}
