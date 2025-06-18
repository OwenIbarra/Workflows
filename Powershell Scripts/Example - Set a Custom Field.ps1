# This is an example script for setting a custom field value. Specifying a type is recommended but not required.
#Requires -Version 4

<#
.SYNOPSIS
    This is an example script for setting a custom field value. Specifying a type is recommended but not required.
.DESCRIPTION
    This is an example script for setting a custom field value. Specifying a type is recommended but not required.
.EXAMPLE
    -CustomFieldName "text" -Value "Even More Text"
    
    Setting Custom Field 'text' with value 'Even More Text'....
    Success!

PARAMETER: -CustomFieldName "NameOfAcustomFieldToSet"
    The name of a custom field that you would like to set.

PARAMETER: -CustomFieldType "ReplaceMeWithFieldType"
    The type of custom field you are trying to set.
    Valid options are: "Text", "Checkbox", "Date", "Date And Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "Phone", "Secure", "URL"

PARAMETER: -NinjaDocumentName "Replace Me With A Ninja Document Name"
    Name of a Ninja Document you would like to retrieve these field values from. Leave blank to retrieve values from device custom fields.

PARAMETER: -Value "ReplaceMe"
    The value you would like to set for the custom field.
    
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
    [String]$NinjaDocumentName,
    [Parameter()]
    [String]$Value
)

begin {
    # Grab parameters from dynamic script variables.
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomFieldName = $env:customFieldName }
    if ($env:customFieldType -and $env:customFieldType -notlike "null") { $CustomFieldType = $env:customFieldType }
    if ($env:ninjaDocumentName -and $env:ninjaDocumentName -notlike "null") { $NinjaDocumentName = $env:ninjaDocumentName }
    if ($env:value -and $env:value -notlike "null") { $Value = $env:value }

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

    # This function is to make it easier to set Ninja Custom Fields.
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

        # If we're requested to set the field value for a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }

        # This is a list of valid fields we can set. If no type is given we'll assume the input doesn't have to be changed in any way.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }

        # The below field requires additional information in order to set
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

        # If we received some sort of error it should have an exception property and we'll exit the function with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }

        # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli is expecting the time to be representing as a Unix Epoch string. So we'll convert what we were given into that format.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID

                if (-not $Selection) {
                    throw "Value is not present in dropdown"
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
            $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1
        }

        if ($CustomField.Exception) {
            throw $CustomField
        }
    }
}
process {
    # If this script doesn't have Local Admin rights, error out.
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    
    # These are the three default mandatory parameters. We'll 'splat' them later.
    $NinjaPropertyParams = @{
        Name        = $CustomFieldName
        Value       = $Value
        ErrorAction = "Stop"
    }

    # If either of the optional options were given, add it to the parameter list to be 'splatted' later.
    if ($CustomFieldType) { $NinjaPropertyParams["Type"] = $CustomFieldType }
    if ($NinjaDocumentName) { $NinjaPropertyParams["DocumentName"] = $NinjaDocumentName }

    # Log that we are about to attempt setting a custom field.
    Write-Host "Setting Custom Field '$CustomFieldName' with value '$Value'...."

    # Set a custom field using our function with the 'splatted' options.
    try {
        Set-NinjaProperty @NinjaPropertyParams
    }
    catch {
        # If we ran into some sort of error we'll output it here.
        Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
        exit 1
    }

    Write-Host "Success!"
}
end {
    
    
    
}
