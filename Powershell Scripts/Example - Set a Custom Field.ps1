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
