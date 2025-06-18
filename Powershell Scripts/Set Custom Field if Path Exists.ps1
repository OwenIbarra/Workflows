# Updates a custom field with Yes or No, depending if the path exists or not.
#Requires -Version 3

<#
.SYNOPSIS
    Updates a custom field with Yes or No, depending if the path exists or not.
.DESCRIPTION
    Updates a custom field with Yes or No, depending if the path exists or not.
.EXAMPLE
    -Path "C:\Program Files\VideoLAN\VLC\vlc.exe" -CustomField "VLC"
    Check if VLC is installed. Set custom field "VLC" to "Yes" if the folder exists or "No" if it doesn't.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012
    Release Notes: Updated Calculated Name
#>
[CmdletBinding()]
param (
    # Path to file or folder
    [Parameter()][String]$Path,
    # THe custom field that we will be updating
    [Parameter()][String]$CustomField,
    # Text that will be saved to the custom field when file/folder exists
    [Parameter(Mandatory = $false)][String]$Exists = "Yes",
    # Text that will be saved to the custom field when file/folder does not exist
    [Parameter(Mandatory = $false)][String]$NotExist = "No"
)

begin {
    if ($env:filePath) {
        $Path = $env:filePath
    }
    if ($env:CustomField) {
        $CustomField = $env:CustomField
    }
    if ($env:Exists) {
        $Exists = $env:Exists
    }
    if ($env:NotExist) {
        $NotExist = $env:NotExist
    }
    if (-not $Path -and -not $CustomField) {
        Write-Host "Path and CustomField Parameters are required."
        exit 1
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
    $CustomFieldValue = $(
        if ($(Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
            Write-Host "The Path $Path Exists!"
            $Exists
        }
        else {
            Write-Warning "The Path $Path Does Not Exist!"
            $NotExist
        }
    )

    try {
        Set-NinjaProperty -Name $CustomField -Value $CustomFieldValue
    }
    catch {
        # If we ran into some sort of error we'll output it here.
        Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
        exit 1
    }
}
end {
    
    
    
}


