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
    # function Set-NinjaProperty { # Removed NinjaOne dependency
    # [CmdletBinding()] # Removed NinjaOne dependency
    # Param( # Removed NinjaOne dependency
    # [Parameter(Mandatory = $True)] # Removed NinjaOne dependency
    # [String]$Name, # Removed NinjaOne dependency
    # [Parameter()] # Removed NinjaOne dependency
    # [String]$Type, # Removed NinjaOne dependency
    # [Parameter(Mandatory = $True, ValueFromPipeline = $True)] # Removed NinjaOne dependency
    # $Value, # Removed NinjaOne dependency
    # [Parameter()] # Removed NinjaOne dependency
    # [String]$DocumentName # Removed NinjaOne dependency
    # ) # Removed NinjaOne dependency

    # # If we're requested to set the field value for a Ninja document we'll specify it here. # Removed NinjaOne dependency
    # $DocumentationParams = @{} # Removed NinjaOne dependency
    # if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName } # Removed NinjaOne dependency

    # # This is a list of valid fields we can set. If no type is given we'll assume the input doesn't have to be changed in any way. # Removed NinjaOne dependency
    # $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL" # Removed NinjaOne dependency
    # if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" } # Removed NinjaOne dependency

    # # The below field requires additional information in order to set # Removed NinjaOne dependency
    # $NeedsOptions = "Dropdown" # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong. # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    # # If we received some sort of error it should have an exception property and we'll exit the function with that error information. # Removed NinjaOne dependency
    # if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions } # Removed NinjaOne dependency

    # # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports. # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry. # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Ninjarmm-cli is expecting the time to be representing as a Unix Epoch string. So we'll convert what we were given into that format. # Removed NinjaOne dependency
    # $Date = (Get-Date $Value).ToUniversalTime() # Removed NinjaOne dependency
    # $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date # Removed NinjaOne dependency
    # $NinjaValue = $TimeSpan.TotalSeconds # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Dropdown" { # Removed NinjaOne dependency
    # # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid. # Removed NinjaOne dependency
    # $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name" # Removed NinjaOne dependency
    # $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID # Removed NinjaOne dependency

    # if (-not $Selection) { # Removed NinjaOne dependency
    # throw "Value is not present in dropdown" # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    # $NinjaValue = $Selection # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # default { # Removed NinjaOne dependency
    # # All the other types shouldn't require additional work on the input. # Removed NinjaOne dependency
    # $NinjaValue = $Value # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    # # We'll need to set the field differently depending on if its a field in a Ninja Document or not. # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
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
    # Set-NinjaProperty -Name $CustomField -Value $CustomFieldValue # Removed NinjaOne dependency
    }
    catch {
        # If we ran into some sort of error we'll output it here.
        Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
        exit 1
    }
}
end {
    
    
    
}


