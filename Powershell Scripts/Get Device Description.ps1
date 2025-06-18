# Retrieves the current device description and optionally saves it to a custom field.

<#
.SYNOPSIS
    Retrieves the current device description and optionally saves it to a custom field.
.DESCRIPTION
    Retrieves the current device description and optionally saves it to a custom field.
.EXAMPLE
    -CustomField "text"
    
    Current device description: 'Kitchen Computer'
    Attempting to set custom field 'text'.
    Successfully set custom field 'text'!

PARAMETER: -CustomField "ExampleInput"
    Optionally specify the name of a custom field you would like to save the results to.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomField
)

begin {
    if ($env:nameOfCustomField -and $env:nameOfCustomField -notlike "null") { $CustomField = $env:nameOfCustomField }

    # PowerShell 3 or higher is required for custom field functionality
    if ($PSVersionTable.PSVersion.Major -lt 3 -and $CustomField) {
        Write-Host -Object "[Error] Setting custom fields requires powershell version 3 or higher."
        Write-Host -Object "https://ninjarmm.zendesk.com/hc/en-us/articles/4405408656013-Custom-Fields-and-Documentation-CLI-and-Scripting"
        exit 1
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
        
        $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
            
        # If requested to set the field value for a Ninja document, specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
            
        # This is a list of valid fields that can be set. If no type is specified, assume that the input does not need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
            
        # The field below requires additional information to set.
        $NeedsOptions = "Dropdown"
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                # Redirect error output to the success stream to handle errors more easily if nothing is found or something else goes wrong.
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
            
        # If an error is received with an exception property, exit the function with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
            
        # The types below require values not typically given to be set. The code below will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # Although it's highly likely we were given a value like "True" or a boolean data type, it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, match the given value with a GUID.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli expects the GUID of the option we're trying to select, so match the value we were given with a GUID.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
            
                if (-not $Selection) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                }
            
                $NinjaValue = $Selection
            }
            default {
                # All the other types shouldn't require additional work on the input.
                $NinjaValue = $Value
            }
        }
            
        # Set the field differently depending on whether it's a field in a Ninja Document or not.
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
    # Check if the script is being run with elevated (administrator) privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access denied. Please run with administrator privileges."
        exit 1
    }

    try {
        # Determine the PowerShell version and get the operating system description accordingly
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            # Use Get-WmiObject for PowerShell versions less than 5
            $Description = $(Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop).Description
        }
        else {
            # Use Get-CimInstance for PowerShell version 5 or greater
            $Description = $(Get-CimInstance -Class Win32_OperatingSystem -ErrorAction Stop).Description
        }

        # Trim any leading or trailing whitespace from the description
        if ($Description) {
            $Description = $Description.Trim()
        }
    }
    catch {
        # Handle any errors that occur while retrieving the device description
        Write-Host -Object "[Error] Failed to retrieve current device description."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Check if the description is empty or not
    if (!$Description) {
        Write-Host -Object "[Alert] No device description is currently set."
        $CustomFieldValue = "No device description is currently set."
    }
    else {
        Write-Host -Object "Current device description: '$Description'"
        $CustomFieldValue = $Description
    }

    # If a custom field is specified, attempt to set its value
    if ($CustomField) {
        try {
            Write-Host "Attempting to set custom field '$CustomField'."
            Set-NinjaProperty -Name $CustomField -Value $CustomFieldValue
            Write-Host "Successfully set custom field '$CustomField'!"
        }
        catch {
            Write-Host -Object "[Error] Failed to set custom field '$CustomField'"
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}
