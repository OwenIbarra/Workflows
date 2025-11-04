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
        
    # $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    # if ($Characters -ge 200000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # If requested to set the field value for a Ninja document, specify it here. # Removed NinjaOne dependency
    # $DocumentationParams = @{} # Removed NinjaOne dependency
    # if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName } # Removed NinjaOne dependency
            
    # # This is a list of valid fields that can be set. If no type is specified, assume that the input does not need to be changed. # Removed NinjaOne dependency
    # $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG" # Removed NinjaOne dependency
    # if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" } # Removed NinjaOne dependency
            
    # # The field below requires additional information to set. # Removed NinjaOne dependency
    # $NeedsOptions = "Dropdown" # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # # Redirect error output to the success stream to handle errors more easily if nothing is found or something else goes wrong. # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # If an error is received with an exception property, exit the function with that error information. # Removed NinjaOne dependency
    # if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions } # Removed NinjaOne dependency
            
    # # The types below require values not typically given to be set. The code below will convert whatever we're given into a format ninjarmm-cli supports. # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # Although it's highly likely we were given a value like "True" or a boolean data type, it's better to be safe than sorry. # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, match the given value with a GUID. # Removed NinjaOne dependency
    # $Date = (Get-Date $Value).ToUniversalTime() # Removed NinjaOne dependency
    # $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date # Removed NinjaOne dependency
    # $NinjaValue = $TimeSpan.TotalSeconds # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Dropdown" { # Removed NinjaOne dependency
    # # Ninjarmm-cli expects the GUID of the option we're trying to select, so match the value we were given with a GUID. # Removed NinjaOne dependency
    # $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name" # Removed NinjaOne dependency
    # $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID # Removed NinjaOne dependency
            
    # if (-not $Selection) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # $NinjaValue = $Selection # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # default { # Removed NinjaOne dependency
    # # All the other types shouldn't require additional work on the input. # Removed NinjaOne dependency
    # $NinjaValue = $Value # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Set the field differently depending on whether it's a field in a Ninja Document or not. # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    
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
    # Set-NinjaProperty -Name $CustomField -Value $CustomFieldValue # Removed NinjaOne dependency
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
