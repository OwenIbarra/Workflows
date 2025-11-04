# Checks the version of Exchange installed and if it is outdated against the supplied versions.

<#
.SYNOPSIS
    Checks the version of Exchange installed and if it is outdated against the supplied versions.
.DESCRIPTION
    Checks the version of Exchange installed and if it is outdated against the supplied versions.
    The version of Exchange that can be checked against are the following versions: 2010, 2013, 2016, and 2019.
    
    If the version is outdated, a warning is displayed.
    The script will not alert if the version is up to date.

    CheckboxCustomField can be used to skip the check, and the custom field must be a checkbox or a text field with a value of "true" or "1".

    CustomFieldName can be used to save the version to a text custom field.

    Exchange 2010 starts with 14.3, 2013 starts with 15.0, 2016 starts with 15.1, and 2019 starts with 15.2.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    [Error] Exchange 2010, 2013, 2016, and 2019 versions are required to run this script.

PARAMETER: -CustomFieldName "ExchangeVersion" -Exchange2010Version "14.3.513.0" -Exchange2013Version "15.0.1497.48" -Exchange2016Version "15.1.0.0" -Exchange2019Version "15.2.0.0"
    Saves the Exchange version to a custom field named "ExchangeVersion"
.EXAMPLE
    -CustomFieldName "ExchangeVersion" -Exchange2010Version "14.3.513.0" -Exchange2013Version "15.0.1497.48" -Exchange2016Version "15.1.0.0" -Exchange2019Version "15.2.0.0"
    ## EXAMPLE OUTPUT WITH CustomFieldName ##
    [Info] Exchange version is up to date. Found version: 15.2.0.0
    [Info] Attempting to set Custom Field 'ExchangeVersion'.
    [Info] Successfully set Custom Field 'ExchangeVersion'!

PARAMETER: -CheckboxCustomField "SkipExchangeCheck" -Exchange2010Version "14.3.513.0" -Exchange2013Version "15.0.1497.48" -Exchange2016Version "15.1.0.0" -Exchange2019Version "15.2.0.0"
    Skips the Exchange version check if the checkbox custom field "SkipExchangeCheck" is checked or if a text custom field is set to "true" or "1".
.EXAMPLE
    -CheckboxCustomField "SkipExchangeCheck" -Exchange2010Version "14.3.513.0" -Exchange2013Version "15.0.1497.48" -Exchange2016Version "15.1.0.0" -Exchange2019Version "15.2.0.0"
    ## EXAMPLE OUTPUT WITH CustomFieldName ##
    [Info] Skipping Exchange version check.

.NOTES
    Minimum OS Architecture Supported: Windows Server 2008 R2
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [String]$CustomFieldName,
    [String]$Exchange2010Version,
    [String]$Exchange2013Version,
    [String]$Exchange2016Version,
    [String]$Exchange2019Version,
    [String]$CheckboxCustomField
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Test-IsWorkstation {
        $OS = Get-WmiObject -Class Win32_OperatingSystem
        return $OS.ProductType -eq 1
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

    # $Characters = $Value | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    # if ($Characters -ge 10000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than 10,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    # # If we're requested to set the field value for a Ninja document we'll specify it here. # Removed NinjaOne dependency
    # $DocumentationParams = @{} # Removed NinjaOne dependency
    # if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName } # Removed NinjaOne dependency

    # # This is a list of valid fields that can be set. If no type is given, it will be assumed that the input doesn't need to be changed. # Removed NinjaOne dependency
    # $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG" # Removed NinjaOne dependency
    # if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" } # Removed NinjaOne dependency

    # # The field below requires additional information to be set # Removed NinjaOne dependency
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

    # # If an error is received it will have an exception property, the function will exit with that error information. # Removed NinjaOne dependency
    # if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions } # Removed NinjaOne dependency

    # # The below types require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports. # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry. # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, the given value will be matched with a GUID. # Removed NinjaOne dependency
    # $Date = (Get-Date $Value).ToUniversalTime() # Removed NinjaOne dependency
    # $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date # Removed NinjaOne dependency
    # $NinjaValue = $TimeSpan.TotalSeconds # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Dropdown" { # Removed NinjaOne dependency
    # # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid. # Removed NinjaOne dependency
    # $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name" # Removed NinjaOne dependency
    # $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID # Removed NinjaOne dependency

    # if (-not $Selection) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown") # Removed NinjaOne dependency
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
        $NeedsOptions = "DropDown", "MultiSelect"

        # Grabbing document values requires a slightly different command.
        if ($DocumentName) {
            # Secure fields are only readable when they're a device custom field
            if ($Type -Like "Secure") { throw [System.ArgumentOutOfRangeException]::New("$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality") }

            # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
            Write-Host "Retrieving value from Ninja Document..."
    # $NinjaPropertyValue = Ninja-Property-Docs-Get -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency

            # Certain fields require more information to parse.
            if ($NeedsOptions -contains $Type) {
    # $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency
            }
        }
        else {
            # We'll redirect error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
    # $NinjaPropertyValue = Ninja-Property-Get -Name $Name 2>&1 # Removed NinjaOne dependency

            # Certain fields require more information to parse.
            if ($NeedsOptions -contains $Type) {
    # $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1 # Removed NinjaOne dependency
            }
        }

        # If we received some sort of error it should have an exception property and we'll exit the function with that error information.
        if ($NinjaPropertyValue.Exception) { throw $NinjaPropertyValue }
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }

        if (-not $NinjaPropertyValue) {
            throw [System.NullReferenceException]::New("The Custom Field '$Name' is empty!")
        }

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
                # In Ninja Date and Date/Time fields are in Unix Epoch time in the UTC timezone the below should convert it into local time as a DateTime object.
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
                # Casts the Ninja provided string into an integer.
                [int]$NinjaPropertyValue
            }
            "MultiSelect" {
                # Multi-Select custom fields come in as a comma-separated list of GUIDs we'll compare these with all the options and return just the option values selected instead of a guid.
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
                # Time fields are given as a number of seconds starting from midnight. This will convert it into a DateTime object.
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

    $ExitCode = 0
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check that the NT Version is at least 6.1 for Windows Server 2008 R2
    $WindowsVersion = $(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentVersion).CurrentVersion
    if ($WindowsVersion -lt 6.1 -or $(Test-IsWorkstation)) {
        Write-Host "[Error] This script requires Windows Server 2008 R2 or higher."
        exit 1
    }

    # Get parameters from Script Variables
    if ($env:customFieldName -and $env:customFieldName -notlike "null") {
        $CustomFieldName = $env:customFieldName
    }
    if ($env:exchange2010Version -and $env:exchange2010Version -notlike "null") {
        $Exchange2010Version = $env:exchange2010Version
    }
    if ($env:exchange2013Version -and $env:exchange2013Version -notlike "null") {
        $Exchange2013Version = $env:exchange2013Version
    }
    if ($env:exchange2016Version -and $env:exchange2016Version -notlike "null") {
        $Exchange2016Version = $env:exchange2016Version
    }
    if ($env:exchange2019Version -and $env:exchange2019Version -notlike "null") {
        $Exchange2019Version = $env:exchange2019Version
    }
    if ($env:checkboxCustomField -and $env:checkboxCustomField -notlike "null") {
        $CheckboxCustomField = $env:checkboxCustomField
    }

    # Required Parameters
    if ($Exchange2010Version -and $Exchange2013Version -and $Exchange2016Version -and $Exchange2019Version) {
        # Check if the versions are valid
        if ([System.Version]::TryParse($Exchange2010Version, [ref]$null) -eq $false) {
            Write-Host "[Error] Exchange 2010 version is not a valid version: $Exchange2010Version"
            exit 1
        }
        if ([System.Version]::TryParse($Exchange2013Version, [ref]$null) -eq $false) {
            Write-Host "[Error] Exchange 2013 version is not a valid version: $Exchange2013Version"
            exit 1
        }
        if ([System.Version]::TryParse($Exchange2016Version, [ref]$null) -eq $false) {
            Write-Host "[Error] Exchange 2016 version is not a valid version: $Exchange2016Version"
            exit 1
        }
        if ([System.Version]::TryParse($Exchange2019Version, [ref]$null) -eq $false) {
            Write-Host "[Error] Exchange 2019 version is not a valid version: $Exchange2019Version"
            exit 1
        }
        # Requirements are met
    }
    else {
        Write-Host "[Error] Exchange 2010, 2013, 2016, and 2019 versions are required to run this script."
        exit 1
    }

    if ($CheckboxCustomField -and $CheckboxCustomField -notlike "null") {
        # Check if the text custom field is set to 1 as a check box or true as a string
        try {
            $boolCheck = Get-NinjaProperty -Name $CheckboxCustomField -Type "Checkbox"
            $stringCheck = Get-NinjaProperty -Name $CheckboxCustomField
            if (
                $true -eq $boolCheck -or
                $stringCheck -eq "1"
            ) {
                Write-Host "[Info] Skipping Exchange version check."
                exit 0
            }
        }
        catch {
            Write-Host "[Warn] Failed to get the value of the checkbox custom field."
            Write-Host "[Info] Continuing with Exchange version check."
        }
    }

    # Check if Exchange is installed
    if (-not $(Get-Service -Name MSExchangeServiceHost -ErrorAction SilentlyContinue)) {
        Write-Host "[Error] This script requires Exchange to be installed and running."
        exit 1
    }

    # Find the location of ExSetup.exe
    $ExSetupPath = Get-ChildItem -Path "C:\Program Files\Microsoft\Exchange Server\*" -Recurse -Filter "ExSetup.exe" | Select-Object -ExpandProperty FullName
    # Check if this is an Exchange server
    if (-not (Test-Path -Path $ExSetupPath)) {
        Write-Host "[Error] Exchange Server is not installed."
        exit 1
    }

    # Get the installed Exchange version from ExSetup.exe
    $ExchangeFileVersion = Get-Command $ExSetupPath | ForEach-Object { $_.FileVersionInfo }
    # Determine the edition of Exchange
    $ExchangeYearVersion = switch ($ExchangeFileVersion.FileVersionRaw.Major) {
        14 {
            "2010"
        }
        15 {
            switch ($ExchangeFileVersion.FileVersionRaw.Minor) {
                0 { "2013" }
                1 { "2016" }
                2 { "2019" }
                Default { "Unknown" }
            }
        }
        Default { "Unknown" }
    }

    # Check if the Exchange version is outdated
    switch ($ExchangeYearVersion) {
        "2010" {
            if ($ExchangeFileVersion.FileVersionRaw -lt $Exchange2010Version) {
                Write-Host "[Warn] Exchange 2010 version is outdated. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
            else {
                Write-Host "[Info] Exchange 2010 version is up to date. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
        }
        "2013" {
            if ($ExchangeFileVersion.FileVersionRaw -lt $Exchange2013Version) {
                Write-Host "[Warn] Exchange 2013 version is outdated. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
            else {
                Write-Host "[Info] Exchange 2013 version is up to date. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
        }
        "2016" {
            if ($ExchangeFileVersion.FileVersionRaw -lt $Exchange2016Version) {
                Write-Host "[Warn] Exchange 2016 version is outdated. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
            else {
                Write-Host "[Info] Exchange 2016 version is up to date. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
        }
        "2019" {
            if ($ExchangeFileVersion.FileVersionRaw -lt $Exchange2019Version) {
                Write-Host "[Warn] Exchange 2019 version is outdated. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
            else {
                Write-Host "[Info] Exchange 2019 version is up to date. Found version: $($ExchangeFileVersion.FileVersionRaw)"
            }
        }
        Default {
            Write-Host "[Error] Unknown Exchange version."
            exit 1
        }
    }

    if ($CustomFieldName -and $CustomFieldName -notlike "null") {
        try {
            Write-Host "[Info] Attempting to set Custom Field '$CustomFieldName'."
    # Set-NinjaProperty -Name $CustomFieldName -Value $($ExchangeFileVersion.FileVersion | Out-String) # Removed NinjaOne dependency
            Write-Host "[Info] Successfully set Custom Field '$CustomFieldName'!"
        }
        catch {
            Write-Host "[Error] Failed to set Custom Field '$CustomFieldName'."
            $ExitCode = 1
        }
    }

    if ($ExitCode -gt 0) {
        exit $ExitCode
    }
}
end {
    
    
    
}
