# Reports the status of System Restore on the system.
#Requires -Version 5.1

<#
.SYNOPSIS
    Reports the status of System Restore on the system.
.DESCRIPTION
    Reports the status of System Restore on the system.
    The report can be saved to a WYSIWYG Custom Field.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    [Info] System Restore Points Found!

    CreationTime        Description      SequenceNumber EventType                                    RestorePointType
    ------------        -----------      -------------- ---------                                    ----------------
    5/7/2024 3:51:11 PM Test Description              1 A system change has begun.                   An application has been installed.
    5/7/2024 3:53:11 PM Test Description              2 A system change has completed.               An application has been uninstalled.
    5/7/2024 3:54:11 PM Test Description              3 A system change has begun and is nested.     An application needs to delete the restore point it created.
    5/7/2024 3:59:11 PM Test Description              4 A system change has completed and is nested. A device driver has been installed.

PARAMETER: -WysiwygCustomField "ReplaceMeWithAnyWysiwygCustomField"
    Reports the status of System Restore on the system.
.EXAMPLE
    -WysiwygCustomField "ReplaceMeWithAnyWysiwygCustomField"
    ## EXAMPLE OUTPUT WITH WysiwygCustomField ##
    [Info] System Restore Points Found!

    CreationTime        Description      SequenceNumber EventType                                    RestorePointType
    ------------        -----------      -------------- ---------                                    ----------------
    5/7/2024 3:51:11 PM Test Description              1 A system change has begun.                   An application has been installed.
    5/7/2024 3:53:11 PM Test Description              2 A system change has completed.               An application has been uninstalled.
    5/7/2024 3:54:11 PM Test Description              3 A system change has begun and is nested.     An application needs to delete the restore point it created.
    5/7/2024 3:59:11 PM Test Description              4 A system change has completed and is nested. A device driver has been installed.


    [Info] Attempting to set Custom Field 'ReplaceMeWithAnyWysiwygCustomField'.
    [Info] Successfully set Custom Field 'ReplaceMeWithAnyWysiwygCustomField'.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$WysiwygCustomField
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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
    # Splatting the properties to be used in the Select-Object command
    $RestorePointSplatting = @{
        Property = @{ Label = "CreationTime"; Expression = {
                # Convert the CreationTime to a DateTime object from example: '20240507155911.581535-000'
                $CreationTime = $_.CreationTime -split "\."
                [DateTime]::ParseExact($CreationTime[0], "yyyyMMddHHmmss", $null)
            } 
        },
        @{ Label = "Description"; Expression = { $_.Description } },
        @{ Label = "SequenceNumber"; Expression = { $_.SequenceNumber } },
        @{
            Label      = "EventType"
            Expression = {
                # Event Type IDs: https://learn.microsoft.com/en-us/windows/win32/sr/systemrestore
                $ET = $_.EventType
                switch ($ET) {
                    100 { "Begun system change" }
                    101 { "Completed system change" }
                    102 { "Begun nested system change" }
                    103 { "Completed nested system change" }
                    Default { "Unknown EventType: $($ET)" }
                }
            }
        },
        @{
            Label      = "RestorePointType"
            Expression = {
                # Restore Point Types: https://learn.microsoft.com/en-us/windows/win32/sr/systemrestore
                $RPT = $_.RestorePointType
                switch ($RPT) {
                    0 { "An application has been installed." }
                    1 { "An application has been uninstalled." }
                    13 { "An application needs to delete the restore point it created." }
                    10 { "A device driver has been installed." }
                    12 { "An application has had features added or removed." }
                    Default { "Unknown RestorePointType: $($RPT)" }
                }
            }
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WysiwygCustomField = $env:wysiwygCustomFieldName }

    # Get System Restore Points
    $RestorePoints = Get-ComputerRestorePoint
    
    # Output the results to the Activity Feed
    if ($RestorePoints.Count -gt 0) {
        Write-Host "[Info] System Restore Points Found!"
        # Splatting from $RestorePointSplatting, auto sized to show all columns with a width of 4096 characters
        $RestorePoints | Select-Object @RestorePointSplatting | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    }
    else {
        Write-Host "[Info] No System Restore Points Found or System Restore is disabled!"
        # Continue on to update the custom field
    }

    # Save the results to a custom field
    if ($WysiwygCustomField) {
        $Report = $(
            if ($RestorePoints.Count -gt 0) {
                # Format the report into an HTML table
                # Splatting from $RestorePointSplatting
                $RestorePoints | Select-Object @RestorePointSplatting | ConvertTo-Html -Fragment
            }
            else {
                "<p>No System Restore Points Found or System Restore is disabled!</p>"
            }
        )
        # Minimum width of the table
        $Report = $Report -replace "<table>", "<table style='white-space:nowrap;'>"
        try {
            Write-Host "[Info] Attempting to set Custom Field '$WysiwygCustomField'."
    # Set-NinjaProperty -Name $WysiwygCustomField -Value $Report # Removed NinjaOne dependency
            Write-Host "[Info] Successfully set Custom Field '$WysiwygCustomField'."
        }
        catch {
            Write-Host "[Error] Failed to set Custom Field '$WysiwygCustomField'."
            $ExitCode = 1
        }
    }
    exit $ExitCode
}
end {
    
    
    
}
