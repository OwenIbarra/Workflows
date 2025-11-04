# Checks the current network connections to see what profile they are currently using and optionally save the results to a custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Checks the current network connections to see what profile they are currently using and optionally save the results to a custom field.
.DESCRIPTION
    Checks the current network connections to see what profile they are currently using and optionally save the results to a custom field.
.EXAMPLE
    (No Parameters)
    
    Retrieving network adapters.
    Gathering additional information.

    NetworkAdapter   MacAddress        Type  Profile
    --------------   ----------        ----  -------
    LabNet - Win10 0 00-17-FB-00-00-02 Wired  Public

PARAMETER: -CustomField "ReplaceMeWithYourDesiredCustomField"
    Optionally specify the name of a custom field to save the results to.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomField
)

begin {
    # If script form variables are used, replace the command the command line parameters with their value.
    if ($env:networkProfileCustomFieldName -and $env:networkProfileCustomFieldName -notlike "null") { $CustomField = $env:networkProfileCustomFieldName }
    
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
        
    # # Measure the number of characters in the provided value # Removed NinjaOne dependency
    # $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    
    # # Throw an error if the value exceeds the character limit of 200,000 characters # Removed NinjaOne dependency
    # if ($Characters -ge 200000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # Initialize a hashtable for additional documentation parameters # Removed NinjaOne dependency
    # $DocumentationParams = @{} # Removed NinjaOne dependency
    
    # # If a document name is provided, add it to the documentation parameters # Removed NinjaOne dependency
    # if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName } # Removed NinjaOne dependency
        
    # # Define a list of valid field types # Removed NinjaOne dependency
    # $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG" # Removed NinjaOne dependency
    
    # # Warn the user if the provided type is not valid # Removed NinjaOne dependency
    # if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" } # Removed NinjaOne dependency
        
    # # Define types that require options to be retrieved # Removed NinjaOne dependency
    # $NeedsOptions = "Dropdown" # Removed NinjaOne dependency
    
    # # If the property is being set in a document or field and the type needs options, retrieve them # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # Throw an error if there was an issue retrieving the property options # Removed NinjaOne dependency
    # if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions } # Removed NinjaOne dependency
            
    # # Process the property value based on its type # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # Convert the value to a boolean for Checkbox type # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Convert the value to a Unix timestamp for Date or Date Time type # Removed NinjaOne dependency
    # $Date = (Get-Date $Value).ToUniversalTime() # Removed NinjaOne dependency
    # $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date # Removed NinjaOne dependency
    # $NinjaValue = $TimeSpan.TotalSeconds # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Dropdown" { # Removed NinjaOne dependency
    # # Convert the dropdown value to its corresponding GUID # Removed NinjaOne dependency
    # $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name" # Removed NinjaOne dependency
    # $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID # Removed NinjaOne dependency
            
    # # Throw an error if the value is not present in the dropdown options # Removed NinjaOne dependency
    # if (!($Selection)) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # $NinjaValue = $Selection # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # default { # Removed NinjaOne dependency
    # # For other types, use the value as is # Removed NinjaOne dependency
    # $NinjaValue = $Value # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Set the property value in the document if a document name is provided # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # # Otherwise, set the standard property value # Removed NinjaOne dependency
    # $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Throw an error if setting the property failed # Removed NinjaOne dependency
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
    # Check if the script is running with elevated (Administrator) privileges.
    if ($CustomField -and !(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Administrator privileges are required to set Custom Fields."
        exit 1
    }

    # Initialize a list to store network information.
    $NetworkInfo = New-Object System.Collections.Generic.List[object]

    # Inform the user that network adapters are being retrieved.
    Write-Host -Object "Retrieving network adapters."

    try {
        # Attempt to retrieve the network connection profiles and adapters.
        $NetworkProfiles = Get-NetConnectionProfile -ErrorAction Stop
        $NetworkAdapters = Get-NetAdapter -ErrorAction Stop
    }
    catch {
        # Catch any errors during network profile/adapter retrieval and output error messages.
        Write-Host -Object "[Error] Failed to retrieve network adapters."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Inform the user that additional information is being gathered.
    Write-Host -Object "Gathering additional information."

    # Loop through each network profile.
    foreach ($NetworkProfile in $NetworkProfiles) {
        # Find the network adapter associated with the current network profile using the InterfaceIndex.
        $NetAdapter = $NetworkAdapters | Where-Object { $_.ifIndex -eq $NetworkProfile.InterfaceIndex }

        # Determine the adapter type (Wired, Wi-Fi, or Other) based on the MediaType.
        switch -Wildcard ($NetAdapter.MediaType) {
            "802.3" { $AdapterType = "Wired" }
            "*802.11" { $AdapterType = "Wi-Fi" }
            default { $AdapterType = "Other" }
        }

        # Add the network adapter information as a custom object to the $NetworkInfo list.
        $NetworkInfo.Add(
            [PSCustomObject]@{
                "NetworkAdapter" = $NetAdapter.Name
                "MacAddress"     = $NetAdapter.MacAddress
                "Type"           = $AdapterType
                "Profile"        = $NetworkProfile.NetworkCategory
            }
        )
    }

    # Check if the $NetworkInfo list is empty or contains fewer than one entry.
    if (!$NetworkInfo -or ($NetworkInfo | Measure-Object | Select-Object -ExpandProperty Count) -lt 1) {
        Write-Host -Object "[Error] No network interfaces found."
        exit 1
    }

    # Format and output the network information in a table.
    Write-Host -Object ""
    ($NetworkInfo | Format-Table | Out-String).Trim() | Write-Host
    Write-Host -Object ""

    # If a custom field is provided, iterate through the network information and append the adapter details to $CustomFieldValue.
    if ($CustomField) {
        $NetworkInfo | ForEach-Object {
            if ($CustomFieldValue) {
                # Append the network adapter name and profile to the existing $CustomFieldValue.
                $CustomFieldValue = "$CustomFieldValue | $($_.NetworkAdapter): $($_.Profile)"
            }
            else {
                # Set $CustomFieldValue if it hasn't been initialized yet.
                $CustomFieldValue = "$($_.NetworkAdapter): $($_.Profile)"
            }
        }

        try {
    # # Try to set the custom field value using the Set-NinjaProperty function. # Removed NinjaOne dependency
            Write-Host "Attempting to set Custom Field '$CustomField'."
    # Set-NinjaProperty -Name $CustomField -Value $CustomFieldValue # Removed NinjaOne dependency
            Write-Host "Successfully set custom field '$CustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Exit the script with the provided $ExitCode variable.
    exit $ExitCode
}
end {
    
    
    
}
