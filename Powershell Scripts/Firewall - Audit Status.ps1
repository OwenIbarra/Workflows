# Get the current status of the specified Windows firewall profile.
#Requires -Version 4

<#
.SYNOPSIS
    Get the current status of the specified Windows firewall profile.
.DESCRIPTION
    Get the current status of the specified Windows firewall profile.
.EXAMPLE
    -Domain -Private -Public
    
    Retrieving current firewall status.
    Checking for disabled firewall profiles or those that allow all inbound connections.

    [Alert] The 'Private' firewall profile is disabled!
    ### Firewall Status ###
    Name    Enabled DefaultInboundAction
    ----    ------- --------------------
    Domain     True                Block
    Private   False                Block
    Public     True                Block

PARAMETER: -Domain
    Check the Domain Firewall Profile.

PARAMETER: -Private
    Check the Private Firewall Profile.

PARAMETER: -Public
    Check the Public Firewall Profile.

PARAMETER: -CustomField "ReplaceMeWithNameOfTextCustomField"
    Optionally specify the name of a text custom field to store the results in.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Code cleanup and reorganization; removed exit codes for non-errors and added a custom field option.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$Domain = [System.Convert]::ToBoolean($env:domainProfile),
    [Parameter()]
    [Switch]$Private = [System.Convert]::ToBoolean($env:privateProfile),
    [Parameter()]
    [Switch]$Public = [System.Convert]::ToBoolean($env:publicProfile),
    [Parameter()]
    [String]$CustomField
)
begin {
    # If script form variables are used, replace the command-line parameters with their values.
    if ($env:firewallStatusCustomFieldName -and $env:firewallStatusCustomFieldName -notlike "null") { $CustomField = $env:firewallStatusCustomFieldName }

    # If no firewall profile is given, display an error message and exit the script.
    if (!$Domain -and !$Private -and !$Public) {
        Write-Host -Object "[Error] You must select the firewall profile you would like to audit."
        exit 1
    }

    function Test-IsElevated {
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
        # Create a WindowsPrincipal object based on the current identity
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    
        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # If setting a custom field is requested, check whether the script is elevated.
    if ($CustomField -and !(Test-IsElevated)) {
        Write-Host -Object "[Error] Setting a custom field requires the script to be run with Administrator privileges."
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
        
        # Measure the number of characters in the provided value
        $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters
    
        # Throw an error if the value exceeds the character limit of 200,000 characters
        if ($Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
        
        # Initialize a hashtable for additional documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # Define a list of valid field types
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
    
        # Warn the user if the provided type is not valid
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # Define types that require options to be retrieved
        $NeedsOptions = "Dropdown"
    
        # If the property is being set in a document or field and the type needs options, retrieve them
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # Throw an error if there was an issue retrieving the property options
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
            
        # Process the property value based on its type
        switch ($Type) {
            "Checkbox" {
                # Convert the value to a boolean for Checkbox type
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Convert the value to a Unix timestamp for Date or Date Time type
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Convert the dropdown value to its corresponding GUID
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
            
                # Throw an error if the value is not present in the dropdown options
                if (!($Selection)) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                }
            
                $NinjaValue = $Selection
            }
            default {
                # For other types, use the value as is
                $NinjaValue = $Value
            }
        }
            
        # Set the property value in the document if a document name is provided
        if ($DocumentName) {
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            # Otherwise, set the standard property value
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
            
        # Throw an error if setting the property failed
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Create a new list to store firewall profiles to audit
    $ProfilesToAudit = New-Object -TypeName System.Collections.Generic.List[string]

    # Add the corrosponding profile to the list if $Domain, $Private or $Public is set
    if ($Domain) { $ProfilesToAudit.Add("Domain") }
    if ($Private) { $ProfilesToAudit.Add("Private") }
    if ($Public) { $ProfilesToAudit.Add("Public") }

    try {
        # Inform the user that the script is retrieving the current firewall status
        Write-Host -Object "Retrieving current firewall status."

        # Retrieve firewall profiles from the ActiveStore and select specific properties: Name, Enabled, and DefaultInboundAction
        $NetProfile = Get-NetFirewallProfile -All -PolicyStore ActiveStore -ErrorAction Stop | Select-Object "Name", "Enabled", "DefaultInboundAction" | Where-Object { $ProfilesToAudit -contains $_.Name }
    }
    catch {
        # Display an error message if the firewall status retrieval fails and exit the script
        Write-Host -Object "[Error] Failed to retrieve the current firewall status!"
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Inform the user that the script is checking for disabled profiles or profiles allowing all inbound connections
    Write-Host -Object "Checking for disabled firewall profiles or those that allow all inbound connections.`n"

    # Loop through each profile in $NetProfile where the profile name is in $ProfilesToAudit
    $NetProfile | ForEach-Object {
        # Check if the profile is disabled and alert the user if so
        if (!([System.Convert]::ToBoolean($_.Enabled))) {
            Write-Host -Object "[Alert] The '$($_.Name)' firewall profile is disabled!"
        }

        # Check if the profile allows all inbound connections and alert the user if so
        if ($_.DefaultInboundAction -like "Allow") {
            Write-Host -Object "[Alert] The '$($_.Name)' firewall profile is set to allow all inbound connections!"
        }
    }

    # Display the status of the firewall profiles in a formatted table
    Write-Host -Object "### Firewall Status ###"
    ($NetProfile | Format-Table -AutoSize | Out-String).Trim() | Write-Host
    Write-Host -Object ""

    # If $CustomField is set, update the status for the custom field
    if ($CustomField) {

        # Loop through profiles to update the custom field status
        $NetProfile | ForEach-Object {
            # Set the status to "Off" if the profile is disabled or allows all inbound connections, otherwise set it to "On"
            if (!$_.Enabled -or $_.DefaultInboundAction -like "Allow") { 
                $Status = "Off" 
            }
            else { 
                $Status = "On" 
            }

            # Update the $CustomFieldValue with the profile name and status
            if ($CustomFieldValue) {
                $CustomFieldValue = "$CustomFieldValue | $($_.Name): $Status"
            }
            else {
                $CustomFieldValue = "$($_.Name): $Status"
            }
        }

        # Try to set the custom field value using the Set-NinjaProperty command
        try {
            Write-Host "Attempting to set Custom Field '$CustomField'."
            Set-NinjaProperty -Name $CustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$CustomField'!"
        }
        catch {
            # If setting the custom field fails, display an error message and exit the script
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Exit the script with the specified exit code
    exit $ExitCode
}
end {
    
    
    
}

