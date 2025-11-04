# Retrieves detailed information about the iSCSI initiator connections and sessions on the local machine.

<#

.SYNOPSIS
    Retrieves detailed information about the iSCSI initiator connections and sessions on the local machine.

.DESCRIPTION
    Gathers details about the iSCSI initiator connections and sessions on the local machine.
    It retrieves information such as connection identifiers, initiator and target addresses, port numbers, session identifiers, and various other session attributes.
    This can also save these details to a specified custom field in a WYSIWYG format if provided.

.EXAMPLE
    Get-IscsiDetails

    This command gets the iSCSI initiator details.

PARAMETER: -WYSIWYGCustomFieldName "wysiwygCustomFieldName"
    The name of the custom field to save the iSCSI initiator details.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial release
#>
[CmdletBinding()]
param(
    [String]
    $WYSIWYGCustomFieldName
)
begin {

    if ($env:wysiwygCustomFieldName -notlike "null") {
        $WYSIWYGCustomFieldName = $env:wysiwygCustomFieldName
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
    # [String]$DocumentName, # Removed NinjaOne dependency
    # [Parameter()] # Removed NinjaOne dependency
    # [Switch]$Piped # Removed NinjaOne dependency
    # ) # Removed NinjaOne dependency
    # # Remove the non-breaking space character # Removed NinjaOne dependency
    # if ($Type -eq "WYSIWYG") { # Removed NinjaOne dependency
    # $Value = $Value -replace 'Â ', '&nbsp;' # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # Measure the number of characters in the provided value # Removed NinjaOne dependency
    # $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    
    # # Throw an error if the value exceeds the character limit of 200,000 characters # Removed NinjaOne dependency
    # if ($Piped -and $Characters -ge 200000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    
    # if (!$Piped -and $Characters -ge 45000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 45,000 characters.") # Removed NinjaOne dependency
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
    # try { # Removed NinjaOne dependency
    # # Otherwise, set the standard property value # Removed NinjaOne dependency
    # if ($Piped) { # Removed NinjaOne dependency
    # $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # catch { # Removed NinjaOne dependency
    # Write-Host -Object "[Error] Failed to set custom field." # Removed NinjaOne dependency
    # throw $_.Exception.Message # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Throw an error if setting the property failed # Removed NinjaOne dependency
    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    $ShouldOutputResults = $false
    $HasHadError = $false
}

process {
    try {
        $iscsiConnection = Get-IscsiConnection -ErrorAction Stop
        $iscsiSession = Get-IscsiSession -ErrorAction Stop
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        Write-Host "[Error] The Get-IscsiConnection or Get-IscsiSession cmdlet is not available on this system."
        exit 1
    }
    catch [System.Management.Automation.ActionPreferenceStopException] {
        Write-Host "[Error] Failed to retrieve iSCSI initiator details."
        exit 1
    }
    catch {
        if ($null -eq $iscsiConnection) {
            Write-Host "[Info] No iSCSI connections found."
        }
        if ($null -eq $iscsiSession) {
            Write-Host "[Info] No iSCSI sessions found."
        }
        exit
    }

    # If a custom field name is provided, save the results to the custom field
    if ($WYSIWYGCustomFieldName) {
        # If there are no iSCSI connections or sessions, output the details to the Activity Feed
        if ($iscsiSession.Count -eq 0) {
            $ShouldOutputResults = $true
            Write-Host "[Info] No data to save to custom field."
        }
        else {
            # Create an HTML string to save to the custom field

            # iSCSI initiator details
            $wysiwyghtml = "<h2>iSCSI Connection</h2>"
            $wysiwyghtml += $iscsiConnection | Select-Object -Property @{l = 'Connection Identifier'; e = { $_.ConnectionIdentifier } },
            @{l = 'Initiator Address'; e = { $_.InitiatorAddress } },
            @{l = 'Initiator Port'; e = { $_.InitiatorPortNumber } },
            @{l = 'Target Address'; e = { $_.TargetAddress } },
            @{l = 'Target Port'; e = { $_.TargetPortNumber } } | ConvertTo-Html -Fragment

            # iSCSI session details
            $wysiwyghtml += "<h2>iSCSI Session</h2>"
            $wysiwyghtml += $iscsiSession | Select-Object -Property @{l = 'Authentication Type'; e = { $_.AuthenticationType } },
            @{l = 'Initiator Name'; e = { $_.InitiatorInstanceName } },
            @{l = 'Initiator Node Address'; e = { $_.InitiatorNodeAddress } },
            @{l = 'Initiator Portal Address'; e = { $_.InitiatorPortalAddress } },
            @{l = 'Initiator Side Identifier'; e = { $_.InitiatorSideIdentifier } },
            @{l = 'Is Connected'; e = { $_.IsConnected } },
            @{l = 'Is Data Digest'; e = { $_.IsDataDigest } },
            @{l = 'Is Persistent'; e = { $_.IsPersistent } },
            @{l = 'Number of Connections'; e = { $_.NumberOfConnections } },
            @{l = 'Session Identifier'; e = { $_.SessionIdentifier } },
            @{l = 'Target Node Address'; e = { $_.TargetNodeAddress } },
            @{l = 'Target Side Identifier'; e = { $_.TargetSideIdentifier } } | ConvertTo-Html -Fragment

            # Save the HTML string to the custom field
            try {
    # Set-NinjaProperty -Name $WYSIWYGCustomFieldName -Value $wysiwyghtml -Type "WYSIWYG" -Piped # Removed NinjaOne dependency
                Write-Host "[Info] Results saved to custom field: $WYSIWYGCustomFieldName"
                $ShouldOutputResults = $true
            }
            catch {
                Write-Host "[Error] Failed to save results to custom field: $WYSIWYGCustomFieldName"
                $ShouldOutputResults = $true
                $HasHadError = $true
            }
        }
    }
    else {
        $ShouldOutputResults = $true
    }

    # Output the iSCSI initiator details to the Activity Feed
    if ($ShouldOutputResults) {
        # Output the iSCSI initiator details to the Activity Feed
        Write-Host "---iSCSI Connection---"
        $iscsiConnection | Select-Object -Property @{l = 'Connection ID'; e = { $_.ConnectionIdentifier } },
        @{l = 'Initiator Address'; e = { $_.InitiatorAddress } },
        @{l = 'Initiator Port'; e = { $_.InitiatorPortNumber } },
        @{l = 'Target Address'; e = { $_.TargetAddress } },
        @{l = 'Target Port'; e = { $_.TargetPortNumber } } | Format-List | Out-String -Width 4000 | Write-Host

        # Output the iSCSI session details to the Activity Feed
        Write-Host "---iSCSI Session---"
        $iscsiSession | Select-Object -Property @{l = 'Auth'; e = { $_.AuthenticationType } },
        @{l = 'Init Name'; e = { $_.InitiatorInstanceName } },
        @{l = 'Init Node Address'; e = { $_.InitiatorNodeAddress } },
        @{l = 'Init Portal Address'; e = { $_.InitiatorPortalAddress } },
        @{l = 'Init Side ID'; e = { $_.InitiatorSideIdentifier } },
        @{l = 'Connected'; e = { $_.IsConnected } },
        @{l = 'Data Digest'; e = { $_.IsDataDigest } },
        @{l = 'Persistent'; e = { $_.IsPersistent } },
        @{l = '# Connections'; e = { $_.NumberOfConnections } },
        @{l = 'SID'; e = { $_.SessionIdentifier } },
        @{l = 'Tgt Node Address'; e = { $_.TargetNodeAddress } },
        @{l = 'Tgt Side ID'; e = { $_.TargetSideIdentifier } } | Format-List | Out-String -Width 4000 | Write-Host
    }

    if ($HasHadError) {
        exit 1
    }
}

end {
    
    
    
}
