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
            [String]$DocumentName,
            [Parameter()]
            [Switch]$Piped
        )
        # Remove the non-breaking space character
        if ($Type -eq "WYSIWYG") {
            $Value = $Value -replace 'Â ', '&nbsp;'
        }
        
        # Measure the number of characters in the provided value
        $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters
    
        # Throw an error if the value exceeds the character limit of 200,000 characters
        if ($Piped -and $Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
    
        if (!$Piped -and $Characters -ge 45000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 45,000 characters.")
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
            try {
                # Otherwise, set the standard property value
                if ($Piped) {
                    $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
                }
                else {
                    $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1
                }
            }
            catch {
                Write-Host -Object "[Error] Failed to set custom field."
                throw $_.Exception.Message
            }
        }
            
        # Throw an error if setting the property failed
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }
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
                Set-NinjaProperty -Name $WYSIWYGCustomFieldName -Value $wysiwyghtml -Type "WYSIWYG" -Piped
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
