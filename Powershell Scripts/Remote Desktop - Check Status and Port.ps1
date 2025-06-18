# Reports the status of Remote Desktop and the port it is listening on.
#Requires -Version 5.1

<#
.SYNOPSIS
    Reports the status of Remote Desktop and the port it is listening on.
.DESCRIPTION
    Reports the status of Remote Desktop and the port it is listening on.
    With the option to save the results to a custom field.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    [Info] Enabled | Port: 3389

PARAMETER: -RdpStatusCustomFieldName "RDPStatus"
    Name of a custom field to save the results to.
.EXAMPLE
    -RdpStatusCustomFieldName "RDPStatus"
    ## EXAMPLE OUTPUT WITH RdpStatusCustomFieldName ##
    [Info] Enabled | Port: 3389
    [Info] Attempting to set Custom Field 'RDPStatus'.
    [Info] Successfully set Custom Field 'RDPStatus'!
    
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$RdpStatusCustomFieldName
)

begin {
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
}
process {

    if ($env:rdpStatusCustomFieldName -and $env:rdpStatusCustomFieldName -notlike "null") { $RdpStatusCustomFieldName = $env:rdpStatusCustomFieldName }

    # Terminal Server registry path
    $RdpPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    # Deny RDP Connections
    $DenyRdpConnections = Get-ItemProperty -Path $RdpPath -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty fDenyTSConnections -ErrorAction SilentlyContinue
    # RDP Port
    $RdpPort = Get-ItemProperty -Path "$RdpPath\WinStations\RDP-Tcp" -Name PortNumber -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PortNumber -ErrorAction SilentlyContinue

    # 1 or $null = Disabled (Default)
    # 0 = Enabled
    $RdpEnabled = if ($DenyRdpConnections -eq 0) { "Enabled" }else { "Disabled" }
    # 3389 or $null = 3389 (Default)
    $RdpPort = if ($null -eq $RdpPort) { "3389" }else { "$RdpPort" }

    $Report = "$RdpEnabled | Port: $RdpPort"

    Write-Host "[Info] $Report"

    if ($RdpStatusCustomFieldName) {
        try {
            Write-Host "[Info] Attempting to set Custom Field '$RdpStatusCustomFieldName'."
            Set-NinjaProperty -Name $RdpStatusCustomFieldName -Value $Report
            Write-Host "[Info] Successfully set Custom Field '$RdpStatusCustomFieldName'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

}
end {
    
    
    
}
