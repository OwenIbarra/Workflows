# Alert on specified ports that are Listening or Established and optionally save the results to a custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Alert on specified ports that are Listening or Established and optionally save the results to a custom field.
.DESCRIPTION
    Will alert on open ports, regardless if a firewall is blocking them or not.
    Checks for open ports that are in a 'Listen' or 'Established' state.
    UDP is a stateless protocol and will not have a state.
    Outputs the open ports, process ID, state, protocol, local address, and process name.
    When a Custom Field is provided this will save the results to that custom field.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    [Alert] Found open port: 80, PID: 99, State: Listen, Local Address: 0.0.0.0, Process: nginx
    [Alert] Found open port: 500, PID: 99, State: Listen, Local Address: 0.0.0.0, Process: nginx

PARAMETER: -Port "100,200,300-350, 400"
    A comma separated list of ports to check. Can include ranges (e.g. 100,200,300-350, 400)
.EXAMPLE
    -Port "80,200,300-350, 400"
    ## EXAMPLE OUTPUT WITH Port ##
    [Alert] Found open port: 80, PID: 99, State: Listen, Local Address: 0.0.0.0, Process: nginx

PARAMETER: -CustomField "ReplaceMeWithAnyMultilineCustomField"
    Name of the custom field to save the results to.
.EXAMPLE
    -Port "80,200,300-350, 400" -CustomField "ReplaceMeWithAnyMultilineCustomField"
    ## EXAMPLE OUTPUT WITH CustomField ##
    [Alert] Found open port: 80, PID: 99, State: Listen, Local Address: 0.0.0.0, Process: nginx
    [Info] Saving results to custom field: ReplaceMeWithAnyMultilineCustomField
    [Info] Results saved to custom field: ReplaceMeWithAnyMultilineCustomField
.OUTPUTS
    None
.NOTES
    Supported Operating Systems: Windows 10/Windows Server 2016 or later with PowerShell 5.1
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$PortsToCheck,
    [String]$CustomFieldName
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
        
    # # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports. # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry. # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Ninjarmm-cli expects the  Date-Time to be in Unix Epoch time so we'll convert it here. # Removed NinjaOne dependency
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
    # $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    if ($env:portsToCheck -and $env:portsToCheck -ne 'null') {
        $PortsToCheck = $env:portsToCheck
    }
    if ($env:customFieldName -and $env:customFieldName -ne 'null') {
        $CustomFieldName = $env:customFieldName
    }

    # Remove any whitespace
    $PortsToCheck = $PortsToCheck -replace '\s', ''

    # Parse the ports to check
    $Ports = if ($PortsToCheck) {
        # Split the ports by comma and handle ranges
        $PortsToCheck -split ',' | ForEach-Object {
            # Trim the whitespace
            $Ports = "$_".Trim()
            # If the port is a range, expand it
            if ($Ports -match '-') {
                # Split the range and expand it
                $Range = $Ports -split '-' | ForEach-Object { "$_".Trim() } | Where-Object { $_ }
                if ($Range.Count -ne 2) {
                    Write-Host "[Error] Invalid range formatting, must be two number with a dash in between them (eg 1-10): $PortsToCheck"
                    exit 1
                }
                try {
                    $Range[0]..$Range[1]
                }
                catch {
                    Write-Host "[Error] Failed to parse range, must be two number with a dash in between them (eg 1-10): $PortsToCheck"
                    exit 1
                }
            }
            else {
                $Ports
            }
        }
    }
    else { $null }

    if ($($Ports | Where-Object { [int]$_ -gt 65535 })) {
        Write-Host "[Error] Can not search for ports above 65535. Must be with in the range of 1 to 65535."
        exit 1
    }

    # Get the open ports
    $FoundPorts = $(
        Get-NetTCPConnection | Select-Object @(
            'LocalAddress'
            'LocalPort'
            'State'
            @{Name = "Protocol"; Expression = { "TCP" } }
            'OwningProcess'
            @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
        )
        Get-NetUDPEndpoint | Select-Object @(
            'LocalAddress'
            'LocalPort'
            @{Name = "State"; Expression = { "None" } }
            @{Name = "Protocol"; Expression = { "UDP" } }
            'OwningProcess'
            @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
        )
    ) | Where-Object {
        $(
            <# When Ports are specified select just those ports. #>
            if ($Ports) { $_.LocalPort -in $Ports }else { $true }
        ) -and
        (
            <# Filter out anything that isn't listening or established. #>
            $(
                $_.Protocol -eq "TCP" -and
                $(
                    $_.State -eq "Listen" -or
                    $_.State -eq "Established"
                )
            ) -or
            <# UDP is stateless, return all UDP connections. #>
            $_.Protocol -eq "UDP"
        )
    } | Sort-Object LocalPort | Select-Object * -Unique

    if (-not $FoundPorts -or $FoundPorts.Count -eq 0) {
        Write-Host "[Info] No ports were found listening or established with the specified: $PortsToCheck"
    }

    # Output the found ports
    $FoundPorts | ForEach-Object {
        Write-Host "[Alert] Found open port: $($_.LocalPort), PID: $($_.OwningProcess), Protocol: $($_.Protocol), State: $($_.State), Local IP: $($_.LocalAddress), Process: $($_.Process)"
    }
    # Save the results to a custom field if one was provided
    if ($CustomFieldName -and $CustomFieldName -ne 'null') {
        try {
            Write-Host "[Info] Saving results to custom field: $CustomFieldName"
    # Set-NinjaProperty -Name $CustomFieldName -Value $( # Removed NinjaOne dependency
                $FoundPorts | ForEach-Object {
                    "Open port: $($_.LocalPort), PID: $($_.OwningProcess), Protocol: $($_.Protocol), State: $($_.State), Local Address: $($_.LocalAddress), Process: $($_.Process)"
                } | Out-String
            )
            Write-Host "[Info] Results saved to custom field: $CustomFieldName"
        }
        catch {
            Write-Host $_.Exception.Message
            Write-Host "[Warn] Failed to save results to custom field: $CustomFieldName"
            exit 1
        }
    }
}
end {
    
    
    
}
