# Alert on specified addresses that are Listening or Established and optionally save the results to a custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Alert on specified addresses that are Listening or Established and optionally save the results to a custom field.
.DESCRIPTION
    Will alert on addresses, regardless if a firewall is blocking them or not.
    Checks for addresses that are in a 'Listen' or 'Established' state.
    UDP is a stateless protocol and will not have a state.
    Outputs the addresses, process ID, state, protocol, local address, and process name.
    When a Custom Field is provided this will save the results to that custom field.

PARAMETER: -IpAddress "192.168.11.1, 192.168.1.1/24"
    A comma separated list of IP Addresses to check. Can include IPv4 CIDR notation for ranges. IPv6 CIDR notation not supported. (e.g. 192.168.1.0/24, 10.0.10.12)
.EXAMPLE
    -IpAddress "192.168.1.0/24, 10.0.10.12"
    ## EXAMPLE OUTPUT WITH IpAddress ##
    [Info] Valid IP Address: 192.168.11.1
    [Info] Valid IP Network: 192.168.1.1/24
    [Alert] Found Local Address: 192.168.1.18, Local Port: 139, Remote Address: 0.0.0.0, Remote Port: None, PID: 4, Protocol: TCP, State: Listen, Process: System
    [Alert] Found Local Address: 192.168.1.18, Local Port: 138, Remote Address: None, Remote Port: None, PID: 4, Protocol: UDP, State: None, Process: System
    [Alert] Found Local Address: 192.168.1.18, Local Port: 137, Remote Address: None, Remote Port: None, PID: 4, Protocol: UDP, State: None, Process: System

PARAMETER: -CustomField "ReplaceMeWithAnyMultilineCustomField"
    Name of the custom field to save the results to.
.EXAMPLE
    -IpAddress "192.168.11.1, 192.168.1.1/24" -CustomField "ReplaceMeWithAnyMultilineCustomField"
    ## EXAMPLE OUTPUT WITH CustomField ##
    [Info] Valid IP Address: 192.168.11.1
    [Info] Valid IP Network: 192.168.1.1/24
    [Alert] Found Local Address: 192.168.1.18, Local Port: 139, Remote Address: 0.0.0.0, Remote Port: None, PID: 4, Protocol: TCP, State: Listen, Process: System
    [Alert] Found Local Address: 192.168.1.18, Local Port: 138, Remote Address: None, Remote Port: None, PID: 4, Protocol: UDP, State: None, Process: System
    [Alert] Found Local Address: 192.168.1.18, Local Port: 137, Remote Address: None, Remote Port: None, PID: 4, Protocol: UDP, State: None, Process: System
    
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
    [String]$IpAddress,
    [String]$CustomFieldName
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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
    
        $Characters = $Value | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 10000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than 10,000 characters.")
        }
        
        # If we're requested to set the field value for a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # This is a list of valid fields that can be set. If no type is given, it will be assumed that the input doesn't need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # The field below requires additional information to be set
        $NeedsOptions = "Dropdown"
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # If an error is received it will have an exception property, the function will exit with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
        
        # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the  Date-Time to be in Unix Epoch time so we'll convert it here.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
        
                if (-not $Selection) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown")
                }
        
                $NinjaValue = $Selection
            }
            default {
                # All the other types shouldn't require additional work on the input.
                $NinjaValue = $Value
            }
        }
        
        # We'll need to set the field differently depending on if its a field in a Ninja Document or not.
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
    function Test-IPNetwork {
        param([string]$Text)
        $Ip, $Prefix = $Text -split '/'
        $Ip -as [System.Net.IPAddress] -and
        $Prefix -as [int] -and $Prefix -ge 0 -and $Prefix -le 32
    }
    function Get-IPNetwork {
        [CmdletBinding()]
    
        Param(
            [Parameter(Mandatory, Position = 0)]
            [ValidateScript({ $_ -eq ([IPAddress]$_).IPAddressToString })]
            [string]$IPAddress,
    
            [Parameter(Mandatory, Position = 1, ParameterSetName = "SubnetMask")]
            [ValidateScript({ $_ -eq ([IPAddress]$_).IPAddressToString })]
            [ValidateScript({
                    $SMReversed = [IPAddress]$_
                    $SMReversed = $SMReversed.GetAddressBytes()
                    [array]::Reverse($SMReversed)
                    [IPAddress]$SMReversed = $SMReversed
                    [convert]::ToString($SMReversed.Address, 2) -match "^[1]*0{0,}$"
                })]
            [string]$SubnetMask,
    
            [Parameter(Mandatory, Position = 1, ParameterSetName = "CIDRNotation")]
            [ValidateRange(0, 32)]
            [int]$PrefixLength,
    
            [switch]$ReturnAllIPs
        )
    
        [IPAddress]$IPAddress = $IPAddress
    
        if ($SubnetMask) {
            [IPAddress]$SubnetMask = $SubnetMask
            $SMReversed = $SubnetMask.GetAddressBytes()
            [array]::Reverse($SMReversed)
            [IPAddress]$SMReversed = $SMReversed
    
            [int]$PrefixLength = [convert]::ToString($SMReversed.Address, 2).replace(0, '').length
        } 
        else {
            [IPAddress]$SubnetMask = ([Math]::Pow(2, $PrefixLength) - 1) * [Math]::Pow(2, (32 - $PrefixLength))
        }
    
        
        $FullMask = [UInt32]'0xffffffff'
        $WildcardMask = [IPAddress]($SubnetMask.Address -bxor $FullMask)
        $NetworkId = [IPAddress]($IPAddress.Address -band $SubnetMask.Address)
        $Broadcast = [IPAddress](($FullMask - $NetworkId.Address) -bxor $SubnetMask.Address)
    
        # Used for determining first usable IP Address
        $FirstIPByteArray = $NetworkId.GetAddressBytes()
        [Array]::Reverse($FirstIPByteArray)
    
        # Used for determining last usable IP Address
        $LastIPByteArray = $Broadcast.GetAddressBytes()
        [Array]::Reverse($LastIPByteArray)
    
        # Handler for /31, /30 CIDR prefix values, and default for all others.
        switch ($PrefixLength) {
            31 {
                $TotalIPs = 2
                $UsableIPs = 2
                $FirstIP = $NetworkId
                $LastIP = $Broadcast
                $FirstIPInt = ([IPAddress]$FirstIPByteArray).Address
                $LastIPInt = ([IPAddress]$LastIPByteArray).Address
                break
            }
    
            32 {
                $TotalIPs = 1
                $UsableIPs = 1
                $FirstIP = $IPAddress
                $LastIP = $IPAddress
                $FirstIPInt = ([IPAddress]$FirstIPByteArray).Address
                $LastIPInt = ([IPAddress]$LastIPByteArray).Address
                break
            }
    
            default {
    
                # Usable Address Space
                $TotalIPs = [Math]::pow(2, (32 - $PrefixLength))
                $UsableIPs = $TotalIPs - 2
    
                # First usable IP
                $FirstIPInt = ([IPAddress]$FirstIPByteArray).Address + 1
                $FirstIP = [IPAddress]$FirstIPInt
                $FirstIP = ($FirstIP).GetAddressBytes()
                [Array]::Reverse($FirstIP)
                $FirstIP = [IPAddress]$FirstIP
    
                # Last usable IP
                $LastIPInt = ([IPAddress]$LastIPByteArray).Address - 1
                $LastIP = [IPAddress]$LastIPInt
                $LastIP = ($LastIP).GetAddressBytes()
                [Array]::Reverse($LastIP)
                $LastIP = [IPAddress]$LastIP
            }
        }
    
        $AllIPs = if ($ReturnAllIPs) {
    
            if ($UsableIPs -ge 500000) {
                Write-Host ('[Warn] Generating an array containing {0:N0} IPs, this may take a little while' -f $UsableIPs)
            }
    
            $CurrentIPInt = $FirstIPInt
    
            Do {
                $IP = [IPAddress]$CurrentIPInt
                $IP = ($IP).GetAddressBytes()
                [Array]::Reverse($IP) | Out-Null
                $IP = ([IPAddress]$IP).IPAddressToString
                $IP
    
                $CurrentIPInt++
    
            } While ($CurrentIPInt -le $LastIPInt)
        }
    
    
        $obj = [PSCustomObject]@{
            NetworkId    = ($NetworkId).IPAddressToString
            Broadcast    = ($Broadcast).IPAddressToString
            SubnetMask   = ($SubnetMask).IPAddressToString
            PrefixLength = $PrefixLength
            WildcardMask = ($WildcardMask).IPAddressToString
            FirstIP      = ($FirstIP).IPAddressToString
            LastIP       = ($LastIP).IPAddressToString
            TotalIPs     = $TotalIPs
            UsableIPs    = $UsableIPs
            AllIPs       = $AllIPs
        }
    
        Write-Output $obj
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    if ($env:ipAddress -and $env:ipAddress -ne 'null') {
        $IpAddress = $env:ipAddress
    }
    if ($env:customFieldName -and $env:customFieldName -ne 'null') {
        $CustomFieldName = $env:customFieldName
    }

    # Parse the Addresses to check
    $Addresses = if ($IpAddress) {
        # Validate the IP Address
        $IpAddress -split ',' | ForEach-Object {
            "$_".Trim()
        } | ForEach-Object {
            if (($_ -as [System.Net.IPAddress])) {
                Write-Host "[Info] Valid IP Address: $_"
                [System.Net.IPAddress]::Parse($_)
            }
            elseif ($(Test-IPNetwork $_)) {
                Write-Host "[Info] Valid IP Network: $_"
                $Address, $PrefixLength = $_ -split '/'
                try {
                    Get-IPNetwork -IPAddress $Address -PrefixLength $PrefixLength -ReturnAllIPs | Select-Object -ExpandProperty AllIPs
                }
                catch {
                    Write-Host "[Error] Invalid IP CIDR: $_"
                    exit 1
                }
            }
            else {
                Write-Host "[Error] Invalid IP Address: $_"
                exit 1
            }
        }
    }
    else { $null }

    # Get the open ports
    $FoundAddresses = $(
        Get-NetTCPConnection | Select-Object @(
            'LocalAddress'
            'LocalPort'
            @{Name = "RemoteAddress"; Expression = { if ($_.RemoteAddress) { $_.RemoteAddress }else { "None" } } }
            @{Name = "RemotePort"; Expression = { if ($_.RemotePort) { $_.RemotePort }else { "None" } } }
            'State'
            @{Name = "Protocol"; Expression = { "TCP" } }
            'OwningProcess'
            @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
        )
        Get-NetUDPEndpoint | Select-Object @(
            'LocalAddress'
            'LocalPort'
            @{Name = "RemoteAddress"; Expression = { "None" } }
            @{Name = "RemotePort"; Expression = { "None" } }
            @{Name = "State"; Expression = { "None" } }
            @{Name = "Protocol"; Expression = { "UDP" } }
            'OwningProcess'
            @{Name = "Process"; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
        )
    ) | Where-Object {
        $(
            <# When Addresses are specified select just those addresses. #>
            if ($Addresses) {
                $_.LocalAddress -in $Addresses -or
                $_.RemoteAddress -in $Addresses
            }
            else { $true }
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
    } | Sort-Object LocalAddress, RemoteAddress | Select-Object * -Unique

    if (-not $FoundAddresses -or $FoundAddresses.Count -eq 0) {
        Write-Host "[Info] No Addresses were found listening or established with the specified network or address"
    }

    # Output the found Addresses
    $FoundAddresses | ForEach-Object {
        Write-Host "[Alert] Found Local Address: $($_.LocalAddress), Local Port: $($_.LocalPort), Remote Address: $($_.RemoteAddress), Remote Port: $($_.RemotePort), PID: $($_.OwningProcess), Protocol: $($_.Protocol), State: $($_.State), Process: $($_.Process)"
    }
    # Save the results to a custom field if one was provided
    if ($CustomFieldName -and $CustomFieldName -ne 'null') {
        try {
            Write-Host "[Info] Saving results to custom field: $CustomFieldName"
            Set-NinjaProperty -Name $CustomFieldName -Value $(
                $FoundAddresses | ForEach-Object {
                    "Local Address: $($_.LocalAddress), Local Port: $($_.LocalPort), Remote Address: $($_.RemoteAddress), Remote Port: $($_.RemotePort), PID: $($_.OwningProcess), Protocol: $($_.Protocol), State: $($_.State), Process: $($_.Process)"
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

