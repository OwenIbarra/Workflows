# Enable or disable components for IPv6 on all network connections.
#Requires -Version 5.1

<#
.SYNOPSIS
    Enable or disable components for IPv6 on all network connections.
.DESCRIPTION
    Enable or disable components for IPv6 on all network connections.
    Rebooting is required for Windows to apply these settings.
.EXAMPLE
     -Components DisableAll
    Disables all IPv6 components.
.EXAMPLE
    PS C:\> Disable-IPv6.ps1 -ComponentsValue 0xFF
    Disables all IPv6 components from custom value.
    See link for more options:
    https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows
.EXAMPLE
     -Components EnableAll
    Enables all IPv6 components.
.EXAMPLE
     -Components DisableAllTunnels
    Disables all IPv6 Tunnels.
.EXAMPLE
     -Components DisableAllTunnels, Disable6to4
    Disables All IPv6 Tunnels and 6to4 components.
.EXAMPLE
    PS C:\> Disable-IPv6.ps1 -Components DisableAll
    Disables all IPv6 components.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated calculated name
.COMPONENT
    ProtocolSecurity
#>

[CmdletBinding(DefaultParameterSetName = "Components")]
param (
    [Parameter(Mandatory = $false, ParameterSetName = "Components")]
    [ValidateSet("EnableAll", "DisableAllTunnels", "Disable6to4", "DisableISATAP", "DisableTeredo", "PreferIPv4Over", "DisableAll")]
    [string[]]
    $Components,
    [Parameter(Mandatory = $false, ParameterSetName = "Value")]
    [ValidateRange(0, 255)]
    [int]
    $ComponentsValue
)

begin {
    $DisableValue = 0
    if (
        $env:enableAll -like "true" -or
        $env:disableAllTunnels -like "true" -or
        $env:disable6To4 -like "true" -or
        $env:disableIsatap -like "true" -or
        $env:disableTeredo -like "true" -or
        $env:preferIpv4Over -like "true" -or
        $env:disableAll -like "true"
    ) {
        $Components = [System.Collections.Generic.List[String]]::new()
        if ($env:enableAll -like "true") { $DisableValue = $DisableValue -bor 0 }
        if ($env:disableAllTunnels -like "true") { $DisableValue = $DisableValue -bor 0x01 }
        if ($env:disable6To4 -like "true") { $DisableValue = $DisableValue -bor 0x02 }
        if ($env:disableIsatap -like "true") { $DisableValue = $DisableValue -bor 0x04 }
        if ($env:disableTeredo -like "true") { $DisableValue = $DisableValue -bor 0x08 }
        if ($env:preferIpv4Over -like "true") { $DisableValue = $DisableValue -bor 0x20 }
        if ($env:disableAll -like "true") { $DisableValue = $DisableValue -bor 0xFF }
    }
    elseif ($Components) {
        # Define values for names in $Components
        $EnableAll = 0
        $DisableAllTunnels = 0x01
        $Disable6to4 = 0x02
        $DisableISATAP = 0x04
        $DisableTeredo = 0x08
        $PreferIPv4Over = 0x20
        $DisableAll = 0xFF

        # Create bit "list" and start at 0
        $DisableValue = 0
        $Components | ForEach-Object {
            # Add each item in $Components to $DisableList with bitwise-or operation
            $DisableValue = $DisableValue -bor $(Get-Variable -Name $_ -ValueOnly)
        }
    }
    elseif ($ComponentsValue) {
        $DisableValue = $ComponentsValue
    }
    else {
        Write-Error "No option selected or parameter specified."
        exit 1
    }
    function Set-ItemProp {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
        # Do not output errors and continue
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        if (-not $(Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            New-Item -Path $Path -Force | Out-Null
        }
        if ((Get-ItemProperty -Path $Path -Name $Name)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = Get-ItemProperty -Path $Path -Name $Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error $_
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $(Get-ItemProperty -Path $Path -Name $Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error $_
            }
            Write-Host "Set $Path$Name to $(Get-ItemProperty -Path $Path -Name $Name)"
        }
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        { Write-Output $true }
        else
        { Write-Output $false }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $Name = "DisabledComponents"
    $Value = $DisableValue
    try {
        Set-ItemProp -Path $Path -Name $Name -Value $Value
    }
    catch {
        Write-Error $_
        exit 1
    }
}
end {
    
    
    
}


