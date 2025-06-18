# Disables or Enables NETBIOS on all network adapters
#Requires -Version 2.0

<#
.SYNOPSIS
    Disables or Enables NETBIOS on all network adapters
.DESCRIPTION
    Disables or Enables NETBIOS on all network adapters
.EXAMPLE
    No parameters needed.
    Sets the default of "Use NetBIOS setting from the DHCP server" on all network adapters
.EXAMPLE
    -Disable
    Disables NETBIOS on all network adapters
.EXAMPLE
    -Enable
    Enables NETBIOS on all network adapters
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012
    Release Notes: Renamed script and added Script Variable support
.COMPONENT
    ProtocolSecurity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [switch]$Enable,
    [Parameter()]
    [switch]$Disable
)

begin {
    if ($env:action -and $env:action -notlike "null") {
        switch ($env:action) {
            "Enable" { $Enable = $True }
            "Disable" { $Disable = $True }
        }
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    $NetBios = if ($Enable) {
        # 1 - Enable NetBIOS over TCP/IP
        1
    }
    elseif ($Disable) {
        # 2 - Disable NetBIOS over TCP/IP
        2
    }
    elseif ($Enable -and $Disable) {
        Write-Error "Can not enable and disable at the same time."
        exit 1
    }
    else {
        # 0 - Use NetBIOS setting from the DHCP server
        0
    }

    if ($(Get-Command "Get-CimInstance" -ErrorAction SilentlyContinue).Name -like "Get-CimInstance") {
        $Arguments = @{
            TcpipNetbiosOptions = [UInt32]($NetBios)
        }
        $Session = New-CimSession
        $Query = 'Select * From Win32_NetworkAdapterConfiguration'
        $Response = Invoke-CimMethod -Query $Query -Namespace Root/CIMV2 -MethodName SetTcpipNetbios -Arguments $Arguments -CimSession $Session
        if ($Response.ReturnValue -is [int] -and $Response.ReturnValue -gt 1) {
            # 0 and 1 are success return values
            # https://powershell.one/wmi/root/cimv2/win32_networkadapterconfiguration-SetTcpipNetbios#return-value
            Write-Error "SetTcpipNetbios returned error code ($($Response.ReturnValue))"
            Remove-CimSession -CimSession $Session
            exit 1
        }
        Write-Host "Netbios set to $NetBios"
        Remove-CimSession -CimSession $Session
    }
    else {
        $Adapters = $(Get-WmiObject -Class win32_networkadapterconfiguration)
        Foreach ($Adapter in $Adapters) {
            try {
                $Adapter.SetTcpipNetbios($NetBios)
            }
            catch {
                # Do nothing if error occurs
            }
            $Adapter | Select-Object Description, TcpipNetbiosOptions
        }
    }
}
end {
    
    
    
}


