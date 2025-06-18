# Identify if any wired ethernet connections that are running slower than 1 Gbps.
#Requires -Version 5.1

<#
.SYNOPSIS
    Identify if any wired ethernet connections that are running slower than 1 Gbps.
.DESCRIPTION
    Identify if any wired ethernet connections that are running slower than 1 Gbps.
    This can highlight devices that are connected to old hubs/switches or have bad cabling.
.OUTPUTS
    None
.NOTES
    Minimum supported OS: Windows 10, Server 2016
    Release Notes:
    Initial release
#>

[CmdletBinding()]
param ()

process {
    $NetworkAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Virtual -eq $false -and # Filter out any adapter that are Virtual, like VPN's
        $_.Status -like "Up" -and # Filter out any disconnected adapters
        ($_.PhysicalMediaType -like "*802.3*" -or $_.NdisPhysicalMedium -eq 14) -and # Filter out adapters like Wifi
        $_.LinkSpeed -notlike "*Gbps" # Filter out the 1, 2.5, and 10 Gbps network adapters
    }
    $NetworkAdapters | Select-Object Name, InterfaceDescription, Status, LinkSpeed
    if ($NetworkAdapters) {
        exit 1
    }
}
