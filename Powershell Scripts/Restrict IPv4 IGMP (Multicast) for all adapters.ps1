# Disable IPv4 IGMP(Multicast) for all network adapters
#Requires -Version 5.1

<#
.SYNOPSIS
    Disable IPv4 IGMP(Multicast) for all network adapters
.DESCRIPTION
    Disable IPv4 IGMP(Multicast) for all network adapters
.EXAMPLE
    -IGMPLevel None
    Disabled sending or receiving IGMP
.EXAMPLE
    -IGMPLevel SendOnly
    Disabled receiving IGMP
.EXAMPLE
    -IGMPLevel All
    Resets IGMP back to the default
.EXAMPLE
    PS C:\> Disable-IGMP.ps1
    No parameters needed.
.OUTPUTS
    None
.NOTES
    Minimum Supported OS: Windows 10, Windows Server 2016+
    Release Notes: Renamed script and added Script Variable support
.COMPONENT
    ProtocolSecurity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$IGMPLevel = "All"
)

begin {

    if ($env:igmpLevel -and $env:igmpLevel -notlike "null") { $IGMPLevel = $env:igmpLevel }
    if ($IGMPLevel -notin @("None", "SendOnly", "All")) {
        Write-Error "IGMP Level must be None, SendOnly, or All."
        exit 1
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
    $Before = Get-NetIPv4Protocol | Select-Object -Property IGMPLevel -ExpandProperty IGMPLevel
    Write-Host "IGMP Level before: $Before"
    Set-NetIPv4Protocol -IGMPLevel $IGMPLevel
    $After = Get-NetIPv4Protocol | Select-Object -Property IGMPLevel -ExpandProperty IGMPLevel
    Write-Host "IGMP Level after: $After"
}
end {
    
    
    
}

