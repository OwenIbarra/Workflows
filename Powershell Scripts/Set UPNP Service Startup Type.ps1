# Set the startup type for the UPnP Device Host service.
#Requires -Version 5.1

<#
.SYNOPSIS
    Set the startup type for the UPnP Device Host service.
.DESCRIPTION
    Set the startup type for the UPnP Device Host service.
.EXAMPLE
    No parameters needed.
    Disables UPnP Host service.
.EXAMPLE
     -StartupType Automatic
    Enables UPnP Host service.
.EXAMPLE
    PS C:\> Set-Upnp.ps1 -StartupType Automatic
    Enables UPnP Host service.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated Calculated Name
.COMPONENT
    OSSecurity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet("Boot", "Automatic", "Manual", "Disabled")]
    [String]
    $StartupType = "Disabled"
)

begin {
    if ($env:StartupType) {
        $StartupType = $env:StartupType
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
    try {
        Set-Service -Name "upnphost" -StartupType $StartupType
    }
    catch {
        Write-Error $_
        exit 1
    }
    if ($(Get-Service -Name "upnphost" | Select-Object -ExpandProperty StartType) -like $StartupType) {
        Write-Host "[Info] Set UPNP start up type to $StartupType"
    }
    else {
        Write-Host "[Error] Failed to set UPNP start up type to $StartupType"
        exit 1
    }
}
end {
    
    
    
}


