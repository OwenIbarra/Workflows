# Enables password on wake from sleep/hibernation.
#Requires -Version 2.0

<#
.SYNOPSIS
    Enables password on wake from sleep/hibernation.
.DESCRIPTION
    Enables password on wake from sleep/hibernation.
.EXAMPLE
    No parameters needed.
    Enables password on wake from sleep/hibernation.
.EXAMPLE
    PS C:\> Set-RequirePasswordOnWake.ps1
    Enables password on wake from sleep/hibernation.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    Release Notes: Renamed script and added Script Variable support, Updated Set-ItemProp
.COMPONENT
    LocalUserAccountManagement
#>

[CmdletBinding()]
param ()

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        { Write-Output $true }
        else
        { Write-Output $false }
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
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    # Require a password when a computer wakes
    $Path = "HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51"
    $ACName = "ACSettingIndex"
    $DCName = "DCSettingIndex"
    $Enable = "1"

    # Plugged In
    try {
        Set-ItemProp -Path $Path -Name $ACName -Value $Enable
    }
    catch {
        Write-Error $_
        exit 1
    }
    
    # On Battery
    try {
        Set-ItemProp -Path $Path -Name $DCName -Value $Enable
    }
    catch {
        Write-Error $_
        exit 1
    }
}
end {
    
    
    
}


