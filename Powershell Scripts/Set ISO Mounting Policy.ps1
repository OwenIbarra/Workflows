# Enables or disables the mounting of ISO images.
#Requires -Version 5.1

<#
.SYNOPSIS
    Enables or disables the mounting of ISO images.
.DESCRIPTION
    Enables or disables the mounting of ISO images.
.EXAMPLE
     -Enable
    Enables mounting of ISO images.
.EXAMPLE
     -Disable
    Disables mounting of ISO images.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $Enable,
    [Parameter()]
    [switch]
    $Disable
)

begin {
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
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    if ($env:Action -like "Enable") {
        $Enable = $true
    }
    elseif ($env:Action -like "Disable") {
        $Disable = $true
    }

    # Use a unique number that isn't likely to be used
    # "ninja" to something close to a number plus 1 at the end: "41470" + "1"
    $GroupName = "414701"

    # Mount HKEY_CLASSES_ROOT as HKCR: for the current session
    New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR

    if ($Enable -and $Disable) {
        Write-Error "Both Enable and Disable can not be used at the same time."
        exit 1
    }
    elseif ($Enable) {
        # Enables the use of ISO mounting by removing registry settings

        # ErrorAction set to SilentlyContinue for when the registry settings don't exist
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name "$GroupName" -ErrorAction SilentlyContinue
        Write-Host "Removed $GroupName from HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"

        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -ErrorAction SilentlyContinue
        Write-Host "Removed DenyDeviceIDsRetroactive from HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"

        Remove-ItemProperty -Path "HKCR:\Windows.IsoFile\shell\mount" -Name "ProgrammaticAccessOnly" -ErrorAction SilentlyContinue
        Write-Host "Removed ProgrammaticAccessOnly from HKCR:\Windows.IsoFile\shell\mount"
    }
    elseif ($Disable) {
        # Disables the use of ISO mounting by creating registry settings

        Set-ItemProp -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs" -Name "$GroupName" -Value "SCSI\CdRomMsft____Virtual_DVD-ROM_" -PropertyType String
        Set-ItemProp -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceIDsRetroactive" -Value "1" -PropertyType DWord
        Set-ItemProp -Path "HKCR:\Windows.IsoFile\shell\mount" -Name "ProgrammaticAccessOnly" -Value "" -PropertyType String
    }
    else {
        Write-Error "Enable or Disable is required."
        exit 1
    }
    Write-Host "Any logged in users will need to log out and back in for changes to take effect."
}
end {
    
    
    
}

