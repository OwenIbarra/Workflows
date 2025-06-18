# Turn on mini dumps if they are off, if other dumps are already enabled do not change the configuration.
<#
.SYNOPSIS
    Turn on mini dumps if they are off, if other dumps are already enabled do not change the configuration.
.DESCRIPTION
    Turn on mini dumps if they are off, if other dumps are already enabled do not change the configuration.
    This will enable the creation of the pagefile, but set to automatically manage by Windows.
    Reboot might be needed.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes:
    Initial Release
#>
[CmdletBinding()]
param ()

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

    # Reference: https://learn.microsoft.com/en-US/troubleshoot/windows-server/performance/memory-dump-file-options
    $Path = "HKLM:\System\CurrentControlSet\Control\CrashControl"
    $Name = "CrashDumpEnabled"
    $CurrentValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue
    $Value = 3

    # If CrashDumpEnabled is set to 0 or doesn't exist then enable mini crash dump
    if ($CurrentValue -eq 0 -and $null -ne $CurrentValue) {
        $PageFile = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name PagingFiles -ErrorAction SilentlyContinue
        if (-not $PageFile) {
            # If the pagefile was not setup, create the registry entry needed to create the pagefile
            try {
                # Enable automatic page management file if disabled to allow mini dump to function
                Set-ItemProp -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name PagingFiles -Value "?:\pagefile.sys" -PropertyType MultiString
            }
            catch {
                Write-Error "Could not create pagefile."
                exit 1
            }
        }
        Set-ItemProp -Path $Path -Name $Name -Value 3
        Write-Host "Reboot might be needed to enable mini crash dump."
    }
    else {
        Write-Host "Crash dumps are already enabled."
    }
    exit 0
}
end {}
