# Enables or Disables RDP for workstations only.
<#
.SYNOPSIS
    Enables or Disables RDP for workstations only.
.DESCRIPTION
    Enables or Disables RDP for workstations only.
.EXAMPLE
    -Disable
    Disables RDP for a workstation.
.EXAMPLE
    -Enable
    Enables RDP for a workstation.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Renamed script and added Script Variable support
#>
[CmdletBinding(DefaultParameterSetName = "Disable")]
param (
    [Parameter(ParameterSetName = "Enable")]
    [switch]$Enable,
    [Parameter(ParameterSetName = "Disable")]
    [switch]$Disable
)

begin {
    if ($env:action -and $env:action -notlike "null") {
        switch ($env:action) {
            "Enable" { $Enable = $True }
            "Disable" { $Disable = $True }
        }
    }

    if ($false -eq $Disable -and $false -eq $Enable) {
        Write-Host "Enable or Disable Parameters are required."
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
            Write-Host "$Path\$Name changed from $CurrentValue to $Value"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error $_
            }
            Write-Host "Set $Path\$Name to $Value"
        }
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Registry settings
    $Path = 'HKLM:\SYSTEM\CurRentControlSet\Control\Terminal Server'
    $Name = "fDenyTSConnections"
    $RegEnable = 0
    $RegDisable = 1

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $IsWorkstation = if ($osInfo.ProductType -eq 1) {
        $true
    }
    else {
        $false
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    if (-not $IsWorkstation) {
        # System is a Domain Controller or Server
        Write-Error "System is a Domain Controller or Server. Skipping."
        exit 1
    }

    # Registry
    if ($Disable) {
        $RegCheck = $null
        $RegCheck = $(Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue)
        if ($null -eq $RegCheck) {
            $RegCheck = 0
        }
        if ($RegDisable -ne $RegCheck) {
            Set-ItemProp -Path $Path -Name $Name -Value $RegDisable
            Write-Host "Disabled $Path\$Name"
        }
        else {
            Write-Host "$Path\$Name already Disabled."
        }
    }
    elseif ($Enable) {
        $RegCheck = $null
        $RegCheck = $(Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction SilentlyContinue)
        if ($null -eq $RegCheck) {
            $RegCheck = 0
        }
        if ($RegEnable -ne $RegCheck) {
            Set-ItemProp -Path $Path -Name $Name -Value $RegEnable
            Write-Host "Enabled $Path\$Name"
        }
        else {
            Write-Host "$Path\$Name already Enabled."
        }
    }
    else {
        Write-Error "Enable or Disable was not specified."
        exit 1
    }

    # Firewall
    if ($Disable) {
        # Disable if was enabled and Disable was used
        try {
            Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Host "Remote Desktop firewall group is missing?"
        }
        Write-Host "Disabled Remote Desktop firewall rule groups."
    }
    elseif ($Enable) {
        # Enable if was disabled and Enable was used
        try {
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Host "Remote Desktop firewall group is missing?"
        }
        Write-Host "Enabled Remote Desktop firewall rule groups."
    }
    else {
        Write-Error "Enable or Disable was not specified."
        exit 1
    }
}
end {
    
    
    
}


