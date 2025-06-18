# Disable or Enable Local LM Hash Storage
#Requires -Version 5.1

<#
.SYNOPSIS
    Disable or Enable Local LM Hash Storage
.DESCRIPTION
    Disable or Enable Local LM Hash Storage
.EXAMPLE
    -Enable
    Enable Local LM Hash Storage
.EXAMPLE
    PS C:\> Disable-LMHash.ps1
    Disable Local LM Hash Storage
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support, updated Set-ItemProp
.COMPONENT
    ProtocolSecurity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [switch]$Enable
)

begin {
    if ($env:enableOrDisable -and $env:enableOrDisable -notlike "null") {
        switch ($env:enableOrDisable) {
            "Enable" { $Enable = $True }
            "Disable" { $Enable = $False }
        }
    }
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
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $Name = "NoLMHash"
    $Value = if ($Enable) { 0 }else { 1 }
    # Sets NoLMHash to 1
    try {
        Set-ItemProp -Path $Path -Name $Name -Value $Value
    }
    catch {
        Write-Error $_
        exit 1
    }
    Write-Host "Set $Path\$Name to $Value"
}
end {
    
    
    
}


