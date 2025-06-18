# Enable or Disable LLMNR(DNS MultiCast) via local group policy.
#Requires -Version 5.1

<#
.SYNOPSIS
    Enable or Disable LLMNR(DNS MultiCast) via local group policy.
.DESCRIPTION
    Enable or Disable LLMNR(DNS MultiCast) via local group policy.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##

PARAMETER: (No Parameters)
    Disables LLMNR
.EXAMPLE
    -Enable
    ## EXAMPLE OUTPUT WITH Enable ##
    Enables LLMNR
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [switch]$Enable
)

begin {
    if ($env:action -and $env:action -notlike "null") {
        switch ($env:action) {
            "Enable LLMNR" { $Enable = $True }
            "Disable LLMNR" { $Enable = $False }
        }
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
        if (-not $(Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
            # Check if path does not exist and create the path
            New-Item -Path $Path -Force | Out-Null
        }
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name)"
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    
    try {
        Set-RegKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMultiCast -Value $(if ($Enable) { 1 }else { 0 }) -PropertyType DWord
    }
    catch {
        Write-Error $_
        Write-Host "Failed to set LLMNR."
        exit 1
    }
    Write-Host "LLMNR(DNS MultiCast) was set to $(if ($Enable) { 1 }else { 0 })"
    exit 0
}
end {
    
    
    
}
