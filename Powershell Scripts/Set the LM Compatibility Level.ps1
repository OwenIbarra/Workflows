# Set the LM and NTLMv1 authentication responses via LmCompatibilityLevel in the registry
#Requires -Version 5.1

<#
.SYNOPSIS
    Set the LM and NTLMv1 authentication responses via LmCompatibilityLevel in the registry
.DESCRIPTION
    Set the LM and NTLMv1 authentication responses via LmCompatibilityLevel in the registry
.EXAMPLE
    No parameters needed.
    Sets LAN Manager auth level to 5, "Send NTLMv2 response only. Refuse LM & NTLM."
.EXAMPLE
     -LmCompatibilityLevel 5
    Sets LAN Manager auth level to 5, "Send NTLMv2 response only. Refuse LM & NTLM."
.EXAMPLE
     -LmCompatibilityLevel 3
    Sets LAN Manager auth level to 3, "Send NTLMv2 response only."
    This is the default from Windows 7 and up.
.EXAMPLE
    PS C:\> Disable-LmNtlmV1.ps1 -LmCompatibilityLevel 5
    Sets LAN Manager auth level to 5, "Send NTLMv2 response only. Refuse LM & NTLM."
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Reference chart: https://ss64.com/nt/syntax-ntlm.html
    Release Notes: Renamed script and added Script Variable support, updated Set-ItemProp
.COMPONENT
    ProtocolSecurity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$LmCompatibilityLevel = 5
)

begin {
    if ($env:lmCompatibilityLevel -and $env:lmCompatibilityLevel -notlike "null") {
        $LmCompatibilityLevel = switch ($env:lmCompatibilityLevel) {
            "Send NTLMv2 Response Only and Refuse LM and NTLM" { 5 }
            "Send NTLMv2 Response Only and Refuse LM" { 4 }
            "Send NTLMv2 Response Only" { 3 }
            "Send LM and NTLM and Use NTMLv2 if Negotiated" { 2 }
            "Send LM and NTLM" { 1 }
        }
    }

    if ($LmCompatibilityLevel -lt 0 -or $LmCompatibilityLevel -gt 5) {
        Write-Error "Lm Compatibility Level needs to be between 0 and 5 (including 0 and 5)!"
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
    $Path = @(
        "HKLM:\SYSTEM\CurrentControlSet\Services\Lsa"
        "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
    )
    $Name = "LmCompatibilityLevel"
    # $Value = $LmCompatibilityLevel
    # Sets LmCompatibilityLevel to $LmCompatibilityLevel
    try {
        $Path | ForEach-Object {
            Set-ItemProp -Path $_ -Name $Name -Value $LmCompatibilityLevel
        }
        
    }
    catch {
        Write-Error $_
        exit 1
    }
    $Path | ForEach-Object {
        $Value = Get-ItemPropertyValue -Path $_ -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $Value) {
            Write-Host "$_\$Name set to: OS's default value(3)."
        }
        else {
            Write-Host "$_\$Name set to: $Value"
        }
    }
}
end {
    
    
    
}


