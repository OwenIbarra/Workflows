# Enable or disable all Windows Firewall profiles(Domain, Public, Private).
#Requires -Version 5.1

<#
.SYNOPSIS
    Enable or disable all Windows Firewall profiles(Domain, Public, Private).
.DESCRIPTION
    Enable or disable all Windows Firewall profiles(Domain, Public, Private).
.EXAMPLE
     -Disable
    Disables all Windows Firewall profiles(Domain, Public, Private).
.EXAMPLE
     -Enable
    Enables all Windows Firewall profiles(Domain, Public, Private).
.EXAMPLE
     -Enable -BlockAllInbound
    Enables all Windows Firewall profiles(Domain, Public, Private).
    Blocks all inbound traffic on the Domain, Public, Private profiles
.OUTPUTS
    String[]
.OUTPUTS
    PSCustomObject[]
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated Calculated Name
.COMPONENT
    ProtocolSecurity
#>

[CmdletBinding(DefaultParameterSetName = "Enable")]
param (
    [Parameter()]
    [switch]$Enable,
    [Parameter()]
    [switch]$Disable,
    [Parameter()]
    [Switch]$BlockAllInbound = [System.Convert]::ToBoolean($env:BlockAllInbound)
)

begin {
    if ($env:enableOrDisable -and $env:enableOrDisable -notlike "null") {
        switch ($env:enableOrDisable) {
            "Enable" { $Enable = $True }
            "Disable" { $Disable = $True }
        }
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}
process {
    if (-not $(Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    if ($Enable -and $Disable) {
        Write-Error "Can not enable and disable the firewall at the same time."
        exit 1
    }
    if (-not $Enable -and -not $Disable) {
        Write-Error "Nothing to do when Enable or Disable are not used."
        exit 1
    }

    if ($(Get-Command "Get-NetFirewallProfile" -ErrorAction SilentlyContinue).Name -like "Get-NetFirewallProfile") {
        # Use Get-NetFirewallProfile if available
        try {
            $NetFirewallSplat = @{
                Profile     = @("Domain", "Public", "Private")
                Enabled     = $(if ($Enable) { "True" }elseif ($Disable) { "False" })
                ErrorAction = "Stop"
            }
            if ($Enable -and $BlockAllInbound) {
                $NetFirewallSplat.Add('DefaultInboundAction', 'Block')
                $NetFirewallSplat.Add('DefaultOutboundAction', 'Allow')
            }
            Set-NetFirewallProfile @NetFirewallSplat
            
        }
        catch {
            Write-Error $_
            Write-Host "Failed to turn $(if ($Enable) { "on" }elseif ($Disable) { "off" }) the firewall."
            exit 1
        }
        # Proof of work
        Get-NetFirewallProfile -ErrorAction Stop | Format-Table Name, Enabled
    }
    else {
        # Fall back onto netsh
        netsh.exe AdvFirewall set AllProfiles state $(if ($Enable) { "on" }elseif ($Disable) { "off" })
        if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
        netsh.exe AdvFirewall set DomainProfile state $(if ($Enable) { "on" }elseif ($Disable) { "off" })
        if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
        netsh.exe AdvFirewall set PrivateProfile state $(if ($Enable) { "on" }elseif ($Disable) { "off" })
        if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
        netsh.exe AdvFirewall set PublicProfile state $(if ($Enable) { "on" }elseif ($Disable) { "off" })
        if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
        
        if ($Enable -and $BlockAllInbound) {
            try {
                netsh.exe AdvFirewall set DomainProfile FirewallPolicy "BlockInbound,AllowOutbound"
                if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
                netsh.exe AdvFirewall set PrivateProfile FirewallPolicy "BlockInbound,AllowOutbound"
                if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
                netsh.exe AdvFirewall set PublicProfile FirewallPolicy "BlockInbound,AllowOutbound"
                if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
            }
            catch {
                Write-Error $_
                Write-Host "Could not set Block All Inbound Traffic to 1"
            }
        }
        # Proof of work
        netsh.exe AdvFirewall show AllProfiles state
        if ($LASTEXITCODE -gt 0) { exit $LASTEXITCODE }
    }
}
end {
    
    
    
}


