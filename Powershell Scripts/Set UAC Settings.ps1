# Configures UAC.
#Requires -Version 2.0

<#
.SYNOPSIS
    Configures UAC.
.DESCRIPTION
    Configures UAC to defaults if no parameters are specified.
.EXAMPLE
    No parameters needed.
    Sets all UAC settings to Microsoft's defaults.
.EXAMPLE
     -ConsentPromptBehaviorAdmin 5
    Sets ConsentPromptBehaviorAdmin to 5
.EXAMPLE
    PS C:\> Set-Uac.ps1
    Sets all UAC settings to MS defaults.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    This script will show before and after UAC settings.
    Release Notes: Renamed script and added Script Variable support, updated Set-ItemProp
.COMPONENT
    LocalUserAccountManagement
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$ConsentPromptBehaviorAdmin = 5,
    [Parameter()]
    [int]$ConsentPromptBehaviorUser = 3,
    [Parameter()]
    [int]$EnableInstallerDetection = 1,
    [Parameter()]
    [int]$EnableLUA = 1,
    [Parameter()]
    [int]$EnableVirtualization = 1,
    [Parameter()]
    [int]$PromptOnSecureDesktop = 1,
    [Parameter()]
    [int]$ValidateAdminCodeSignatures = 0,
    [Parameter()]
    [int]$FilterAdministratorToken = 0
)

begin {
    if ($env:consentPromptBehaviorAdmin -and $env:consentPromptBehaviorAdmin -notlike "null") {
        $ConsentPromptBehaviorAdmin = switch ($env:consentPromptBehaviorAdmin) {
            "Prompt for consent for non-Windows binaries" { 5 }
            "Prompt for consent" { 4 }
            "Prompt for credentials" { 3 }
            "Prompt for consent on the secure desktop" { 2 }
            "Prompt for credentials on the secure desktop" { 1 }
            "Elevate without prompting" { 0 }
        }
    }
    if ($env:consentPromptBehaviorUser -and $env:consentPromptBehaviorUser -notlike "null") {
        $ConsentPromptBehaviorUser = switch ($env:consentPromptBehaviorUser) {
            "Prompt for credentials" { 3 }
            "Prompt for credentials on the secure desktop" { 1 }
            "Automatically deny elevation requests" { 0 }
        }
    }
    if ($env:enableInstallerDetection -and $env:enableInstallerDetection -notlike "null") {
        $EnableInstallerDetection = if ([System.Convert]::ToBoolean($env:enableInstallerDetection)) { 1 }else { 0 }
    }
    if ($env:enableLua -and $env:enableLua -notlike "null") {
        $EnableLUA = if ([System.Convert]::ToBoolean($env:enableLua)) { 1 }else { 0 }
    }
    if ($env:enableVirtualization -and $env:enableVirtualization -notlike "null") {
        $EnableVirtualization = if ([System.Convert]::ToBoolean($env:enableVirtualization)) { 1 }else { 0 }
    }
    if ($env:promptOnSecureDesktop -and $env:promptOnSecureDesktop -notlike "null") {
        $PromptOnSecureDesktop = if ([System.Convert]::ToBoolean($env:promptOnSecureDesktop)) { 1 }else { 0 }
    }
    if ($env:validateAdminCodeSignatures -and $env:validateAdminCodeSignatures -notlike "null") {
        $ValidateAdminCodeSignatures = if ([System.Convert]::ToBoolean($env:validateAdminCodeSignatures)) { 1 }else { 0 }
    }
    if ($env:filterAdministratorToken -and $env:filterAdministratorToken -notlike "null") {
        $FilterAdministratorToken = if ([System.Convert]::ToBoolean($env:filterAdministratorToken)) { 1 }else { 0 }
    }

    if ($ConsentPromptBehaviorAdmin -gt 5 -or $ConsentPromptBehaviorAdmin -lt 0) {
        Write-Error "Consent Prompt Behavior Admin needs to be between 0 and 5 (including 0 and 5)."
        exit 1
    }

    if ($ConsentPromptBehaviorUser -gt 3 -or $ConsentPromptBehaviorUser -lt 0) {
        Write-Error "Consent Prompt Behavior User needs to be between 0 and 3 (including 0 and 3)."
        exit 1
    }

    if ($EnableInstallerDetection -gt 1 -or $EnableInstallerDetection -lt 0) {
        Write-Error "Enable Installer Detection needs to be between 0 and 1 (including 0 and 1)."
        exit 1
    }

    if ($EnableLUA -gt 1 -or $EnableLUA -lt 0) {
        Write-Error "Enable Lua needs to be between 0 and 1 (including 0 and 1)."
        exit 1
    }

    if ($EnableVirtualization -gt 1 -or $EnableVirtualization -lt 0) {
        Write-Error "Enable Virtualization needs to be between 0 and 1 (including 0 and 1)."
        exit 1
    }

    if ($PromptOnSecureDesktop -gt 1 -or $PromptOnSecureDesktop -lt 0) {
        Write-Error "Prompt on Secure Desktop needs to be between 0 and 1 (including 0 and 1)."
        exit 1
    }

    if ($ValidateAdminCodeSignatures -gt 1 -or $ValidateAdminCodeSignatures -lt 0) {
        Write-Error "Validate Admin Code Signatures needs to be between 0 and 1 (including 0 and 1)."
        exit 1
    }

    if ($FilterAdministratorToken -gt 1 -or $FilterAdministratorToken -lt 0) {
        Write-Error "Filter Administrator Tokens needs to be between 0 and 1 (including 0 and 1)."
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
            $CurrentValue = Get-ItemProperty -Path $Path -Name $Name | Select-Object -ExpandProperty $Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error $_
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $(Get-ItemProperty -Path $Path -Name $Name | Select-Object -ExpandProperty $Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error $_
            }
            Write-Host "Set $Path\$Name to $(Get-ItemProperty -Path $Path -Name $Name | Select-Object -ExpandProperty $Name)"
        }
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $filter = "ConsentPromptBehaviorAdmin|ConsentPromptBehaviorUser|EnableInstallerDetection|EnableLUA|EnableVirtualization|PromptOnSecureDesktop|ValidateAdminCodeSignatures|FilterAdministratorToken"

    try {
        $filter -split '\|' | ForEach-Object {
            Set-ItemProp -Path $Path -Name $_ -Value (Get-Variable -Name $_).Value
        }
    }
    catch {
        Write-Error $_
        exit 1
    }

    (Get-ItemProperty $path).psobject.properties | Where-Object { $_.name -match $filter } | Select-Object name, value
}
end {
    
    
    
}


