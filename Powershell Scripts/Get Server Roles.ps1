# Retrieves the installed server roles.
#Requires -Version 4.0

<#
.SYNOPSIS
    Retrieves the installed server roles.
.DESCRIPTION
    Retrieves the installed server roles.

    For Exchange and SQL, this just detects if the services are installed.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    DisplayName                      FeatureType Installed PostConfigurationNeeded
    -----------                      ----------- --------- -----------------------
    Active Directory Domain Services Role             True                   False
    DNS Server                       Role             True                   False
    File and Storage Services        Role             True                   False

PARAMETER: -CustomField "Roles"
    Saves the results to a multi-line custom field.
.EXAMPLE
    -CustomField "Roles"
    ## EXAMPLE OUTPUT WITH CustomField ##
    DisplayName                      FeatureType Installed PostConfigurationNeeded
    -----------                      ----------- --------- -----------------------
    Active Directory Domain Services Role             True                   False
    DNS Server                       Role             True                   False
    File and Storage Services        Role             True                   False

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Server 2012
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [string]
    $CustomField
)

begin {
    if ($env:customfield -notlike "null" -and $env:customfield) {
        $CustomField = $env:customfield
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

    $SQLServices = Get-Service | Where-Object { $_.DisplayName -like "SQL Server*" }
    $ExchangeServices = Get-Service -Name MSExchangeServiceHost -ErrorAction SilentlyContinue
    $InstalledFeatures = Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -like "Role" } | Select-Object -Property DisplayName, FeatureType, Installed, PostConfigurationNeeded
    $InstalledFeatures = if ($SQLServices) {
        $InstalledFeatures
        [PSCustomObject]@{
            DisplayName             = "SQL Server"
            FeatureType             = "Role"
            Installed               = $true
            PostConfigurationNeeded = $null
        }
    }
    else { $InstalledFeatures }
    $InstalledFeatures = if ($ExchangeServices) {
        $InstalledFeatures
        [PSCustomObject]@{
            DisplayName             = "Exchange Server"
            FeatureType             = "Role"
            Installed               = $true
            PostConfigurationNeeded = $null
        }
    }
    else { $InstalledFeatures }

    $InstalledFeatures | Format-Table -AutoSize | Out-String | Write-Host

    if ($CustomField) {
        Ninja-Property-Set -Name $CustomField -Value $($InstalledFeatures.DisplayName | Out-String)
    }
}
end {
    
    
    
}
