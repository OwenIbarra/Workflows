# Retrieves details regarding the devices Microsoft Entra/Azure AD connection status.
#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieves details regarding the device's Microsoft Entra/Azure AD connection status.
.DESCRIPTION
    Retrieves details regarding the device's Microsoft Entra/Azure AD connection status.
.EXAMPLE
    (No Parameters)
    
    Join Type: Microsoft Entra Joined

    Tenant Name Tenant ID                            Device Name     Device ID                           
    ----------- ---------                            -----------     ---------                           
    NinjaOne    0e0adb39-f83f-4576-9102-db1b902ca108 KYLE-WIN11-TEST 59fd69ed-4893-41df-9f7d-211d5a0a8986

PARAMETER: -DeviceStateCustomFieldName "ReplaceMe"
    Name of a custom field to store the device state (Microsoft Entra Joined, Domain Joined etc...) in. E.g., deviceState

PARAMETER: -TenantInfoCustomFieldName "ReplaceMe"
    Name of a custom field to store tenant info in. E.g., azureInfo.

.OUTPUTS
    None
.NOTES
    Minimum Supported OS: Windows 10+
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$DeviceStateCustomFieldName,
    [Parameter()]
    [String]$TenantInfoCustomFieldName
)

begin {
    # Retrieve custom field name from dynamic script form
    if ($env:joinTypeCustomFieldName -and $env:joinTypeCustomFieldName -notlike "null") { $DeviceStateCustomFieldName = $env:joinTypeCustomFieldName }
    if ($env:tenantInfoCustomFieldName -and $env:tenantInfoCustomFieldName -notlike "null") { $TenantInfoCustomFieldName = $env:tenantInfoCustomFieldName }

    # Turn dsregcmd.exe /status into a much more parseable PowerShell object
    function Get-DSRegCMD {
        $DSReg = dsregcmd.exe /status | Where-Object { $_ -match " : " }

        $properties = @{}

        $DSReg | ForEach-Object {
            $split = ($_ -split '\s:\s').trim()
            $properties[$split[0]] = $split[1]
        }

        [PSCustomObject]$properties
    }
}
process {
    # Retrieve current Azure AD information
    $AzureInfo = Get-DSRegCMD

    $JoinType = if ($AzureInfo.AzureAdJoined -eq "YES" -and $AzureInfo.DomainJoined -eq "NO" -and $AzureInfo.EnterpriseJoined -eq "NO") {
        "Microsoft Entra Joined"
    }
    elseif ($AzureInfo.AzureAdJoined -eq "NO" -and $AzureInfo.DomainJoined -eq "YES" -and $AzureInfo.EnterpriseJoined -eq "NO") {
        "Domain Joined"
    }
    elseif ($AzureInfo.AzureAdJoined -eq "YES" -and $AzureInfo.DomainJoined -eq "YES" -and $AzureInfo.EnterpriseJoined -eq "NO") {
        "Microsoft Entra Hybrid Joined"
    }
    elseif ($AzureInfo.AzureAdJoined -eq "NO" -and $AzureInfo.DomainJoined -eq "YES" -and $AzureInfo.EnterpriseJoined -eq "YES") {
        "On-Premises DRS Joined"
    }
    else {
        "None"
    }

    # Retrieve the most relevant information
    $TenantInfo = [PSCustomObject]@{
        "Tenant Name" = $AzureInfo.TenantName
        "Tenant ID"   = $AzureInfo.TenantId
        "Device Name" = $AzureInfo."Device Name"
        "Device ID"   = $AzureInfo.DeviceId
    }

    # Report results into the activity log
    Write-Host "Join Type: $JoinType"
    $TenantInfo | Format-Table | Out-String | Write-Host

    # Store results into a custom field
    if($DeviceStateCustomFieldName -eq $TenantInfoCustomFieldName -and $DeviceStateCustomFieldName){
        $TenantInfo | Add-Member -MemberType NoteProperty -Name 'Join Type' -Value $JoinType

        Ninja-Property-Set -Name $DeviceStateCustomFieldName -Value ($TenantInfo | Format-List -Property "Tenant Name","Tenant ID","Join Type","Device Name","Device ID" | Out-String)
        exit 0
    }

    if ($DeviceStateCustomFieldName) {
        Ninja-Property-Set -Name $DeviceStateCustomFieldName -Value ($JoinType)
    }

    if ($TenantInfoCustomFieldName) {
        Ninja-Property-Set -Name $TenantInfoCustomFieldName -Value ($TenantInfo | Format-List | Out-String)
    }
}
end {
    
    
    
}
