# This will get information about the current number of Hyper-V checkpoints there are on a given machine. Can be given a threshold in days to report on, can also get this threshold from an integer custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    This will get information about the current number of Hyper-V checkpoints there are on a given machine. Can be given a threshold in days to report on, can also get this threshold from an integer custom field.
.DESCRIPTION
    This will get information about the current number of Hyper-V checkpoints there are on a given machine. 
    Can be given a threshold in days to report on, can also get this threshold from an integer custom field.

.EXAMPLE 
    (No Parameters)
    WARNING: There are checkpoints older than 04/12/2023 14:01:26!

    VMName              Name                   CreationTime
    ------              ----                   ------------
    SRV16-TEST          Fresh Start            4/12/2023 10:53:14 AM
    SRV16-TEST          Hyper-V Installed      4/12/2023 11:13:09 AM
    SRV19-TEST          Fresh Start            4/12/2023 10:42:44 AM
    SRV22-TEST          Fresh Start            4/12/2023 10:45:02 AM

PARAMETER: -OlderThan "14"
    Alert/Show only vm checkpoints older than x days. 
    ex. "7" will alert/show vm checkpoints older than 7 days.
.EXAMPLE
    -OlderThan "7"
    WARNING: There are checkpoints older than 04/05/2023 14:04:01!
    
    VMName              Name                                                              CreationTime
    ------              ----                                                              ------------
    old WIN10-TEST      Automatic Checkpoint - WIN10-TEST - (3/30/2023 - 3:02:28 PM)      3/30/2023 3:02:28 PM 

PARAMETER: -FromCustomField "ReplaceMeWithAnyIntegerCustomField"
    Name of an integer custom field that contains your desired OlderThan threshold.
    ex. "CheckpointAgeLimit" where you have entered in your desired age limit in the "CheckPointAgeLimit" custom field rather than in a parameter.
.EXAMPLE
    -FromCustomField "ReplaceMeWithAnyIntegerCustomField"
    WARNING: There are checkpoints older than 04/05/2023 14:04:01!
    
    VMName              Name                                                              CreationTime
    ------              ----                                                              ------------
    old WIN10-TEST      Automatic Checkpoint - WIN10-TEST - (3/30/2023 - 3:02:28 PM)      3/30/2023 3:02:28 PM

.OUTPUTS
    
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2016
    Release Notes: Renamed script and added Script Variable support
.COMPONENT
    ManageUsers
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$OlderThan = "0",
    [Parameter()]
    [String]$FromCustomField
)
begin {
    if ($env:ageLimit -and $env:ageLimit -notlike "null") { $OlderThan = $env:ageLimit }
    if ($env:retrieveAgeLimitFromCustomField -and $env:retrieveAgeLimitFromCustomField -notlike "null") { $FromCustomField = $env:retrieveAgeLimitFromCustomField }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    if (!(Test-IsElevated) -and !(Test-IsSystem)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
}
process {

    $Threshold = (Get-Date).AddDays(-$OlderThan)

    if ($FromCustomField) {
        $Threshold = (Get-Date).AddDays( - (Ninja-Property-Get $FromCustomField))
    }
    
    $CheckPoints = Get-VM | Get-VMSnapshot | Where-Object { $_.CreationTime -lt $Threshold }

    if (!$CheckPoints) {
        Write-Host "There are no checkpoints older than $Threshold!"
        exit 0
    }
    else {
        Write-Warning "There are checkpoints older than $Threshold!"
        $Checkpoints | Format-Table -Property VMName, Name, CreationTime | Out-String | Write-Host
        exit 1
    }
}end {
    
    
    
}

