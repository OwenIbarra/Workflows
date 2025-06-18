# Conditional script that helps determine if an SSD drive is failing or has failed.
#Requires -Version 5.1

<#
.SYNOPSIS
    Conditional script that helps determine if an SSD drive is failing or has failed.
.DESCRIPTION
    Conditional script that helps determine if an SSD drive is failing or has failed.

    A wear % of 100% indicates that the estimated wear level as been reached.

    Do note that some drives don't report all the needed details to the OS.
        This can be caused by a RAID card, settings in the BIOS, or the drive it self.
.PARAMETER WearLevelPercentMax
    The max estimated wear level percentage to fail at.
    The default is 80 %.
.EXAMPLE
     -WearLevelPercentMax 90
    Fail if SSD is found to have used 90% of its estimated wear leveling.
.OUTPUTS
    None
.NOTES
    Minium Supported OS: Windows 10, Server 2016
    Release Notes: Updated Calculated Name
#>

[CmdletBinding()]
param (
    [int]
    $WearLevelPercentMax = 80
)

begin {
    if ($env:WearLevelPercentMax) {
        $WearLevelPercentMax = $env:WearLevelPercentMax
    }
    function Write-UnhealthyDisk {
        param([PSObject[]]$Disks)
        process {
            $Disks | ForEach-Object {
                try {
                    $PhysicalDisk = Get-PhysicalDisk -DeviceNumber $_ | Select-Object FriendlyName, DeviceId, MediaType, OperationalStatus, HealthStatus
                    $StorageReliabilityCounters = Get-PhysicalDisk -DeviceNumber $_ | Get-StorageReliabilityCounter | Select-Object Temperature, WriteErrorsTotal, Wear
                    Write-Host "$($PhysicalDisk.FriendlyName)"
                    Write-Host "DeviceId: $($PhysicalDisk.DeviceId) | Type: $($PhysicalDisk.MediaType) | Status: $($PhysicalDisk.OperationalStatus) | Health: $($PhysicalDisk.HealthStatus)"
                    Write-Host "Temp: $($StorageReliabilityCounters.Temperature) CÂ° | Total Write Errors: $($StorageReliabilityCounters.WriteErrorsTotal) | Wear: $($StorageReliabilityCounters.Wear)%"
                    Write-Host ""
                    Write-Output 1
                }
                catch {
                    # Skip this drive
                    Write-Output 0
                }
            } | Measure-Object -Sum | Select-Object -ExpandProperty Sum
        }
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
    # Get all disks
    $Disks = Get-PhysicalDisk
    # Get any SSD's that have Write Errors, to hot, or Wear level over 10%
    $UnhealthySSDDisks = $Disks | Where-Object { $_.MediaType -like "SSD" -and $_.PhysicalLocation -notlike "*.vhd*" } | Get-StorageReliabilityCounter | Where-Object {
        (
            $null -ne $_.WriteErrorsTotal -and
            $_.WriteErrorsTotal -ge 1 # Any amount for an SSD is a cause for concern
        ) -or
        (
            $null -ne $_.Wear -and
            # The storage device wear indicator, in percentage. At 100 percent, the estimated wear limit has been reached.
            # https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-storagereliabilitycounter
            $_.Wear -ge $WearLevelPercentMax
        )
    }

    $DeviceIds = $UnhealthySSDDisks | Sort-Object -Property DeviceId -Unique | Select-Object -ExpandProperty DeviceId
    $DriveCount = Write-UnhealthyDisk -Disks $DeviceIds

    if ($DeviceIds.Count -and $DriveCount) {
        Write-Host "WARNING: $($DeviceIds.Count) disks were found with wear level above $WearLevelPercentMax%."
        exit 1
    }

    Write-Host "No disks were found with wear level above $WearLevelPercentMax%."
    exit 0
}
end {
    
    
    
}


