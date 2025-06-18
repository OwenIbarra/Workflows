# Get the drive types of all fixed SSD and HDD drives.
#Requires -Version 5.1

<#
.SYNOPSIS
    Get the drive types of all fixed SSD and HDD drives.
.DESCRIPTION
    Gets the drive types of all fixed SSD and HDD drives and can save the results to a custom field.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    DiskNumber DriveLetter MediaType BusType SerialNumber
    ---------- ----------- --------- ------- ------------
    0          C:          SSD       SATA    50026B768B3A4E3A
    1          D:          HDD       SATA    WD-WCC4N0JYJYJY

PARAMETER: -CustomFieldParam "ReplaceMeWithAnyMultilineCustomField"
    The name of the custom field to save the results to.
.EXAMPLE
    -CustomFieldParam "ReplaceMeWithAnyMultilineCustomField"
    ## EXAMPLE OUTPUT WITH CustomFieldParam ##
    DiskNumber DriveLetter MediaType BusType SerialNumber
    ---------- ----------- --------- ------- ------------
    0          C:          SSD       SATA    50026B768B3A4E3A
    1          D:          HDD       SATA    WD-WCC4N0JYJYJY
    [Info] Saving the results to the custom field. (ReplaceMeWithAnyMultilineCustomField)
    [Info] The results have been saved to the custom field. (ReplaceMeWithAnyMultilineCustomField)

Custom Field Output:
    #0, Letter: C:, Media: SSD, Bus: SATA, SN: 50026B768B3A4E3A
    #1, Letter: D:, Media: HDD, Bus: SATA, SN: WD-WCC4N0JYJYJY

.PARAMETER CustomFieldName
    The name of the custom field to save the results to.
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10/Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomFieldName
)

begin {
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
    if ($env:customFieldName -and $env:customFieldName -ne 'null') {
        $CustomFieldName = $env:customFieldName
    }

    # Get the drive type of all drives
    $Disks = Get-PhysicalDisk | Where-Object { $_.BusType -notlike "File Backed Virtual" -and -not ($_.PhysicalLocation -like "*USB*" -or $_.BusType -like "*USB*") } | Select-Object -Property DeviceID, MediaType, BusType, SerialNumber
    if ($($Disks | Where-Object { $_.MediaType -like "Unspecified" }).Count) {
        Write-Host "[Info] An Unspecified MediaType likely indicates this machine is a VM or there is an issue with that drive."
    }
    # Get the partitions with mounted drive letters
    $Partitions = Get-Partition | Where-Object { $_.DriveLetter -ne $null } | Select-Object -Property DriveLetter, DiskNumber
    # Join the two collections
    $Drives = $Disks | ForEach-Object {
        $Disk = $_
        $Partition = $Partitions | Where-Object { $_.DiskNumber -eq $Disk.DeviceID }
        [PSCustomObject]@{
            DiskNumber   = $_.DeviceID
            DriveLetter  = $Partition.DriveLetter | Where-Object { $_ }
            MediaType    = $_.MediaType
            BusType      = $_.BusType
            SerialNumber = $_.SerialNumber
        }
    }
    $($Drives | Out-String) | Write-Host

    # Save the results to a custom field
    if ($CustomFieldName) {
        Write-Host "[Info] Saving the results to the custom field. ($CustomFieldName)"
        $CustomField = $(
            $Drives | ForEach-Object {
                "#:$($_.DiskNumber), Letter: $($_.DriveLetter), Media: $($_.MediaType), Bus: $($_.BusType), SN: $($_.SerialNumber)"
            }
        ) | Ninja-Property-Set-Piped -Name $CustomFieldName 2>&1
        if ($CustomField.Exception) {
            Write-Host $CustomField.Exception.Message
            Write-Host "[Error] Failed to save the results to the custom field. ($CustomFieldName)"
        }
        else {
            Write-Host "[Info] The results have been saved to the custom field. ($CustomFieldName)"
        }
    }
}
end {
    
    
    
}
