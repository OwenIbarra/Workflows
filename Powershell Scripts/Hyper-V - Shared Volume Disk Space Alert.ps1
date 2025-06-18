# Hyper-V Monitor shared volume disk free space. Must be ran as a Local or Domain Admin user.
#Requires -Version 5.1

<#
.SYNOPSIS
    Hyper-V Monitor shared volume disk free space. Must be ran as a Local or Domain Admin user.
.DESCRIPTION
    Hyper-V Monitor shared volume disk free space. Must be ran as a Local or Domain Admin user.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
Name                       Path                  Size(GB) FreeSpace(GB) UsedSpace(GB) PercentFree
----                       ----                  -------- ------------- ------------- -----------
Cluster Virtual Disk (vd1) C:\ClusterStorage\vd1 3,068.98 168.77        2900.21       9.99

PARAMETER: -MinimumPercentage 20
    Only errors when any shared volume disk is below the specified percentage.
    Defaults to 10 percent.
.EXAMPLE
    -MinimumPercentage 20
    ## EXAMPLE OUTPUT WITH MinimumPercentage ##
Name                       Path                  Size(GB) FreeSpace(GB) UsedSpace(GB) PercentFree
----                       ----                  -------- ------------- ------------- -----------
Cluster Virtual Disk (vd1) C:\ClusterStorage\vd1 3,068.98 168.77        2900.21       9.99

PARAMETER: -MinimumFreeBytes 1073741824
    Only errors when any shared volume disk is below the specified percentage.
    Defaults to 1GB or 1073741824 bytes.
.EXAMPLE
    -MinimumFreeBytes 1073741824
    ## EXAMPLE OUTPUT WITH MinimumFreeBytes ##
Name                       Path                  Size(GB) FreeSpace(GB) UsedSpace(GB) PercentFree
----                       ----                  -------- ------------- ------------- -----------
Cluster Virtual Disk (vd1) C:\ClusterStorage\vd1 3,068.98 168.77        2900.21       9.99

PARAMETER: -ExcludeDrivesByName MyDisk
    Excludes drives that contains the text MyDisk in its name.
.EXAMPLE
    -ExcludeDrivesByName 1073741824
    ## EXAMPLE OUTPUT WITH ExcludeDrivesByName ##
Name                       Path                  Size(GB) FreeSpace(GB) UsedSpace(GB) PercentFree
----                       ----                  -------- ------------- ------------- -----------
Cluster Virtual Disk (vd1) C:\ClusterStorage\vd1 3,068.98 168.77        2900.21       9.99

PARAMETER: -ExcludeDrivesByPath C:\ClusterStorage\MyDisk
    Excludes drives that contains the text MyDisk in its name.
.EXAMPLE
    -ExcludeDrivesByPath C:\ClusterStorage\MyDisk
.EXAMPLE
    -ExcludeDrivesByPath MyDisk
    ## EXAMPLE OUTPUT WITH ExcludeDrivesByPath ##
Name                       Path                  Size(GB) FreeSpace(GB) UsedSpace(GB) PercentFree
----                       ----                  -------- ------------- ------------- -----------
Cluster Virtual Disk (vd1) C:\ClusterStorage\vd1 3,068.98 168.77        2900.21       9.99

PARAMETER: -CustomFieldParam "ReplaceMeWithAnyMultilineCustomField"
    Saves the results to a multi-line string custom field.
.EXAMPLE
    -CustomFieldParam "ReplaceMeWithAnyMultilineCustomField"
    ## EXAMPLE OUTPUT WITH CustomFieldParam ##
Name                       Path                  Size(GB) FreeSpace(GB) UsedSpace(GB) PercentFree
----                       ----                  -------- ------------- ------------- -----------
Cluster Virtual Disk (vd1) C:\ClusterStorage\vd1 3,068.98 168.77        2900.21       9.99
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [int]$MinimumPercentage = 10,
    $MinimumFreeBytes = 1GB,
    [String]$ExcludeDrivesByName,
    [String]$ExcludeDrivesByPath,
    [string]$CustomFieldParam
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }
    function Get-FriendlySize {
        param($Bytes)
        # Converts Bytes to the highest matching unit
        $Sizes = 'Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
        for ($i = 0; ($Bytes -ge 1kb) -and ($i -lt $Sizes.Count); $i++) { $Bytes /= 1kb }
        $N = 2
        if ($i -eq 0) { $N = 0 }
        if ($Bytes) { "$([System.Math]::Round($Bytes,$N)) $($Sizes[$i])" }else { "0 B" }
    }
    function Get-Size {
        param (
            [string]$String,
            [ValidateSet("PB", "TB", "GB", "MB", "KB", "B", "Bytes")][string]$DefaultSize = "GB"
        )
        switch -wildcard ($String) {
            '*PB' { [int64]$($String -replace '[^\d+]+') * 1PB; break }
            '*TB' { [int64]$($String -replace '[^\d+]+') * 1TB; break }
            '*GB' { [int64]$($String -replace '[^\d+]+') * 1GB; break }
            '*MB' { [int64]$($String -replace '[^\d+]+') * 1MB; break }
            '*KB' { [int64]$($String -replace '[^\d+]+') * 1KB; break }
            '*B' { [int64]$($String -replace '[^\d+]+') * 1; break }
            '*Bytes' { [int64]$($String -replace '[^\d+]+') * 1; break }
            Default { Get-Size -String "$String $DefaultSize" }
        }
    }
    function Invoke-FilterDisks {
        [CmdletBinding()]
        param(
            [parameter(ValueFromPipeline = $true)]
            $Disks
        )
        process {
            $Disks | ForEach-Object {
                # Check if exclude by name is needed
                if ($([string]::IsNullOrEmpty($ExcludeDrivesByName) -or [string]::IsNullOrWhiteSpace($ExcludeDrivesByName))) {
                    $_
                }
                else {
                    if (
                        $_.Name -like "*$ExcludeDrivesByName*"
                    ) {
                        # Output Nothing
                    }
                    else {
                        $_
                    }
                }
            } | ForEach-Object {
                # Check if exclude by name is needed
                if ($([string]::IsNullOrEmpty($ExcludeDrivesByPath) -or [string]::IsNullOrWhiteSpace($ExcludeDrivesByPath))) {
                    $_
                }
                else {
                    if (
                        $_.Path -like "*$ExcludeDrivesByPath*"
                    ) {
                        # Output Nothing
                    }
                    else {
                        $_
                    }
                }
            }
        }
    }
    if ($env:MinimumPercentage) {
        $MinimumPercentage = $env:MinimumPercentage
    }
    if ($env:minimumFreeSpace) {
        $MinimumFreeBytes = Get-Size -String $env:minimumFreeSpace
    }
    if ($env:ExcludeDrivesByName) {
        $ExcludeDrivesByName = $env:ExcludeDrivesByName
    }
    if ($env:ExcludeDrivesByPath) {
        $ExcludeDrivesByPath = $env:ExcludeDrivesByPath
    }
    if ($env:CustomFieldParam) {
        $CustomFieldParam = $env:CustomFieldParam
    }
}
process {
    if (Test-IsSystem) {
        Write-Error -Message "Access Denied. Please run with a Domain Account or a Local Account that has permissions to access this node."
        exit 1
    }

    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    Import-Module FailoverClusters -ErrorAction SilentlyContinue

    if (-not $(Get-Command -Name "Get-Cluster" -ErrorAction SilentlyContinue)) {
        Write-Error "[Error] Must run this script on a server that is apart of a Cluster or can communicate with a Cluster."
        exit 1
    }

    try {
        Get-ClusterNode -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "[Error] Failed to get Cluster Nodes."
        exit 1
    }

    # Get Cluster Shared Volume Info
    $Volumes = foreach ( $csv in $(Get-ClusterSharedVolume) ) {
        foreach ( $csvinfo in $($csv | Select-Object -Property Name -ExpandProperty SharedVolumeInfo) ) {
            [PSCustomObject]@{
                Name        = $csv.Name
                Path        = $csvinfo.FriendlyVolumeName
                Size        = $csvinfo.Partition.Size
                FreeSpace   = $csvinfo.Partition.FreeSpace
                UsedSpace   = $csvinfo.Partition.UsedSpace
                PercentFree = $csvinfo.Partition.PercentFree
            }
        }
    }

    # Prep Format-Table substitutions
    $Size = @{ Label = "Size(GB)" ; Expression = { (Get-FriendlySize -Bytes $_.Size) } }
    $FreeSpace = @{ Label = "FreeSpace(GB)" ; Expression = { (Get-FriendlySize -Bytes $_.FreeSpace) } }
    $UsedSpace = @{ Label = "UsedSpace(GB)" ; Expression = { (Get-FriendlySize -Bytes $_.UsedSpace) } }
    $PercentFree = @{ Label = "PercentFree" ; Expression = { ($_.PercentFree) } }
    # Sort disks by FreeSpace
    $Disks = $Volumes | Sort-Object FreeSpace
    # Save results as a string
    $DisksFormattedString = $Disks | Format-Table -AutoSize Name, Path, $Size, $FreeSpace, $UsedSpace, $PercentFree | Out-String

    # If using a custom field sent that to the specified custom field, should be a multi-line
    if ($CustomFieldParam) {
        Ninja-Property-Set -Name $CustomFieldParam -Value $DisksFormattedString
    }

    # Loop through each disk
    $DiskUnderPercentage = $Disks | Invoke-FilterDisks | Where-Object { $_.PercentFree -lt $MinimumPercentage }
    $DiskUnderFreeBytes = $Disks | Invoke-FilterDisks | Where-Object { $_.FreeSpace -lt $MinimumFreeBytes }

    if ($DiskUnderPercentage -or $DiskUnderFreeBytes) {
        if ($DiskUnderPercentage) {
            Write-Host "[Issue] One or more Disks under $MinimumPercentage % free!"
        }
        if ($DiskUnderFreeBytes) {
            Write-Host "[Issue] One or more Disks under $(Get-FriendlySize -Bytes $MinimumFreeBytes) free!"
        }
        $DisksFormattedString | Write-Host
        exit 1
    }

    # List all shared volumes
    if (-not $DiskUnderPercentage) {
        Write-Host "[Info] One or more Disks over $MinimumPercentage % free."
    }
    if (-not $DiskUnderFreeBytes) {
        Write-Host "[Info] One or more Disks over $(Get-FriendlySize -Bytes $MinimumFreeBytes) free."
    }
    $DisksFormattedString | Write-Host
    exit 0
}
end {
    
    
    
}


