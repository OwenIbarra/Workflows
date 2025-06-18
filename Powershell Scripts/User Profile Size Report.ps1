# Updates a Custom Field with the total size of all User Profiles. If the Max parameter is specified then it will return an exit code of 1 for any profile being over that Max threshold in GB.
#Requires -Version 5.1

<#
.SYNOPSIS
    Updates a Custom Field with the total size of all User Profiles. If the Max parameter is specified then it will return an exit code of 1 for any profile being over that Max threshold in GB.
.DESCRIPTION
    Updates a Custom Field with the total size of all User Profiles.
    If the Max parameter is specified then it will return an exit code of 1
     for any profile being over that Max threshold in GB.
.EXAMPLE
     -Max 60
    Returns and exit code of 1 if any profile is over 60GB
.EXAMPLE
     -CustomField "Something"
    Specifies the name of the custom field to update.
.EXAMPLE
    No Parameter needed.
    Uses the default custom field name: TotalUsersProfileSize
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Alias("MaxSize", "Size", "ms", "m", "s")]
    [Double]$Max,
    [Parameter()]
    [Alias("Custom", "Field", "cf", "c", "f")]
    [String]$CustomField = "TotalUsersProfileSize"
)

begin {
    if ($env:sizeInGbToAlertOn -and $env:sizeInGbToAlertOn -notlike "null") { $Max = $env:sizeInGbToAlertOn }
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Format-FileSize {
        param($Length)
        switch ($Length) {
            { $_ / 1TB -gt 1 } { "$([Math]::Round(($_ / 1TB),2)) TB"; break }
            { $_ / 1GB -gt 1 } { "$([Math]::Round(($_ / 1GB),2)) GB"; break }
            { $_ / 1MB -gt 1 } { "$([Math]::Round(($_ / 1MB),2)) MB"; break }
            { $_ / 1KB -gt 1 } { "$([Math]::Round(($_ / 1KB),2)) KB"; break }
            Default { "$_ Bytes" }
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    $Profiles = Get-ChildItem -Path "C:\Users"
    $ProfileSizes = $Profiles | ForEach-Object {
        [PSCustomObject]@{
            Name   = $_.BaseName
            Length = Get-ChildItem -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue | Select-Object -Property Sum -ExpandProperty Sum
        }
    }
    $Largest = $ProfileSizes | Sort-Object -Property Length -Descending | Select-Object -First 1

    $Size = $ProfileSizes | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue | Select-Object -Property Sum -ExpandProperty Sum

    $FormattedSize = Format-FileSize -Length $Size

    $AllProfiles = $ProfileSizes | Sort-Object -Property Length -Descending | ForEach-Object {
        $FormattedSizeUser = Format-FileSize -Length $_.Length
        "$($_.Name) $($FormattedSizeUser)"
    }

    Write-Host "All Profiles - $FormattedSize, $($AllProfiles -join ', ')"

    Ninja-Property-Set -Name $CustomField -Value "$AllProfiles"

    if ($Max -and $Max -gt 0) {
        if ($Largest.Length -gt $Max * 1GB) {
            Write-Host "Found profile over the max size of $Max GB."
            Write-Host "$($Largest.Name) profile is $($Largest.Length / 1GB) GB"
            exit 1
        }
    }
    exit 0
}
end {
    
    
    
}

