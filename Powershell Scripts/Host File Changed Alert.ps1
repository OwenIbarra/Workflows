# Checks if the hosts file was modified from last run.
#Requires -Version 5.1

<#
.SYNOPSIS
    Checks if the hosts file was modified from last run.
.DESCRIPTION
    Checks if the hosts file was modified from last run.
    On first run this will not produce an error, but will create a cache file for later comparison.
.EXAMPLE
    No parameters needed.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated Calculated Name
#>

[CmdletBinding()]
param (
    # Path and file of the hosts file
    [string]
    $HostsPath = "C:\Windows\System32\drivers\etc\hosts",
    # Path and file where the cache file will be saved for comparison
    [string]
    $CachePath = "C:\ProgramData\NinjaRMMAgent\scripting\Test-HostsFile.clixml"
)

begin {
    if ($env:HostsPath) {
        $HostsPath = $env:HostsPath
    }
    if ($env:CachePath) {
        $CachePath = $env:CachePath
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

    # Check if hosts file exists
    if ($(Test-Path -Path $HostsPath)) {
        # Get content and create hash of hosts file
        $HostsContent = Get-Content -Path $HostsPath
        $HostsHash = Get-FileHash -Path $HostsPath -Algorithm SHA256

        $Current = [PSCustomObject]@{
            Content = $HostsContent
            Hash    = $HostsHash
        }

        # Check if this is first run or not
        if ($(Test-Path -Path $CachePath)) {
            # Compare last content and hash
            $Cache = Import-Clixml -Path $CachePath
            $ContentDifference = Compare-Object -ReferenceObject $Cache.Content -DifferenceObject $Current.Content -CaseSensitive
            $HashDifference = $Cache.Hash -like $Current.Hash
            $Current | Export-Clixml -Path $CachePath -Force -Confirm:$false
            if (-not $HashDifference) {
                Write-Host "Hosts file has changed since last run!"
                Write-Host ""
                $ContentDifference | ForEach-Object {
                    if ($_.SideIndicator -like '=>') {
                        Write-Host "Added: $($_.InputObject)"
                    }
                    elseif ($_.SideIndicator -like '<=') {
                        Write-Host "Removed: $($_.InputObject)"
                    }
                }
                exit 1
            }
            else {
                Write-Host "No changes detected since last run."
            }
        }
        else {
            Write-Host "First run, saving comparison cache file."

            $FolderPath = $CachePath | Split-Path
            if (-not $(Test-Path -Path $FolderPath)) {
                Write-Host "$FolderPath does not exist creating..."
                New-Item -ItemType Directory -Path $FolderPath | Out-Null
            }
        
            $Current | Export-Clixml -Path $CachePath -Force -Confirm:$false
        }
    }
    else {
        Write-Error "Hosts file is missing!"
        exit 1
    }
    exit 0
}
end {
    
    
    
}


