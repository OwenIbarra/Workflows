# Wait for a random amount of time. The maximum allowed time to wait is 180 minutes (3 hours).

<#
.SYNOPSIS
    Wait for a random amount of time. The maximum allowed time to wait is 180 minutes (3 hours).
.DESCRIPTION
    Wait for a random amount of time. The maximum allowed time to wait is 180 minutes (3 hours).

.EXAMPLE
    (No Parameters)
    
    Sleeping for 1.15 Minutes...
    Wait has finished

PARAMETER: -MaxTimeInMinutes "30"
    The maximum amount of time the script should sleep for.

.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2008
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$MaxTime = 120
)

begin {
    if ($env:maxTimeInMinutes -and $env:maxTimeInMinutes -notlike "null") { $MaxTime = $env:maxTimeInMinutes }

    if($Maxtime -eq 180){
        $Maxtime = $Maxtime - 1
    }
    
    if ($MaxTime -lt 1 -or $MaxTime -gt 180) {
        Write-Host "[Error] Max Time must be greater than 0 and less than or equal to 180 Minutes"
        exit 1
    }
}
process {
    $TimeInSeconds = Get-Random -Maximum ($MaxTime * 60)

    Write-Host "Sleeping for $([math]::Round(($TimeInSeconds / 60),2)) Minutes..."
    Start-Sleep -Seconds $TimeInSeconds

    Write-Host "Wait has finished"
}
end {
    
    
    
}
