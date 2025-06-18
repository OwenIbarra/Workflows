# Compares the local system time to an NTP server and alerts if outside the max time range.
#Requires -Version 5.1

<#
.SYNOPSIS
    Compares the local system time to an NTP server and alerts if outside the max time range.
.DESCRIPTION
    Compares the local system time to an NTP server and alerts if outside the max time range.
.EXAMPLE
    No parameters needed
    The maximum acceptable time difference of 2 seconds.
.EXAMPLE
    -Max 5
    The maximum acceptable time difference of 5 seconds.
.EXAMPLE
    -NtpServer "pool.ntp.org"
    The maximum acceptable time difference of 2 seconds, but uses the ntp.org's pool and use the time server pool "pool.ntp.org".
    Alterative pools:
    time.google.com
    time.cloudflare.com
    time.facebook.com
    time.apple.com
    time.nist.gov
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Exit code 1: If the time is off more than Max
    Exit code 0: If the time is off less than or equal to Max
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [double]$Max = 120,
    [Parameter()]
    [string]$NtpServer = "time.windows.com"
)

begin {
    if ($env:maxTimeDifferenceInSeconds) {
        $Max = $env:maxTimeDifferenceInSeconds
    }
    if ($env:ntpServer) {
        $NtpServer = $env:ntpServer
    }
}
process {
    Write-Host "Retrieving the current time using an NTP server ($NtpServer)."
    $TimeSample = w32tm.exe /StripChart /Computer:"$NtpServer" /DataOnly /Samples:1
    $Diff = $($($TimeSample | Select-Object -Last 1) -split ', ' | Select-Object -Last 1) -replace '\+' -replace '\-'
    if($TimeSample -match 'error'){
        Write-Host "[Error] Failed to get the time difference from the ntp server. Is the NTP server correct? ($NtpServer)"
        Write-Host $TimeSample
        exit 1
    }
    $TimeScale = $Diff -split '' | Select-Object -Last 1 -Skip 1

    # Convert to minutes
    $Diff = switch ($TimeScale) {
        "s" { [double]$($Diff -replace 's') }
        "m" { [double]$($Diff -replace 'm') * 60 }
        "h" { [double]$($Diff -replace 'h') * 60 * 60 * 60 }
        "d" { [double]$($Diff -replace 'd') * 60 * 60 * 60 * 24 }
        Default {}
    }
    Write-Host "The time difference between the NTP server and local system is $($([Math]::Round($Diff,2))) seconds."

    if ($Max -lt 0) {
        # If Max is negative then flip the sign to positive
        $Max = 0 - $Max
    }

    # Only output this if -Verbose is used
    Write-Verbose "$($Diff) seconds > $Max seconds = $($Diff -gt $Max)"
    # Assuming that $Max and $Diff are positive
    if (
        $Diff -gt $Max
    ) {
        # If time difference > $Max then return exit code of 1
        Write-Host "[Alert] Time is over the maximum seconds of $Max."
        exit 1
    }
    else {
        # If time difference < $Max then return exit code of 0
        Write-Host "Time is under the maximum seconds of $Max."
        exit 0
    }
}
end {
    
    
    
}


