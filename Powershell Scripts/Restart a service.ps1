# Restart one or more services.
<#
.SYNOPSIS
    Restart one or more services.
.DESCRIPTION
    Restart one or more services. This also try three more times to get the service(s) to start, all the while waiting 15 seconds between each attempt.
.EXAMPLE
     -Name "ServiceName"
    Restarts a service with the name ServiceName
.EXAMPLE
     -Name "ServiceName","AnotherServiceName" -WaitTimeInSecs 15
    Restarts two services with the names ServiceName and AnotherServiceName and waits 15 Seconds for them all to start
.EXAMPLE
    PS C:\> Restart-Service.ps1 -Name "ServiceName"
    Restarts a service with the name ServiceName
.EXAMPLE
    PS C:\> Restart-Service.ps1 -Name "ServiceName","AnotherServiceName" -WaitTimeInSecs 15
    Restarts two services with the names ServiceName and AnotherServiceName and waits 15 Seconds for them all to start
.NOTES
    Exit Code 0: All service(s) restarted
    Exit Code 1: Some or all service(s) failed to restart
    Release Notes: Updated Calculated Name
#>
[CmdletBinding()]
param (
    # Name of service(s), either Name or DisplayName from Get-Service cmdlet
    [Parameter()]
    [String[]]
    $Name,
    # The number of attempts to restart the service before giving up
    [Parameter()]
    [int]
    $Attempts = 3,
    # Duration in Seconds to wait for service(s) to start between each attempt
    [Parameter()]
    [int]
    $WaitTimeInSecs = 15
)

begin {
    if ($env:Name) {
        $Name = $env:Name
    }
    if ($env:Attempts) {
        $Attempts = $env:Attempts
    }
    if ($env:WaitTimeInSecs) {
        $WaitTimeInSecs = $env:WaitTimeInSecs
    }
    if (-not $Name) {
        Write-Host "Name is required."
        exit 1
    }
    if ($Name -like "*,*") {
        $Name = $Name -split ',' | ForEach-Object { "$_".Trim() }
    }
    function Test-Service {
        [CmdletBinding()]
        param (
            [Parameter()]
            [String[]]
            $Services
        )
        if ((Get-Service | Where-Object { ($_.Name -in $Services -or $_.DisplayName -in $Services) -and $_.Status -like "Running" }).Count -gt 0) {
            $true
        }
        else {
            $false
        }
    }
    $FailedToStart = 0
}
process {
    # Get service(s)
    $Services = Get-Service | Where-Object { $_.Name -in $Name -or $_.DisplayName -in $Name }
    if ($Services.Count -eq 0) {
        Write-Error "No service(s) found."
        exit 1
    }

    # Restart service(s)
    $Services | ForEach-Object {
        $AttemptCounter = $Attempts
        # Restart the service
        $Service = $_ | Get-Service
        $Service | Restart-Service
        # Wait till status of service reaches Running, timeout after $WaitTimeInSecs seconds
        $AttemptTime = Get-Date
        # Loop till either the service is in a running state or our $AttemptCounter reaches 0 or less
        while (
            $($Service | Get-Service).Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running -or
            $AttemptTime -le $(Get-Date).AddSeconds($WaitTimeInSecs)
        ) {
            # Start service
            $Service | Start-Service
            # Wait $WaitTimeInSecs seconds
            Start-Sleep -Seconds $WaitTimeInSecs
            $AttemptCounter = $AttemptCounter - 1
            if ($AttemptCounter -le 0) { break }
        }
        if ($(($Service | Get-Service).Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running)) {
            # Add 1 to later show the count of services that failed to reach the running state
            $FailedToStart = $FailedToStart + 1
            Write-Error -Message "Failed to start service( $($Service.Name) ) after $Attempts attempts."
        }
    }

    # Print out services with their status
    Get-Service | Where-Object { $_.Name -in $Name -or $_.DisplayName -in $Name }

    # Check if service(s) have started
    if ($FailedToStart -eq 0) {
        # All service(s) have been restarted
        Write-Host "All Service(s) restarted."
        exit 0
    }
    else {
        # Some or all Service(s) failed to restart
        Write-Error -Message "Failed to start $FailedToStart service(s)."
        exit 1
    }
}
end {
    
    
    
}


