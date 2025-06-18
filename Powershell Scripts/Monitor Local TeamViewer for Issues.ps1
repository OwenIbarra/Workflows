# This script is a best effort attempt to detect when the TeamViewer Service is not working and may need a restart or reinstall. There is a lot of things that can cause this and we recommend verifying its results before taking action.
#Requires -Version 5.1

<#
.SYNOPSIS
    This script is a best effort attempt to detect when the TeamViewer Service is not working and may need a restart or reinstall. There is a lot of things that can cause this and we recommend verifying its results before taking action.
.DESCRIPTION
    This script is a best effort attempt to detect when the TeamViewer Service is not working and may need a restart or reinstall. 
    There is a lot of things that can cause this and we recommend verifying its results before taking action.
.EXAMPLE
    (No Parameters)
    
    The TeamViewer Process and Service appears to be ready for connections.

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2016
    Release Notes: Renamed script
#>

[CmdletBinding()]
param ()

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Grabs initial set of services to try once.
    $ServiceList = Get-CimInstance -ClassName "win32_service"

    # Attempts to find the TeamViewer service using it's exe name.
    function Find-Service {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [String]$Name
        )
        process {
            $ServiceList | Where-Object { $_.State -like "Running" -and $_.PathName -Like "*$Name.exe*" }
        }
    }

    # Name of each Teamviwer exe.
    $ProcessName = "TeamViewer", "TeamViewer_Service"
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # List of services to try
    $Services = $ProcessName | Find-Service

    if (-not $Services) {
        Write-Error "TeamViewer Service appears to not be running or does not exist!"
        exit 1
    }

    # Checking TeamViewer Processes
    $FailedProcesses = New-Object System.Collections.Generic.List[Object]
    $ProcessName | ForEach-Object {
        $FailedProcess = Get-Process -Name $_ -ErrorAction Ignore

        if (-not $FailedProcess) {
            $FailedProcesses.Add($_)
        }
    }

    if ($FailedProcesses) {
        $FailedProcesses | ForEach-Object { Write-Warning "Critical Process $_.exe is not running!" }
        Write-Error "One or more TeamViewer Processes may need to be running in order for TeamViewer to establish connections."
        exit 1
    }

    Write-Host "The TeamViewer Process and Service appears to be ready for connections."
    exit 0
}
end {
    
    
    
}

