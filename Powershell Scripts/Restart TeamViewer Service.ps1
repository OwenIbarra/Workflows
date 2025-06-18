# Restarts the TeamViewer Service. Use Set to Automatic if the service was disabled.
#Requires -Version 5.1

<#
.SYNOPSIS
    Restarts the TeamViewer Service. Use "Set to Automatic" if the service was disabled.
.DESCRIPTION
    Restarts the TeamViewer Service. Use "Set to Automatic" if the service was disabled.
.EXAMPLE
    (No Parameters)
    
    Status   Name               DisplayName                           
    ------   ----               -----------                           
    Running  TeamViewer         TeamViewer                            
    Attempt 1 has completed!
    TeamViewer has restarted successfully!

PARAMETER: -Enable
    Re-Enables disabled TeamViewer services.

PARAMETER: -Attempts "7" 
    Overrides the number of attempts the script will make to restart the service. Simply replace 7 with your desired number of attempts.

PARAMETER: -WaitTimeInSecs "30"
    Overrides the amount of time in between attempts. Defaults to 15.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2016
    Release Notes: Initial release
#>

[CmdletBinding()]
param (
    [Parameter()]    
    [Switch]$Enable = [System.Convert]::ToBoolean($env:setToAutomatic),
    [Parameter()]
    [int]$Attempts = 3,
    [Parameter()]
    [int]$WaitTimeInSecs = 15
)

begin {
    if ($env:attempts -and $env:attempts -notlike "null") { $Attempts = $env:attempts }
    if ($env:waitTimeInSeconds -and $env:waitTimeInSeconds -notlike "null") { $WaitTimeInSecs = $env:waitTimeInSeconds }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Grabs initial set of services to try once.
    $ServiceList = Get-CimInstance -ClassName "win32_service"

    # Attempts to find the TeamViewer service using its executable name.
    function Find-Service {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [String]$Name
        )
        process {
            $ServiceList | Where-Object { $_.PathName -Like "*$Name.exe*" } 
        }
    }

    # Tests if the service was successful
    function Test-Service {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [String]$Name
        )
        process {
            $Running = Get-Service $Name | Where-Object { $_.Status -eq $Running }
            if ($Running) {
                return $True
            }
            else {
                return $False
            }
        }
    }

    # Name of each TeamViewer exe.
    $ProcessName = "TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64"
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # List of services to try
    $Services = $ProcessName | Find-Service

    # If no TeamViewer service is found
    if (-not $Services) {
        Write-Host "[Error] TeamViewer appears to be missing its service. You will need to reinstall it."
        exit 1
    }

    # Loops through each service and attempts to start them
    foreach ($Service in $Services) {
        $Failed = $True
        $Attempt = 1
        While ($Attempt -le $Attempts -and $Failed -eq $True) {

            # If the service was disabled, check if -Enable was specified.
            if ($Service.StartMode -ne "Auto" -and $Enable) {
                # If so re-enable it.
                $Service | Get-Service | Set-Service -StartupType "Automatic"
            }
            elseif ($Service.StartMode -ne "Auto") {
                Write-Host "[Error] The service is not set to start automatically. Use 'Set To Automatic' to change the startup type to automatic."
                if($Service.StartMode -eq "Disabled"){ exit 1 }
            }

            # All possible service states
            Switch ($Service.State) {
                "Running" { $Service | Get-Service | Restart-Service -PassThru }
                "Paused" { $Service | Get-Service | Resume-Service -PassThru }
                "Pending" {
                    $Service | Get-Service | Stop-Service
                    Start-Sleep -Seconds 2  # Ensure the service has time to stop
                    $Service | Get-Service | Start-Service -PassThru
                }
                "Stopped" { $Service | Get-Service | Start-Service -PassThru }
            }

            Start-Sleep -Seconds $WaitTimeInSecs

            # Feedback on the number of attempts made. Multiple attempts may indicate that TeamViewer needs to be reinstalled.
            Write-Host "Attempt $Attempt completed."

            $Attempt++
            $Failed = $Service.Name | Test-Service
        }
    }
    $Failed = $Services | Get-Service | Where-Object { $_.Status -ne "Running" }

    if ($Failed) {
        Write-Host "[Error] Unable to start the service!"
        exit 1
    }
    else {
        Write-Host "TeamViewer has restarted successfully!"
        exit 0
    }
}
end {
    
    
    
}


