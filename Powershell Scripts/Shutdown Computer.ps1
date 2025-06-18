# Shuts down the computer with an optional time delay in seconds.

<#
.SYNOPSIS
    Shuts down the computer with an optional time delay in seconds.
.DESCRIPTION
    Shuts down the computer with an optional time delay in seconds.
.EXAMPLE
    (No Parameters)
    
    Shutdown scheduled for 07/12/2024 16:34:57.

PARAMETER: -Timeout "ReplaceMeWithANumber"
    Sets the time-out period before shutdown to a specified number of seconds. The valid range is 10-315360000 (10 years).

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Grammar
#>

[CmdletBinding()]
param (
    [Parameter()]
    [long]$Timeout = 60
)

begin {
    # If script form variables are used replace the command line parameters with them.
    if ($env:timeDelayInSeconds -and $env:timeDelayInSeconds -notlike "null") { $Timeout = $env:timeDelayInSeconds }

    # Ensure Timeout is specified; if not, display an error message and exit with code 1
    if (!$Timeout) {
        Write-Host -Object "[Error] Timeout in seconds is required!"
        exit 1
    }

    # Validate the Timeout value to ensure it is within the acceptable range
    if ($Timeout -lt 10 -or $Timeout -gt 315360000 - 1) {
        Write-Host -Object "[Error] An invalid timeout of '$Timeout' was given. The timeout must be greater than or equal to 10 and less than 315360000 (10 years)."
        exit 1
    }
    
    # Initialize the ExitCode variable
    $ExitCode = 0
}
process {

    # Define file paths for logs
    $ShutdownOutputLog = "$env:TEMP\shutdown-output-$(Get-Random).log"
    $ShutdownErrorLog = "$env:TEMP\shutdown-error-$(Get-Random).log"

    # Set shutdown arguments based on the OS version
    if ([System.Environment]::OSVersion.Version.Major -ge 10) {
        $ShutdownArguments = "/sg", "/t $Timeout", "/f"
    }
    else {
        $ShutdownArguments = "/s", "/t $Timeout", "/f"
    }

    # Start the shutdown process and redirect output and error logs
    $ShutdownProcess = Start-Process -FilePath "$env:SystemRoot\System32\shutdown.exe" -ArgumentList $ShutdownArguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $ShutdownOutputLog -RedirectStandardError $ShutdownErrorLog

    # Display and remove the standard output log if it exists
    if (Test-Path -Path $ShutdownOutputLog -ErrorAction SilentlyContinue) {
        Get-Content -Path $ShutdownOutputLog -ErrorAction SilentlyContinue | ForEach-Object { 
            Write-Host -Object $_ 
        }
        Remove-Item -Path $ShutdownOutputLog -Force -ErrorAction SilentlyContinue
    }

    # Display error messages, set ExitCode to 1, and remove the error log if it exists
    if (Test-Path -Path $ShutdownErrorLog -ErrorAction SilentlyContinue) {
        Get-Content -Path $ShutdownErrorLog -ErrorAction SilentlyContinue | ForEach-Object { 
            Write-Host -Object "[Error] $_"
            $ExitCode = 1
        }
        Remove-Item -Path $ShutdownErrorLog -Force -ErrorAction SilentlyContinue
    }

    # Handle the exit code from the shutdown process
    switch ($ShutdownProcess.ExitCode) {
        0 { 
            Write-Host -Object "Shutdown scheduled for $((Get-Date).AddSeconds($Timeout))." 
        }
        default { 
            Write-Host -Object "[Error] Failed to schedule shutdown."
            $ExitCode = 1
        }
    }

    # Exit the script with the appropriate exit code
    exit $ExitCode
}
end {
    
    
    
}
