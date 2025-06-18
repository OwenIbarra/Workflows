# Reports PowerShell Desktop and/or Core Version(s) to output for automation systems.

<#
.SYNOPSIS
    Reports PowerShell Desktop and/or Core Version(s) to output for automation systems.
.DESCRIPTION
    Reports PowerShell Desktop and/or Core Version(s) to output for automation systems. Works on Windows, Linux, and macOS.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    PowerShell Desktop: 5.1.19041.3570 - PowerShell Core: 7.3.9

PARAMETER: -OutputPrefix "PowerShellVersion"
    Prefix for the output to identify the version information in automation systems.
.EXAMPLE
    -OutputPrefix "PowerShellVersion"
    ## EXAMPLE OUTPUT WITH OutputPrefix ##
    PowerShellVersion:PowerShell Desktop: 5.1.19041.3570 - PowerShell Core: 7.3.9

.OUTPUTS
    String containing PowerShell version information
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2, Linux, macOS
    Release Notes: Updated for cross-platform compatibility, removed RMM dependencies
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$OutputPrefix = "PowerShellVersion"
)

begin {
    # Cross-platform OS detection
    function Get-OperatingSystem {
        if ($IsWindows -or $env:OS -like "Windows*") {
            return "Windows"
        }
        elseif ($IsLinux) {
            return "Linux"
        }
        elseif ($IsMacOS) {
            return "macOS"
        }
        else {
            return "Unknown"
        }
    }

    $OS = Get-OperatingSystem
}
process {
    # Get current PowerShell version information
    $CurrentPSVersion = $PSVersionTable.PSVersion
    $PSEdition = $PSVersionTable.PSEdition
    
    # Cross-platform PowerShell version reporting
    if ($OS -eq "Windows") {
        # Windows can have both Desktop and Core versions
        if ($PSEdition -eq "Desktop") {
            $PSDesktop = "PowerShell Desktop: $CurrentPSVersion"
        }
        else {
            $PSDesktop = "PowerShell Core: $CurrentPSVersion"
        }

        # Check for PowerShell Core on Windows
        $PSVersionOutput = if (Get-Command -Name "pwsh" -ErrorAction SilentlyContinue) {
            try {
                $pwshVersion = (pwsh -version 2>$null) -replace 'PowerShell\s+', ''
                if ($PSEdition -eq "Desktop") {
                    "$PSDesktop - PowerShell Core: $pwshVersion"
                }
                else {
                    $PSDesktop
                }
            }
            catch {
                $PSDesktop
            }
        }
        else {
            $PSDesktop
        }
    }
    else {
        # Linux and macOS typically use PowerShell Core
        $PSVersionOutput = "PowerShell Core: $CurrentPSVersion"
    }
    
    Write-Host "`n$PSVersionOutput`n"

    # Output for automation systems
    if ($OutputPrefix) {
        Write-Output "${OutputPrefix}:$PSVersionOutput"
    }
    else {
        Write-Output $PSVersionOutput
    }
}
end {
    
    
    
}
