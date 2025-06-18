# Fetches the install date. Outputs to the activity feed and can store it in a custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Fetches the install date. Outputs to the activity feed and can store it in a custom field.
.DESCRIPTION
    Fetches the install date. Outputs to the activity feed and can store it in a custom field.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    Install Date: 08/18/2021 13:50:15

PARAMETER: -CustomField "InstallDate"
    A custom field to save the install date to.
.EXAMPLE
    -CustomField "InstallDate"
    ## EXAMPLE OUTPUT WITH CustomField ##
    Install Date: 08/18/2021 13:50:15
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [string]$CustomField
)

begin {
    $Epoch = [DateTime]'1/1/1970'
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }
    Write-Host ""
}
process {
    $InstallDate = $(
        try {
            # Get Install Date from registry
            Get-ChildItem -Path "HKLM:\System\Setup\Source*" -ErrorAction SilentlyContinue | ForEach-Object {
                $InstallDate = Get-ItemPropertyValue -Path Registry::$_ -Name "InstallDate" -ErrorAction SilentlyContinue
                [System.TimeZone]::CurrentTimeZone.ToLocalTime(($Epoch).AddSeconds($InstallDate))
            }
            $InstallDateCu = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name "InstallDate" -ErrorAction SilentlyContinue
            [System.TimeZone]::CurrentTimeZone.ToLocalTime(($Epoch).AddSeconds($InstallDateCu))
        }
        catch {
            # Skip if errors
        }

        try {
            # Get Install date from system info
            $SystemInfo = systeminfo.exe
            # --- Output of system info ---
            # Original Install Date:     9/3/2020, 8:54:48 AM
            $($SystemInfo | Select-String "install date") -split 'Date:\s+' | Select-Object -Last 1 | Get-Date
        }
        catch {
            # Skip if errors
        }

        try {
            # Get Install date from WMI
            $(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).InstallDate
        }
        catch {
            # Skip if errors
        }

        try {
            if ($PSVersionTable.PSVersion.Major -ge 5 -and $PSVersionTable.PSVersion.Minor -ge 1) {
                $ComputerInfo = Get-ComputerInfo -Property WindowsInstallDateFromRegistry, OsInstallDate -ErrorAction SilentlyContinue
                $ComputerInfo.WindowsInstallDateFromRegistry
                $ComputerInfo.OsInstallDate
            }
        }
        catch {
            # Skip if errors
        }
    ) | Sort-Object | Select-Object -First 1

    if ($InstallDate) {
        if ($CustomField) {
            Ninja-Property-Set -Name $CustomField -Value $InstallDate
        }
        Write-Host "Install Date: $InstallDate"
    }
    else {
        if ($CustomField) {
            Ninja-Property-Set -Name $CustomField -Value "Unknown"
        }
        Write-Host "Install Date: Unknown"
    }
}
end {
    
    
    
}

