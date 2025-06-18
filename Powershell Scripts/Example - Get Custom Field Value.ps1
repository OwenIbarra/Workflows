# This is an example script for retrieving system configuration values. Specify a type to have the value converted to a more PowerShell native type.
#Requires -Version 4

<#
.SYNOPSIS
    This is an example script for retrieving system configuration values. Specify a type to have the value converted to a more PowerShell native type.
.DESCRIPTION
    This is a cross-platform script that can retrieve system configuration values from various sources like registry (Windows), 
    configuration files (Linux/macOS), or environment variables. It demonstrates how to handle different data types consistently.
.EXAMPLE
    -ConfigName "date"

    Retrieving value from configuration date.
    1697094000
.EXAMPLE
    -ConfigName "date" -ValueType "Date"

    Retrieving value from configuration date.

    Thursday, October 12, 2023 12:00:00 AM

PARAMETER: -ConfigName "NameOfAConfigurationToRetrieve"
    The name of a configuration setting that has a value you would like to retrieve.

PARAMETER: -ValueType "ReplaceMeWithFieldType"
    To convert the value into a more PowerShell-native type, simply specify the type. This is optional; leave blank to output the raw value.
    Valid options are: "Text", "Checkbox", "Date", "Date And Time", "Decimal", "Integer", "Time", "Boolean"

PARAMETER: -ConfigSource "Replace Me With A Configuration Source"
    Source of the configuration value. Options: "Registry", "EnvironmentVariable", "ConfigFile", "Auto" (default: Auto)

.OUTPUTS
    The configuration value, optionally converted to the specified type
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2012 R2, Linux, macOS
    Release Notes: Updated for cross-platform compatibility, removed RMM dependencies
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$ConfigName,
    [Parameter()]
    [String]$ValueType,
    [Parameter()]
    [String]$ConfigSource = "Auto"
)

begin {
    # Cross-platform OS detection
    function Get-OperatingSystem {
        if ($IsWindows -or $env:OS -like "Windows*") {
            return "Windows"
        } elseif ($IsLinux) {
            return "Linux"
        } elseif ($IsMacOS) {
            return "macOS"
        } else {
            return "Unknown"
        }
    }

    $OS = Get-OperatingSystem

    # A configuration name is required.
    if (-not $ConfigName) {
        Write-Error "No configuration name was specified!"
        exit 1
    }

    # If the value type specified is a date or date and time, change it to "Date or Date Time" to be used by the function.
    if ($ValueType -eq "Date" -or $ValueType -eq "Date And Time") {
        $ValueType = "Date or Date Time"
    }    # Cross-platform configuration retrieval function
    function Get-ConfigValue {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter()]
            [String]$Source = "Auto"
        )

        $ConfigValue = $null

        # Determine configuration source
        switch ($Source) {
            "Registry" {
                if ($OS -eq "Windows") {
                    try {
                        $ConfigValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\SystemConfiguration" -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name
                    }
                    catch {
                        Write-Warning "Could not retrieve registry value for $Name"
                    }
                } else {
                    Write-Warning "Registry source not available on $OS"
                }
            }
            "EnvironmentVariable" {
                $ConfigValue = [System.Environment]::GetEnvironmentVariable($Name)
            }
            "ConfigFile" {
                # Example configuration file locations
                $ConfigPaths = switch ($OS) {
                    "Windows" { @("$env:ProgramData\SystemConfig\config.json", "$env:USERPROFILE\.config\config.json") }
                    "Linux" { @("/etc/systemconfig/config.json", "$HOME/.config/systemconfig/config.json") }
                    "macOS" { @("/usr/local/etc/systemconfig/config.json", "$HOME/.config/systemconfig/config.json") }
                    default { @() }
                }
                
                foreach ($ConfigPath in $ConfigPaths) {
                    if (Test-Path $ConfigPath) {
                        try {
                            $ConfigData = Get-Content $ConfigPath | ConvertFrom-Json
                            $ConfigValue = $ConfigData.$Name
                            break
                        }
                        catch {
                            Write-Warning "Could not parse configuration file: $ConfigPath"
                        }
                    }
                }
            }
            "Auto" {
                # Try environment variable first, then registry (Windows), then config files
                $ConfigValue = [System.Environment]::GetEnvironmentVariable($Name)
                
                if (-not $ConfigValue -and $OS -eq "Windows") {
                    try {
                        $ConfigValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\SystemConfiguration" -Name $Name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name
                    }
                    catch { }
                }
                
                if (-not $ConfigValue) {
                    # Try config files
                    $ConfigPaths = switch ($OS) {
                        "Windows" { @("$env:ProgramData\SystemConfig\config.json") }
                        "Linux" { @("/etc/systemconfig/config.json") }
                        "macOS" { @("/usr/local/etc/systemconfig/config.json") }
                        default { @() }
                    }
                    
                    foreach ($ConfigPath in $ConfigPaths) {
                        if (Test-Path $ConfigPath) {
                            try {
                                $ConfigData = Get-Content $ConfigPath | ConvertFrom-Json
                                $ConfigValue = $ConfigData.$Name
                                if ($ConfigValue) { break }
                            }
                            catch { }
                        }
                    }
                }
            }
        }

        if (-not $ConfigValue) {
            throw "Configuration value '$Name' not found"
        }        # Type conversion switch
        switch ($Type) {
            "Checkbox" {
                # Convert string/number to boolean
                if ($ConfigValue -eq "1" -or $ConfigValue -eq "true" -or $ConfigValue -eq $true) {
                    $true
                } else {
                    $false
                }
            }
            "Date or Date Time" {
                # Handle Unix timestamp or ISO date strings
                if ($ConfigValue -match '^\d+$') {
                    # Unix timestamp
                    $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds([int64]$ConfigValue)
                    $TimeZone = [TimeZoneInfo]::Local
                    [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
                } else {
                    # Try to parse as date string
                    try {
                        [DateTime]::Parse($ConfigValue)
                    }
                    catch {
                        Write-Warning "Could not parse '$ConfigValue' as date"
                        $ConfigValue
                    }
                }
            }
            "Decimal" {
                # Convert to double
                try {
                    [double]$ConfigValue
                }
                catch {
                    Write-Warning "Could not parse '$ConfigValue' as decimal"
                    $ConfigValue
                }
            }
            "Integer" {
                # Convert to integer
                try {
                    [int]$ConfigValue
                }
                catch {
                    Write-Warning "Could not parse '$ConfigValue' as integer"
                    $ConfigValue
                }
            }
            "Time" {
                # Handle time values (seconds since midnight or time strings)
                if ($ConfigValue -match '^\d+$') {
                    $Seconds = [int]$ConfigValue
                    $TimeSpan = [TimeSpan]::FromSeconds($Seconds)
                    $TimeSpan.ToString("hh\:mm\:ss")
                } else {
                    try {
                        $ParsedTime = [DateTime]::Parse($ConfigValue)
                        $ParsedTime.ToString("HH:mm:ss")
                    }
                    catch {
                        Write-Warning "Could not parse '$ConfigValue' as time"
                        $ConfigValue
                    }
                }
            }
            "Boolean" {
                # Convert to boolean
                if ($ConfigValue -eq "1" -or $ConfigValue -eq "true" -or $ConfigValue -eq $true -or $ConfigValue -eq "yes") {
                    $true
                } else {
                    $false
                }
            }
            default {
                # Return raw value
                $ConfigValue
            }
        }
    }
}
process {
    try {
        Write-Host "Retrieving configuration value for '$ConfigName'..."
        $ConfigValue = Get-ConfigValue -Name $ConfigName -Type $ValueType -Source $ConfigSource
        
        if ($ConfigValue) {
            Write-Host "Configuration value retrieved successfully."
            Write-Output $ConfigValue
        } else {
            Write-Warning "No value found for configuration '$ConfigName'"
        }
    }
    catch {
        Write-Error "Failed to retrieve configuration value: $($_.Exception.Message)"
        exit 1
    }
}
end {
    
    
    
}
