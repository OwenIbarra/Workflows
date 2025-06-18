# Add an antivirus to the device details or override the existing antivirus information.
#Requires -Version 5.1

<#
.SYNOPSIS
    Add an antivirus to the device details or override the existing antivirus information.
.DESCRIPTION
    Add an antivirus to the device details or override the existing antivirus information.
.EXAMPLE
    -AntivirusName "My AV" -AntivirusVersion "1.0.1" -AntivirusStatus "Out-of-Date" -AntivirusState "ON"

    Creating customization folder.


        Directory: C:\ProgramData\NinjaRMMAgent


    Mode                 LastWriteTime         Length Name                                                                 
    ----                 -------------         ------ ----                                                                 
    d-----         6/19/2024   4:09 PM                Customization                                                        
    Successfully created customization folder.

    Applying override.
    Successfully applied override.

PARAMETER: -AntivirusName "ReplaceMeWithNameOfAnAntivirus"
    Name of the antivirus you would like to appear in the device details.

PARAMETER: -AntivirusVersion "1.0.2"
    Specify the version number of the antivirus.

PARAMETER: -AntivirusStatus "Up-to-Date"
    Specify whether the antivirus definitions are up-to-date, out-of-date, or unknown.

PARAMETER: -AntivirusState "ON"
    Specify the current status of the antivirus.

PARAMETER: -Append
    Append or update an existing override.
    
PARAMETER: -RemoveOverride
    Remove all existing overrides.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$AntivirusName,
    [Parameter()]
    [String]$AntivirusVersion,
    [Parameter()]
    [String]$AntivirusStatus,
    [Parameter()]
    [String]$AntivirusState,
    [Parameter()]
    [Switch]$Append = [System.Convert]::ToBoolean($env:append),
    [Parameter()]
    [Switch]$RemoveOverride = [System.Convert]::ToBoolean($env:removeOverride)
)

begin {
    # Replace command line paramets with the form variables if used.
    if ($env:avName -and $env:avName -notlike "null") { $AntivirusName = $env:avName }
    if ($env:avVersion -and $env:avVersion -notlike "null") { $AntivirusVersion = $env:avVersion }
    if ($env:avStatus -and $env:avStatus -notlike "null") { $AntivirusStatus = $env:avStatus }
    if ($env:avState -and $env:avState -notlike "null") { $AntivirusState = $env:avState }

    # Check if RemoveOverride is set and any of the other parameters are also set
    if ($RemoveOverride -and ($AntivirusState -or $AntivirusStatus -or $AntivirusVersion -or $AntivirusName -or $Append)) {
        Write-Host -Object "[Error] Cannot remove an override and add an override at the same time."
        exit 1
    }

    # Check if AntivirusName is not provided and RemoveOverride is not set
    if (!$AntivirusName -and !$RemoveOverride) {
        Write-Host $RemoveOverride
        if ($Append) {
            Write-Host -Object "[Error] Antivirus name was not given. The antivirus name is required when updating or adding a new override!"
        }
        else {
            Write-Host -Object "[Error] Antivirus name was not given. Antivirus name, state, and status are required when adding a new override!"
        }

        exit 1
    }

    # Validate AntivirusVersion for invalid characters
    if ($AntivirusVersion -and $AntivirusVersion -match '[^0-9\.]') {
        Write-Host -Object "[Error] The antivirus version given contains an invalid character. Only the following characters are allowed: '0-9' and '.'"
        exit 1
    }

    # Check if AntivirusStatus is not provided and neither RemoveOverride nor Append is set
    if (!$AntivirusStatus -and !$RemoveOverride -and !$Append) {
        Write-Host -Object "[Error] Antivirus status was not given. Antivirus name, state, and status are required!"
        exit 1
    }

    # Define valid antivirus statuses
    $ValidStatus = "Up-to-Date", "Out-of-Date", "Unknown"
    # Check if the provided AntivirusStatus is valid
    if ($AntivirusStatus -and $ValidStatus -notcontains $AntivirusStatus) {
        Write-Host -Object "[Error] An invalid antivirus status was given. Only the following statuses are valid: 'Up-to-Date', 'Out-of-Date', and 'Unknown'."
        exit 1
    }

    # Check if AntivirusState is not provided and neither RemoveOverride nor Append is set
    if (!$AntivirusState -and !$RemoveOverride -and !$Append) {
        Write-Host -Object "[Error] Antivirus state was not given. Antivirus name, state, and status are required!"
        exit 1
    }

    # Define valid antivirus states
    $ValidState = "ON", "OFF", "EXPIRED", "SNOOZED", "UNKNOWN"
    # Check if the provided AntivirusState is valid
    if ($AntivirusState -and $ValidState -notcontains $AntivirusState) {
        Write-Host -Object "[Error] An invalid antivirus state was given. Only the following states are valid: 'ON', 'OFF', 'EXPIRED', 'SNOOZED', and 'UNKNOWN'."
        exit 1
    }

    # Check if the NinjaRMMAgent directory exists
    if (!(Test-Path -Path "$env:ProgramData\NinjaRMMAgent")) {
        Write-Host -Object "[Error] Ninja Agent is not present at '$env:ProgramData\NinjaRMMAgent'."
        exit 1
    }

    # Function to check if the script is running with elevated privileges
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Set ExitCode to 0 if it is not already set
    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access denied. Please run with administrator privileges."
        exit 1
    }

    # Check if RemoveOverride is set
    if ($RemoveOverride) {
        # Check if the antivirus override file exists
        if (Test-Path -Path "$env:ProgramData\NinjaRMMAgent\Customization\av_override.json" -ErrorAction SilentlyContinue) {
            Write-Host -Object "Removing $env:ProgramData\NinjaRMMAgent\Customization\av_override.json file."

            # Attempt to remove the antivirus override file
            try {
                Remove-Item -Path "$env:ProgramData\NinjaRMMAgent\Customization\av_override.json" -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to remove antivirus override."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
        else {
            Write-Host -Object "Antivirus override is not currently set."
        }

        exit $ExitCode
    }

    # Check if the Customization directory exists, if not, create it
    if (!(Test-Path -Path "$env:ProgramData\NinjaRMMAgent\Customization" -ErrorAction SilentlyContinue)) {
        try {
            Write-Host -Object "Creating customization folder."
            New-Item -Path "$env:ProgramData\NinjaRMMAgent\Customization" -ItemType Directory -Force -ErrorAction Stop
            Write-Host -Object "Successfully created customization folder.`n"
        }
        catch {
            Write-Host -Object "[Error] Unable to create customization folder."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Initialize a list to hold antivirus overrides
    $AntivirusOverrides = New-Object System.Collections.Generic.List[Object]

    # If Append is set and the antivirus override file exists, retrieve current overrides
    if ($Append -and (Test-Path -Path "$env:ProgramData\NinjaRMMAgent\Customization\av_override.json" -ErrorAction SilentlyContinue)) {
        try {
            $CurrentOverrides = Get-Content -Path "$env:ProgramData\NinjaRMMAgent\Customization\av_override.json" -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop | Select-Object -ExpandProperty "av_override" -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Failed to retrieve current overrides."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        # Iterate over current overrides to update or add new overrides
        $CurrentOverrides | ForEach-Object {
            if ($AntivirusName -notmatch [Regex]::Escape($_.av_name)) {
                $AntivirusOverrides.Add($_)
                return
            }

            Write-Host -Object "An existing antivirus with the same name was detected. Updating the existing entry.`n"

            $AntivirusOverrides.Add(
                [PSCustomObject]@{
                    av_name    = $AntivirusName
                    av_version = if ($AntivirusVersion) { $AntivirusVersion }else { $_.av_version }
                    av_status  = if ($AntivirusStatus) { $AntivirusStatus }else { $_.av_status }
                    av_state   = if ($AntivirusState) { $AntivirusState }else { $_.av_state }
                }
            )

            $UpdatedOverride = $True
        }
    }

    # If Append is set but no override was updated, check for required parameters
    if ($Append -and !$UpdatedOverride -and (!$AntivirusStatus -or !$AntivirusState)) {
        Write-Host -Object "[Error] Antivirus name, state, and status are required when adding a new override!"
        exit 1
    }
    elseif ($Append) {
        Write-Host -Object "Adding override to the existing list of overrides.`n"
    }

    # If no override was updated, add a new override
    if (!$UpdatedOverride) {
        $AntivirusOverrides.Add(
            [PSCustomObject]@{
                av_name    = $AntivirusName
                av_version = $AntivirusVersion
                av_status  = $AntivirusStatus
                av_state   = $AntivirusState
            }
        )
    }

    # Attempt to apply the override by writing to the override file
    try {
        Write-Host -Object "Applying override."
        $AntivirusOverrideJSON = [PSCustomObject]@{
            av_override = $AntivirusOverrides
        } | ConvertTo-Json -ErrorAction Stop

        $AntivirusOverrideJSON | Out-File -FilePath "$env:ProgramData\NinjaRMMAgent\Customization\av_override.json" -Encoding "utf8" -Force -ErrorAction Stop
        Write-Host -Object "Successfully applied override."
    }
    catch {
        Write-Host -Object "[Error] Unable to create override."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    exit $ExitCode
}
end {
    
    
    
}
