# Gets the Last BIOS time from the startup section of task manager and alerts if it exceeds a threshold you specify.
#Requires -Version 5.1

<#
.SYNOPSIS
    Gets the Last BIOS time from the startup section of task manager and alerts if it exceeds a threshold you specify.
.DESCRIPTION
    Gets the Last BIOS time from the startup section of task manager and alerts if it exceeds a threshold you specify.
    Can save the result to a custom field.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    Last BIOS Time: 14.6s

PARAMETER: -BootCustomField "BootTime"
    Saves the boot time to this Text Custom Field.
.EXAMPLE
    -BootCustomField "BootTime"
    ## EXAMPLE OUTPUT WITH BootCustomField ##
    Last BIOS Time: 14.6s

PARAMETER: -Seconds 20
    Sets the threshold for when the boot time is greater than this number.
    In this case the boot time is over the threshold.
.EXAMPLE
    -Seconds 20
    ## EXAMPLE OUTPUT WITH Seconds ##
    Last BIOS Time: 14.6s
    [Error] Boot time exceeded threshold of 20s by 5.41s. Boot time: 14.6s

PARAMETER: -Seconds 10
    Sets the threshold for when the boot time is greater than this number.
    In this case the boot time is under the threshold.
.EXAMPLE
    -Seconds 10
    ## EXAMPLE OUTPUT WITH Seconds ##
    Last BIOS Time: 14.6s
    [Info] Boot time under threshold of 10s by 4.59s. Boot time: 14.6s

.OUTPUTS
    String
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    $Seconds,
    [String]$BootCustomField
)

begin {
    if ($env:bootCustomField -and $env:bootCustomField -notlike "null") {
        $BootCustomField = $env:bootCustomField
    }
    if ($env:bootTimeThreshold -and $env:bootTimeThreshold -notlike "null") {
        # Remove any non digits
        [double]$Seconds = $env:bootTimeThreshold -replace '[^0-9.]+'
    }

}
process {
    $Ticks = try {
        # Get boot time from performance event logs
        $PerfTicks = Get-WinEvent -FilterHashtable @{LogName = "Microsoft-Windows-Diagnostics-Performance/Operational"; Id = 100 } -MaxEvents 1 -ErrorAction SilentlyContinue | ForEach-Object {
            # Convert the event to XML and grab the Event node
            $eventXml = ([xml]$_.ToXml()).Event
            # Output boot time in ms
            [int64]($eventXml.EventData.Data | Where-Object { $_.Name -eq 'BootTime' }).InnerXml
        }
        # Get the boot POST time from the firmware, when available
        $FirmwareTicks = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "FwPOSTTime" -ErrorAction SilentlyContinue
        # Get the boot POST time from Windows, used as fall back
        $OsTicks = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "POSTTime" -ErrorAction SilentlyContinue
        # Use most likely to be accurate to least accurate
        if ($FirmwareTicks -gt 0) {
            $FirmwareTicks
        }
        elseif ($OsTicks -gt 0) {
            $OsTicks
        }
        elseif ($PerfTicks -and $PerfTicks -gt 0) {
            $PerfTicks
        }
        else {
            # Fall back to reading System event logs
            $StartOfBoot = Get-WinEvent -FilterHashtable @{LogName = 'System'; Id = 12 } -MaxEvents 1 | Select-Object -ExpandProperty TimeCreated
            $LastUpTime = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop | Select-Object @{Label = 'LastBootUpTime'; Expression = { $_.ConvertToDateTime($_.LastBootUpTime) } } | Select-Object -ExpandProperty LastBootUpTime
            New-TimeSpan -Start $LastUpTime -End $StartOfBoot -ErrorAction Stop | Select-Object -ExpandProperty TotalMilliseconds
        }
    }
    catch {
        Write-Host "[Error] Failed to get Last BIOS Time from registry."
        exit 2
    }

    $TimeSpan = [TimeSpan]::FromMilliseconds($Ticks)

    $BootTime = if ($TimeSpan.Days -gt 0) {
        "$($TimeSpan.Days)d, $($TimeSpan.Hours)h, $($TimeSpan.Minutes)m, $($TimeSpan.Seconds + [Math]::Round($TimeSpan.Milliseconds / 1000, 1))s"
    }
    elseif ($TimeSpan.Hours -gt 0) {
        "$($TimeSpan.Hours)h, $($TimeSpan.Minutes)m, $($TimeSpan.Seconds + [Math]::Round($TimeSpan.Milliseconds / 1000, 1))s"
    }
    elseif ($TimeSpan.Minutes -gt 0) {
        "$($TimeSpan.Minutes)m, $($TimeSpan.Seconds + [Math]::Round($TimeSpan.Milliseconds / 1000, 1))s"
    }
    elseif ($TimeSpan.Seconds -gt 0) {
        "$($TimeSpan.Seconds + [Math]::Round($TimeSpan.Milliseconds / 1000, 1))s"
    }
    else {
        # Fail safe output
        "$($TimeSpan.Days)d, $($TimeSpan.Hours)h, $($TimeSpan.Minutes)m, $($TimeSpan.Seconds + [Math]::Round($TimeSpan.Milliseconds / 1000, 1))s"
    }

    Write-Host "Last BIOS Time: $BootTime"

    if ($BootCustomField) {
    }

    if ($Seconds -gt 0) {
        if ($TimeSpan.TotalSeconds -gt $Seconds) {
            Write-Host "[Error] Boot time exceeded threshold of $($Seconds)s by $($TimeSpan.TotalSeconds - $Seconds)s. Boot time: $BootTime"
            exit 1
        }
        Write-Host "[Info] Boot time under threshold of $($Seconds)s by $($Seconds - $TimeSpan.TotalSeconds)s. Boot time: $BootTime"
    }
    exit 0
}
end {

}
