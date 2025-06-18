# Enables or Disabled Windows 10 Linguistic Data Collection, Advertising ID, and Telemetry
#Requires -Version 5.1

<#
.SYNOPSIS
    Enables or Disabled Windows 10 Linguistic Data Collection, Advertising ID, and Telemetry
.DESCRIPTION
    Enables or Disabled Windows 10 Linguistic Data Collection, Advertising ID, and Telemetry
.EXAMPLE
    No Params needed to Disable Windows 10 Linguistic Data Collection, Advertising ID, and Telemetry
.EXAMPLE
     -Enable
    Enables Linguistic Data Collection, Advertising ID, and Telemetry
.EXAMPLE
    PS C:\> Set-Windows10KeyLogger.ps1
    Disables Windows 10 Linguistic Data Collection, Advertising ID, and Telemetry
.EXAMPLE
    PS C:\> Set-Windows10KeyLogger.ps1 -Enable
    Enables Windows 10 Linguistic Data Collection, Advertising ID, and Telemetry
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Renamed script and added Script Variable support, Updated Set-ItemProp
.COMPONENT
    OSSecurity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$Enable
)

begin {
    if ($env:enableOrDisable -and $env:enableOrDisable -notlike "null") { 
        switch ($env:enableOrDisable) {
            "Enable" { $Enable = $True }
            "Disable" { $Enable = $False }
        }
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        { Write-Output $true }
        else
        { Write-Output $false }
    }
    function Set-ItemProp {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
        # Do not output errors and continue
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
        if (-not $(Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            New-Item -Path $Path -Force | Out-Null
        }
        if ((Get-ItemProperty -Path $Path -Name $Name)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = Get-ItemProperty -Path $Path -Name $Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error $_
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $(Get-ItemProperty -Path $Path -Name $Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error $_
            }
            Write-Host "Set $Path$Name to $(Get-ItemProperty -Path $Path -Name $Name)"
        }
        $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Continue
    }
    $Type = "DWORD"
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    $Value = if ($Enable) { 1 }else { 0 }

    try {
        @(
            # Linguistic Data Collection
            [PSCustomObject]@{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput"
                Name = "AllowLinguisticDataCollection"
            }
            # Advertising ID
            [PSCustomObject]@{
                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
                Name = "Enabled"
            }
            # Telemetry
            [PSCustomObject]@{
                Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
                Name = "AllowTelemetry"
            }
        ) | ForEach-Object {
            Set-ItemProp -Path $_.Path -Name $_.Name -Value $Value -PropertyType $Type
            Write-Host "$($_.Path)\$($_.Name) set to $(Get-ItemPropertyValue -Path $_.Path -Name $_.Name)"
        }

        if ($Enable) {
            Write-Host "Enabling DiagTrack Services"
            Get-Service -Name DiagTrack | Set-Service -StartupType Automatic | Start-Service
        }
        else { 
            Write-Host "Disabling DiagTrack Services"
            Get-Service -Name DiagTrack | Set-Service -StartupType Disabled | Stop-Service
        }

        Write-Host "DiagTrack Service status: $(Get-Service -Name DiagTrack | Select-Object -Property Status -ExpandProperty Status)"
        Write-Host "DiagTrack Service is set to: $(Get-Service -Name dmwappushservice | Select-Object -Property StartType -ExpandProperty StartType)"

        if ($Enable) {
            Get-Service -Name dmwappushservice | Set-Service -StartupType Manual
        }
        else { 
            Get-Service -Name dmwappushservice | Set-Service -StartupType Disabled | Stop-Service
        }

        Write-Host "dmwappushservice Service status: $(Get-Service -Name dmwappushservice | Select-Object -Property Status -ExpandProperty Status)"
        Write-Host "dmwappushservice Service is set to: $(Get-Service -Name dmwappushservice | Select-Object -Property StartType -ExpandProperty StartType)"

        $tasks = "SmartScreenSpecific", "ProgramDataUpdater", "Microsoft Compatibility Appraiser", "AitAgent", "Proxy", "Consolidator",
        "KernelCeipTask", "BthSQM", "CreateObjectTask", "WinSAT", #"Microsoft-Windows-DiskDiagnosticDataCollector", # This is disabled by default
        "GatherNetworkInfo", "FamilySafetyMonitor", "FamilySafetyRefresh", "SQM data sender", "OfficeTelemetryAgentFallBack",
        "OfficeTelemetryAgentLogOn"
        
        if ($Enable) {
            Write-Host "Enabling telemetry scheduled tasks"
            $tasks | ForEach-Object {
                Write-Host "Enabling $_ Scheduled Task"
                # Note: ErrorAction set to SilentlyContinue so as to skip over any missing tasks. Enable-ScheduledTask will still error if it can't be enabled.
                Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Enable-ScheduledTask
                $State = Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Select-Object State -ExpandProperty State
                Write-Host "Scheduled Task: $_ is $State"
            }
        }
        else { 
            Write-Host "Disabling telemetry scheduled tasks"
            $tasks | ForEach-Object {
                Write-Host "Disabling $_ Scheduled Task"
                # Note: ErrorAction set to SilentlyContinue so as to skip over any missing tasks. Disable-ScheduledTask will still error if it can't be disabled.
                Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Disable-ScheduledTask
                $State = Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Select-Object State -ExpandProperty State
                Write-Host "Scheduled Task: $_ is $State"
            }
        }
    }
    catch {
        Write-Error $_
        exit 1
    }
    
    gpupdate.exe /force
    exit 0
}
end {
    
    
    
}


