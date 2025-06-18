# Limit how much bandwidth a device can consume with updates and microsoft store updates. Please note 5Mbps will set a different speed limit than 5MBps.
#Requires -Version 5.1

<#
.SYNOPSIS
    Limit how much bandwidth a device can consume with updates and microsoft store updates. Please note 5Mbps will set a different speed limit than 5MBps.
.DESCRIPTION
    Limit how much bandwidth a device can consume with updates and microsoft store updates. Please note 5Mbps will set a different speed limit than 5MBps.
.EXAMPLE
    (No Parameters)

    C:\ProgramData\NinjaRMMAgent\scripting\customscript_gen_6.ps1 : No Speed Limit given?
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,customscript_gen_6.ps1

PARAMETER: -BackgroundSpeed "15Mbps"
    Limits the "background" bandwidth to 15Mbps replace "15Mbps" with your prefered speed limit.
.EXAMPLE
    -BackgroundSpeed "15Mbps"
    
    HKLM:SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DOMaxBackgroundDownloadBandwidth changed from 1920 to 1920

PARAMETER: -ForegroundSpeed "15Mbps"
    Limits the "foreground" bandwidth to 15Mbps replace "15Mbps" with your prefered speed limit.
.EXAMPLE
    -ForegroundSpeed "15Mbps"
    
    HKLM:SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DOMaxForegroundDownloadBandwidth changed from 1920 to 1920

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$BackgroundSpeed,
    [Parameter()]
    [String]$ForegroundSpeed
)

begin {

    if ($env:maxBackgroundDownloadSpeed -and $env:maxBackgroundDownloadSpeed -notlike "null") { $BackgroundSpeed = $env:maxBackgroundDownloadSpeed }
    if ($env:maxForegroundDownloadSpeed -and $env:maxForegroundDownloadSpeed -notlike "null") { $ForegroundSpeed = $env:maxForegroundDownloadSpeed }

    if (-not $BackgroundSpeed -and -not $ForegroundSpeed) {
        Write-Error "No Speed Limit given?"
        Exit 1
    }

    function Set-HKProperty {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet('DWord', 'QWord', 'String', 'ExpandedString', 'Binary', 'MultiString', 'Unknown')]
            $PropertyType = 'DWord'
        )
        if (-not $(Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            New-Item -Path $Path -Force | Out-Null
        }
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    function Get-Size {
        param (
            [string]$String
        )
        if ($String -Like 0) {
            return 0
        }
        switch -casesensitive -regex ($String) {
            'PB|pB' { [int64]$($String -replace '[^\d+]+') * 1PB; break }
            'Pb|pb' { [int64]$($String -replace '[^\d+]+') * 1PB / 8; break }
            'TB|tB' { [int64]$($String -replace '[^\d+]+') * 1TB; break }
            'Tb|tb' { [int64]$($String -replace '[^\d+]+') * 1TB / 8; break }
            'GB|gB' { [int64]$($String -replace '[^\d+]+') * 1GB; break }
            'Gb|gb' { [int64]$($String -replace '[^\d+]+') * 1GB / 8; break }
            'MB|mB' { [int64]$($String -replace '[^\d+]+') * 1MB; break }
            'Mb|mb' { [int64]$($String -replace '[^\d+]+') * 1MB / 8; break }
            'KB|kB' { [int64]$($String -replace '[^\d+]+') * 1KB; break }
            'Kb|kb' { [int64]$($String -replace '[^\d+]+') * 1KB / 8; break }
            'B|b' { [int64]$($String -replace '[^\d+]+') * 1; break }
            Default { [int64]$($String -replace '[^\d+]+') * 1MB / 8 }
        }
    }

    function ConvertTo-Kilobytes {
        param (
            [Parameter(ValueFromPipeline)]
            $Number
        )
        process {
            $Number / 1KB
        }
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    $Path = "HKLM:SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if ($BackgroundSpeed) { Set-HKProperty -Path $Path -Name DOMaxBackgroundDownloadBandwidth -Value $(Get-Size $BackgroundSpeed | ConvertTo-Kilobytes ) }
    if ($ForegroundSpeed) { Set-HKProperty -Path $Path -Name DOMaxForegroundDownloadBandwidth -Value $(Get-Size $ForegroundSpeed | ConvertTo-Kilobytes ) }
}
end {
    
    
    
}
