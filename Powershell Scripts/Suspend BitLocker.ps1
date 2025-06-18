# Suspends BitLocker Protection until after the next restart. Can optionally restart the computer once suspended.
#Requires -Version 5.1

<#
.SYNOPSIS
    Suspends BitLocker Protection until after the next restart. Can optionally restart the computer once suspended.
.DESCRIPTION
    Suspends BitLocker Protection until after the next restart. Can optionally restart the computer once suspended.
.EXAMPLE
    (No Parameters)

    Checking for Bitlocker Volumes...
    Bitlocker Volumes found!

    Drive RecoveryPassword                                                Status
    ----- ----------------                                                ------
    C:    652795-525382-638803-450769-280214-250415-444829-276023 FullyEncrypted



    Suspending Found Volumes
    Suspended Drive C:

PARAMETER: -Restart
    Restart the computer after suspending BitLocker protection.

PARAMETER: -RestartIfNoEncryption
    Restart the computer even if no BitLocker protection was found.

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2016
    Release Notes:
    Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$Restart = [System.Convert]::ToBoolean($env:restart),
    [Parameter()]
    [Switch]$RestartIfNoEncryption = [System.Convert]::ToBoolean($env:restartRegardlessOfBitlockerStatus)
)

begin {
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

    Write-Host "Checking for BitLocker Volumes..."
    $BitLockerVolumes = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "On" } | ForEach-Object {
        [PSCustomObject]@{
            Drive            = $_.MountPoint
            RecoveryPassword = $_.KeyProtector | Where-Object { $_.RecoveryPassword } | Select-Object -ExpandProperty RecoveryPassword
            Status           = $_.VolumeStatus
        }
    }

    if ($BitlockerVolumes) {
        Write-Host "BitLocker Volumes found!"
        $BitLockerVolumes | Format-Table -AutoSize | Out-String | Write-Host

        Write-Host "Suspending Found Volumes"
        $BitlockerVolumes | ForEach-Object {
            try {
                Suspend-BitLocker -MountPoint $_.Drive -RebootCount 1 -ErrorAction Stop | Out-Null
                Write-Host "Suspended Drive $($_.Drive)"
            }
            catch {
                Write-Error "Failed to suspend drive $($_.Drive)!"
                Exit 1
            }
        }
    }else{
        Write-Warning "No BitLocker Volumes found with protection turned on?"
        if(-not $RestartIfNoEncryption){
            Exit 1
        }
    }

    if(($Restart -or $RestartIfNoEncryption) -and ($BitLockerVolumes -or $RestartIfNoEncryption)){
        Write-Host "Scheduling restart for 30 seconds from now."

        Start-Process cmd.exe -ArgumentList "/c shutdown.exe /r /t 30" -Wait -NoNewWindow
    }
    
}
end {
    
    
    
}
