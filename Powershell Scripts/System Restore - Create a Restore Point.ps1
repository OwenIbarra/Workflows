# This script will create a restore point for the system drive. If system restore is disabled, you can use the -EnableIfDisabled switch to enable it before creating the restore point.
#Requires -Version 5.1

<#
.SYNOPSIS
    This script will create a restore point for the system drive. If system restore is disabled, you can use the -EnableIfDisabled switch to enable it before creating the restore point.

.DESCRIPTION
    This script will create a restore point for the system drive. If system restore is disabled, you can use the -EnableIfDisabled switch to enable it before creating the restore point.

.PARAMETER -Description
    Description of the restore point to be created. Default is "NinjaOne Restore Point."

.PARAMETER -EnableIfDisabled
    Enable system restore if it is found to be disabled. The restore point will be created after. 

.PARAMETER -ForceCreateSystemRestorePoint
    Forcibly creates a system restore point in case the registry key for time between restore points would block the creation. Sets the registry key back to its previous state once finished.

.EXAMPLE
    (No Parameters)

    [Info] Testing current system restore status...
    [Info] System restore is enabled.
    [Info] Creating system restore point.
    [Info] Restore point successfully created:

    CreationTime           Description            SequenceNumber EventType           RestorePointType
    ------------           -----------            -------------- ---------           ----------------
    12/23/2024 12:40:09 PM NinjaOne Restore Point 16             BEGIN_SYSTEM_CHANGE APPLICATION_INSTALL

.EXAMPLE
    -EnableIfDisabled

    [Info] Testing current system restore status...
    [Info] Enabling System Restore on system drive C:
    [Info] Enabled System Restore on system drive C:
    [Info] Creating system restore point.
    [Info] Restore point successfully created:

    CreationTime           Description            SequenceNumber EventType           RestorePointType
    ------------           -----------            -------------- ---------           ----------------
    12/23/2024 12:40:09 PM NinjaOne Restore Point 16             BEGIN_SYSTEM_CHANGE APPLICATION_INSTALL

.EXAMPLE
    -ForceCreateSystemRestorePoint

    [Info] Testing current system restore status...
    [Info] System restore is enabled.
    [Info] Temporarily changing registry settings to allow for restore point creation.
    Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore\SystemRestorePointCreationFrequency changed from 1440 to 0
    [Info] Restore point successfully created:

    CreationTime          Description            SequenceNumber EventType           RestorePointType
    ------------          -----------            -------------- ---------           ----------------
    12/27/2024 1:07:17 PM NinjaOne Restore Point 15             BEGIN_SYSTEM_CHANGE APPLICATION_INSTALL

    Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore\SystemRestorePointCreationFrequency changed from 0 to 1440
    [Info] Registry changes have been undone.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows 11
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$Description = "NinjaOne Restore Point",

    [Parameter()]
    [switch]$EnableIfDisabled = [System.Convert]::ToBoolean($env:enableIfDisabled),

    [Parameter()]
    [switch]$ForceCreateSystemRestorePoint = [System.Convert]::ToBoolean($env:ForceCreateSystemRestorePoint)
)

begin {
    
    if ($env:description -and $env:description -ne 'null'){
        $Description = $env:description
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-SystemRestore {
        $path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\"
        
        if (Test-Path $path){
            try {
                $RegValue = Get-ItemPropertyValue -Path $path -Name "RPSessionInterval" -ErrorAction Stop
            }
            catch{
                # if error, assume false
                return $false
            }
        }
        else{
            # if the reg path does not exist, assume false
            return $false
        }

        if ($RegValue -ge 1) {
            return $true
        }
        else {
            return $false
        }
    }

    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
    
        # Check if the specified registry path exists
        if (!(Test-Path -Path $Path)) {
            try {
                # If the path does not exist, create it
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            catch {
                # If there is an error creating the path, output an error message and exit
                Write-Host "[Error] Unable to create the registry path $Path for $Name. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
    
        # Check if the registry key already exists at the specified path
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
            # Retrieve the current value of the registry key
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            if ($CurrentValue -eq $Value) {
                Write-Host "$Path\$Name is already the value '$Value'."
            }
            else {
                try {
                    # Update the registry key with the new value
                    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
                }
                catch {
                    # If there is an error setting the key, output an error message and exit
                    Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                    Write-Host "[Error] $($_.Exception.Message)"
                    exit 1
                }
                # Output the change made to the registry key
                Write-Host "$Path\$Name changed from $CurrentValue to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
            }
        }
        else {
            try {
                # If the registry key does not exist, create it with the specified value and property type
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                # If there is an error creating the key, output an error message and exit
                Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            # Output the creation of the new registry key
            Write-Host "Set $Path\$Name to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    function Get-NextSystemRestorePointTime {
        try{
            $currentErrorActionPref = $ErrorActionPreference
            $ErrorActionPreference = "Stop"

            $date = @{Label = "Date"; Expression = {$_.ConvertToDateTime($_.CreationTime)}}

            $lastRestoreTime = (Get-ComputerRestorePoint | Sort-Object CreationTime | Sort-Object -Descending | Select-Object -First 1 | Select-Object $date).Date

            # if above is null, no restore points exist, so return a date in the past
            if (-not $lastRestoreTime){
                return (Get-Date).AddMinutes(-1)
            }
            
            $systemRestoreSettingsReg = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore"

            if (Test-Path $systemRestoreSettingsReg){
                $minutesBetweenRestores = (Get-ItemProperty $systemRestoreSettingsReg -Name "SystemRestorePointCreationFrequency" -ErrorAction SilentlyContinue).SystemRestorePointCreationFrequency

                # if no results from above, assume default of 24 hours/1440 minutes
                if ($null -eq $minutesBetweenRestores){
                    $minutesBetweenRestores = 1440
                }
            }
            else{
                # if the registry path does not exist, assume default of 24 hours/1440 minutes
                $minutesBetweenRestores = 1440
            }

            $restoreTime = $lastRestoreTime.AddMinutes($minutesBetweenRestores)
            $ErrorActionPreference = $currentErrorActionPref
            return $restoreTime
        }
        catch {
            Write-Host "[Error] Error finding next system restore point time."
            Write-Host "$($_.Exception.Message)"
            exit 1
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # check if system restore is enabled
    Write-Host "[Info] Testing current system restore status..."
    $systemRestoreStatus = Test-SystemRestore

    if ($systemRestoreStatus -eq $false -and -not $EnableIfDisabled){
        Write-Host "[Error] System restore is not enabled and -EnableIfDisabled was not used. Please run again with the -EnableIfDisabled option."
        exit 1
    }
    elseif ($systemRestoreStatus -eq  $false){
        try {
            Write-Host "[Info] Enabling System Restore on system drive $env:SystemDrive"
            Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction Stop
            Write-Host "[Info] Enabled System Restore on system drive $env:SystemDrive"
        }
        catch {
            Write-Host "[Error] Failed to enable System Restore:"
            Write-Host "$($_.Exception.Message)"
            exit 1
        }
    }
    else{
        Write-Host "[Info] System restore is enabled."
    }
    
    # create restore point if system restore is enabled
    try {
        $nextTime = Get-NextSystemRestorePointTime

        # returns true if the next valid system restore point time has already passed
        $readyToCreate = $nextTime -lt (Get-Date)

        if (-not $readyToCreate -and -not $ForceCreateSystemRestorePoint){
            Write-Host "[Error] Due to registry settings, you must wait until $nextTime to create a new restore point."
            Write-Host "You can change this by creating or modifying the SystemRestorePointCreationFrequency DWORD value (measured in minutes) at HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore."
            Write-Host "Or use the -ForceCreateSystemRestorePoint switch on this script."
            exit 1
        }
        else{
            if ($readyToCreate){
                Write-Host "[Info] Creating system restore point."

                Checkpoint-Computer -Description $Description -ErrorAction Stop

                # create restore point and output info
                Write-Host "[Info] Restore point successfully created:`n"
                (Get-ComputerRestorePoint | Sort-Object CreationTime | Select-Object -Last 1 | Format-Table -AutoSize | Out-String).Trim() + ("`n") | Write-Host
                $ExitCode = 0
            }
            else{
                $registryChanged = $false
                $regPath = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore"
                $key = "SystemRestorePointCreationFrequency"
                $currentValue = (Get-ItemProperty -Path $regPath -Name $key -ErrorAction SilentlyContinue).$Key

                Write-Host "[Info] Temporarily changing registry settings to allow for restore point creation."

                Set-RegKey -Path $regPath -Name $key -PropertyType DWord -Value 0
                $registryChanged = $true

                # create restore point and output info
                Checkpoint-Computer -Description $Description -ErrorAction Stop

                Write-Host "[Info] Restore point successfully created:`n"
                (Get-ComputerRestorePoint | Sort-Object CreationTime | Select-Object -Last 1 | Format-Table -AutoSize | Out-String).Trim() + ("`n") | Write-Host
                $ExitCode = 0
            }
        }
    }
    catch {
        Write-Host "[Error] Failed to create a system restore point."
        Write-Host "$($_.Exception.Message)"
        $ExitCode = 1
    }

    # set registry key back if it was changed, if it did not exist before it will be deleted
    if ($registryChanged){
        if ($null -eq $currentValue){
            Remove-ItemProperty -Path $regPath -Name $key
        }
        else{
            Set-RegKey -Path $regPath -name $key -PropertyType Dword -Value $currentValue
        }
        Write-Host "[Info] Registry changes have been undone."
    }
    exit $ExitCode
}
end {
    
    
    
}
