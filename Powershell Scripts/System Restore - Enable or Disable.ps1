# Enables or Disables System Restore on System Drive(C:). Use caution when enabling on a system that contains system image backups(VSS).
#Requires -Version 5.1

<#
.SYNOPSIS
    Enables or Disables System Restore on System Drive(C:). Use caution when enabling on a system that contains system image backups(VSS).
.DESCRIPTION
    Enables or Disables System Restore on System Drive(C:). Use caution when enabling on a system that contains system image backups(VSS), as it will cause shadow copies to be deleted faster than normal.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##

PARAMETER: -Action "Enable"
    Enables System Restore.
.EXAMPLE
    -Action "Enable"
    ## EXAMPLE OUTPUT WITH Action ##
    [Info] Enabling System Restore
    [Info] Enabled System Restore

PARAMETER: -Action "Disable"
    Disables System Restore.
.EXAMPLE
    -Action "Disable"
    [Info] Disabling System Restore
    [Info] Disabled System Restore

PARAMETER: -Action "DisableAndRemove"
    Disables System Restore and removes all existing restore points.
.EXAMPLE
    -Action "DisableAndRemove"
    [Info] Disabling System Restore
    [Info] Disabled System Restore
    [Info] Removing Existing Restore Points
    [Info] Removed Existing Restore Points

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet("Enable", "Disable", "DisableAndRemove")]
    [string]$Action
)

begin {
    $EnableSystemRestore = $false
    $DisableSystemRestore = $false
    $RemoveExistingRestorePoints = $false
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # If the registry value is 1, System Restore is enabled.
    $RegValue = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\" -Name "RPSessionInterval" -ErrorAction SilentlyContinue

    $SystemRestoreStatus = if ($RegValue -ge 1) {
        # If either of the above conditions are met, System Restore is enabled.
        Write-Output "Enabled"
    }
    else {
        Write-Output "Disabled"
    }

    # Check if the action Script Variable was used
    if ($env:action -and $env:action -ne "null") {
        switch ($env:action) {
            "Enable" { $EnableSystemRestore = $true }
            "Disable" { $DisableSystemRestore = $true }
            "Disable and Remove Existing Restore Points" { $RemoveExistingRestorePoints = $true }
            Default {
                Write-Host -Object "[Error] Invalid Action"
                exit 1
            }
        }
        
    }
    # Check if the parameter Action was used
    else {
        switch ($Action) {
            "Enable" { $EnableSystemRestore = $true }
            "Disable" { $DisableSystemRestore = $true }
            "DisableAndRemove" { $RemoveExistingRestorePoints = $true }
            Default {
                Write-Host -Object "[Error] Invalid Action"
                exit 1
            }
        }
    }
    function Remove-ComputerRestorePoint {
        [CmdletBinding(SupportsShouldProcess = $True)]param(
            [Parameter(
                Position = 0,
                Mandatory = $true,
                ValueFromPipeline = $true
            )]
            $RestorePoint
        )
        begin {
            $fullName = "SystemRestore.DeleteRestorePoint"
            #check if the type is already loaded
            $isLoaded = $null -ne ([AppDomain]::CurrentDomain.GetAssemblies() | ForEach-Object { $_.GetTypes() } | Where-Object { $_.FullName -eq $fullName })
            if (!$isLoaded) {
                $SRClient = Add-Type -MemberDefinition @"
[DllImport ("Srclient.dll")]
public static extern int SRRemoveRestorePoint (int index);
"@ -Name DeleteRestorePoint -Namespace SystemRestore -PassThru
            }
        }
        process {
            foreach ($restorePoint in $RestorePoint) {
                if ($PSCmdlet.ShouldProcess("$($restorePoint.Description)", "Deleting Restore Point")) {
                    [SystemRestore.DeleteRestorePoint]::SRRemoveRestorePoint($restorePoint.SequenceNumber) | Out-Null
                }
            }
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Get Windows Install Drive from SystemRoot
    $TargetDrive = "$($env:SystemRoot -split "\\" | Select-Object -First 1)\"

    $ExitCode = 0
    # When the action is Enable
    if ($EnableSystemRestore) {
        if ($SystemRestoreStatus -eq "Enabled") {
            Write-Host -Object "[Info] System Restore is already enabled."
            exit 0
        }

        # Save the current value of the SystemRestorePointCreationFrequency registry key
        $OldValue = try {
            Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -ErrorAction Stop -WarningAction Stop
        }
        catch {
            # Return the default value of 1440 minutes if the registry key does not exist
            1440
        }
        if ($null -ne $OldValue) {
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value "0" -ErrorAction SilentlyContinue
        }

        # Enable System Restore
        try {
            Write-Host -Object "[Info] Enabling System Restore: $TargetDrive"
            Enable-ComputerRestore -Drive "$TargetDrive"
            Write-Host -Object "[Info] Enabled System Restore: $TargetDrive"
        }
        catch {
            Write-Host -Object "[Error] Failed to enable System Restore"
            $ExitCode = 1
        }

        try {
            Write-Host -Object "[Info] Creating restore point."

            # Create a new restore point
            Checkpoint-Computer -Description "Restore Point Created by Enable or Disable System Restore" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop -WarningAction Stop

            Write-Host -Object "[Info] Created Restore Point."
        }
        catch {
            Write-Host -Object "[Error] Failed to create restore point."
            $ExitCode = 1
        }

        # Restore the old value of the SystemRestorePointCreationFrequency registry key
        if ($null -ne $OldValue) {
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value $OldValue -ErrorAction SilentlyContinue
        }
    }
    # When the action is Disable
    elseif ($DisableSystemRestore) {
        if ($SystemRestoreStatus -eq "Disabled") {
            Write-Host -Object "[Info] System Restore is already disabled."
            exit 0
        }
        # Disable System Restore
        try {
            Write-Host -Object "[Info] Disabling System Restore: $TargetDrive"
            Disable-ComputerRestore -Drive "$TargetDrive"
            Write-Host -Object "[Info] Disabled System Restore: $TargetDrive"
        }
        catch {
            Write-Host -Object "[Error] Failed to disable System Restore"
            $ExitCode = 1
        }
    }
    # When the action is DisableAndRemove / Disable and Remove Existing Restore Points
    elseif ($RemoveExistingRestorePoints) {
        if ($SystemRestoreStatus -eq "Disabled") {
            Write-Host -Object "[Info] System Restore is already disabled."
            exit 0
        }
        # Remove all existing restore points
        try {
            Write-Host -Object "[Info] Removing Existing Restore Points"
            Get-ComputerRestorePoint | Remove-ComputerRestorePoint
            Write-Host -Object "[Info] Removed Existing Restore Points"
        }
        catch {
            Write-Host -Object "[Error] Failed to remove existing restore points"
            $ExitCode = 1
        }
        # Disable System Restore
        try {
            Write-Host -Object "[Info] Disabling System Restore: $TargetDrive"
            Disable-ComputerRestore -Drive "$TargetDrive"
            Write-Host -Object "[Info] Disabled System Restore: $TargetDrive"
        }
        catch {
            Write-Host -Object "[Error] Failed to disable System Restore"
            $ExitCode = 1
        }
    }
    exit $ExitCode
}
end {
    
    
    
}
