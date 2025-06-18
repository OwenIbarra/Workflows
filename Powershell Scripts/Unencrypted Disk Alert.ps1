# Returns the number of drives in the Unlocked and FullyDecrypted state.
#Requires -Version 2.0

<#
.SYNOPSIS
    Returns the number of drives in the Unlocked and FullyDecrypted state.
.DESCRIPTION
    Returns the number of drives in the Unlocked and FullyDecrypted state.
.EXAMPLE
    No parameters needed.
.EXAMPLE
    PS C:\> Get-UnencryptedDiskCount.ps1
    No Parameters needed
.OUTPUTS
    int
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    Uses manage-bde.exe or Get-BitLockerVolume depending on the version of PowerShell
    Release Notes:
    Initial Release
.COMPONENT
    Misc
#>

[CmdletBinding()]
param ()

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        { Write-Output $true }
        else
        { Write-Output $false }
    }
    function Get-DriveLetter {
        param()
        Get-Disk | Where-Object { $_.bustype -ne 'USB' } | Get-Partition | Where-Object { $_.DriveLetter } | Select-Object -ExpandProperty DriveLetter
    }
    function Invoke-ManageBDE {
        [CmdletBinding()]
        param ()
        # Check if manage-bde.exe is available
        if ((Get-Command -Name "manage-bde.exe" -ErrorAction SilentlyContinue)) {
            # Get physical drives
            Get-DriveLetter | ForEach-Object {
                $DriveLetter = $_
                $ReturnObj = [PSCustomObject]@{
                    MountPoint = "$_`:"
                }
                # Get data from manage-bde.exe and convert the text to objects for easier processing 
                (manage-bde.exe -status "$_`:") -split "`n" | Where-Object { $_ -like "*:*" } | ForEach-Object {
                    $First = ($_ -split ":")[0].Trim() -replace ' '
                    $Last = ($_ -split ":")[1].Trim() -replace ' '
                    if ($First -notlike "Name" -and $First -notlike "BitLocker Drive Encryption" -and $First -notlike "Volume $DriveLetter") {
                        if ($First -like "ConversionStatus") {
                            # Renames ConversionStatus to VolumeStatus to match Get-BitLockerVolume's output
                            $ReturnObj | Add-Member -MemberType NoteProperty -Name "VolumeStatus" -Value $Last
                        }
                        else {
                            $ReturnObj | Add-Member -MemberType NoteProperty -Name $First -Value $Last
                        }
                    }
                }
                $ReturnObj
            } | Select-Object MountPoint, LockStatus, VolumeStatus
        }
        else {
            Write-Host "Windows Feature BitLocker is not install."
            Write-Output 0
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    $Result = if ($PSVersionTable.PSVersion.Major -le 4) {
        Invoke-ManageBDE
    }
    else {
        try {
            Get-DriveLetter | Get-BitLockerVolume | Select-Object MountPoint, LockStatus, VolumeStatus
        }
        catch {
            Write-Output "Falling back on manage-bde.exe"
            Invoke-ManageBDE
        }
    }
    $UnencryptedDisks = if ($Result) {
        (($Result | Where-Object { "Unlocked" -like $_.LockStatus -and "FullyDecrypted" -like $_.VolumeStatus }).LockStatus).Count
    }
    else {
        (Get-DriveLetter).Count
    }
    
    # Return a count of Unlocked drives
    Write-Host "Unencrypted Disk Count: $UnencryptedDisks"
    # Return an exit code of 2 if more than 1 disk is unencrypted
    if ($UnencryptedDisks -gt 0) {
        exit 2
    }
    exit 0
}
end {}
