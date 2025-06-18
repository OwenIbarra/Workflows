# Monitors if user profiles have modern auth for Office 365 enabled or disabled.
#Requires -Version 5.1

<#
.SYNOPSIS
    Monitors if user profiles have modern auth for Office 365 enabled or disabled.
.DESCRIPTION
    Monitors if user profiles have modern auth for Office 365 enabled or disabled.
    Check if HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Common\Identity\EnableADAL is set to 1.
    Check if HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Identity\EnableADAL is set to 0.
    Returns an exit code of 1 if one user has modern auth disabled.
    Returns an exit code of 0 if all user have modern auth enabled.
.EXAMPLE
     No parameter needed.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes:
    Initial Release
#>

[CmdletBinding()]
param ()

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
    # Loop through each user's profile
    # Check if HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\15.0\Common\Identity\EnableADAL is set to 1
    # Check if HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Identity\EnableADAL is set to 1

    $Path = @("SOFTWARE\Microsoft\Office\15.0\Common\Identity", "SOFTWARE\Microsoft\Office\16.0\Common\Identity")
    $Name = "EnableADAL"

    $Script:FoundModernAuthDisabled = $false

    # Get each user profile SID and Path to the profile
    $UserProfiles = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
        Where-Object { $_.PSChildName -match "S-1-5-21-(\d+-?){4}$" } |
        Select-Object @{Name = "SID"; Expression = { $_.PSChildName } }, @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, @{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }

    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path -Path "Registry::HKEY_USERS\$($UserProfile.SID)") -eq $false) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) $($UserProfile.UserHive)" -Wait -WindowStyle Hidden
        }

        # Read the user's registry
        $Path | ForEach-Object {
            $Key = Join-Path -Path "Registry::HKEY_USERS\$($UserProfile.SID)" -ChildPath $($_)
            $Value = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue | Select-Object $Name -ExpandProperty $Name -ErrorAction SilentlyContinue
            if (
                (
                    $_ -like "*15.0*" -and
                    $Value -ne 1 -and
                    $(Test-Path -Path $Key -ErrorAction SilentlyContinue)
                ) -or
                (
                    $_ -like "*16.0*" -and
                    $Value -eq 0
                )
            ) {
                Write-Host "$($UserProfile.UserName) ModernAuth is not enabled."
                $Script:FoundModernAuthDisabled = $true
            }
        }
 
        # Unload NTuser.dat
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
        }
    }
    if ($FoundModernAuthDisabled) {
        Write-Output $false
        exit 1
    }
    else {
        Write-Output $true
        exit 0
    }
}
end {}
