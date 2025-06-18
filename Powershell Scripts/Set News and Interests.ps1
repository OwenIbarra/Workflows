# Hides or shows the News and Interests tab in the taskbar. On Windows 11, it hides or shows the widgets tab.
#Requires -Version 5.1

<#
.SYNOPSIS
    Hides or shows the 'News and Interests' tab in the taskbar. On Windows 11, it hides or shows the widgets tab.
.DESCRIPTION
    Hides or shows the 'News and Interests' tab in the taskbar. On Windows 11, it hides or shows the widgets tab.
.EXAMPLE
    (No Parameters)
    
    WARNING: Hiding News and Interests from the taskbar for all users!
    Registry::HKEY_USERS\S-1-12-1-2117605486-1182246982-3318994623-3070967164\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa changed from 1 to 0
    Registry::HKEY_USERS\S-1-5-21-4122835015-3639794443-155648563-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa changed from 1 to 0
    WARNING: This script will take effect the next time the user completes a full sign-in or restarts.

PARAMETER: -Enable
    Reveals the 'News and Interests' tab in the taskbar.
.EXAMPLE
    -Enable

    Revealing News and Interests for all users!
    Registry::HKEY_USERS\S-1-12-1-2117605486-1182246982-3318994623-3070967164\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa changed from 0 to 1
    Registry::HKEY_USERS\S-1-5-21-4122835015-3639794443-155648563-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa changed from 0 to 1
    WARNING: This script will take effect the next time the user completes a full sign-in or restarts.

PARAMETER: -PreventChanges
    Should the end-user be able to modify this setting after it's been set with this script?
.EXAMPLE
    -PreventChanges
    
    WARNING: Hiding News and Interests from the taskbar for all users!
    Set Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh\AllowNewsAndInterests to 0
    WARNING: This script will take effect the next time the user completes a full sign-in or restarts.

PARAMETER: -RestartExplorer
    In order for this script to take immediate effect, explorer.exe will need to be restarted.
.EXAMPLE
    -RestartExplorer

    WARNING: Hiding News and Interests from the taskbar for all users!
    Registry::HKEY_USERS\S-1-12-1-2117605486-1182246982-3318994623-3070967164\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa changed from 1 to 0
    Registry::HKEY_USERS\S-1-5-21-4122835015-3639794443-155648563-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDa changed from 1 to 0
    WARNING: Restarting Explorer.exe

.OUTPUTS
    None
.NOTES
    Minimum Supported OS: Windows 10+
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$Enable,
    [Parameter()]
    [Switch]$PreventChanges = [System.Convert]::ToBoolean($env:preventChanges),
    [Parameter()]
    [Switch]$RestartExplorer = [System.Convert]::ToBoolean($env:restartExplorer)
)

begin {
    # Grabbing dynamic script variables
    if ($env:showOrHide -and $env:showOrHide -notlike "null") { if ($env:showOrHide -eq "Show") { $Enable = $True } }

    # Check if script is running with local admin privileges.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Check if script is running with system privileges.
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    # Get a list of all the user profiles for when the script is run as System.
    function Get-UserHives {
        param (
            [Parameter()]
            [ValidateSet('AzureAD', 'DomainAndLocal', 'All')]
            [String]$Type = "All",
            [Parameter()]
            [String[]]$ExcludedUsers,
            [Parameter()]
            [switch]$IncludeDefault
        )
    
        # User account SID's follow a particular pattern depending on if they're Azure AD or a Domain account or a local "workgroup" account.
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # We'll need the NTuser.dat file to load each user's registry hive. So we grab it if their account sid matches the above pattern. 
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } | 
                Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                @{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                @{Name = "Path"; Expression = { $_.ProfileImagePath } }
        }
    
        # There are some situations where grabbing the .Default user's info is needed.
        switch ($IncludeDefault) {
            $True {
                $DefaultProfile = "" | Select-Object UserName, SID, UserHive, Path
                $DefaultProfile.UserName = "Default"
                $DefaultProfile.SID = "DefaultProfile"
                $DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                $DefaultProfile.Path = "C:\Users\Default"
    
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.UserName }
            }
        }
    
        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
    }

    # Helper function for setting registry keys
    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
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
                Write-Host "[Error] Unable to set registry key for $Name at $Path please see below error!"
                Write-Host "[Error] $($_.Exception.Message)"
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
                Write-Host "[Error] Unable to set registry key for $Name at $Path please see below error!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }
    
    # Gets the OS Name E.g. Windows 10 Enterprise or Windows 11 Enterprise
    function Get-OSName {
        systeminfo | findstr /B /C:"OS Name"
    }

    $OSName = Get-OSName
}
process {
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # The registry key is different depending on if its Windows 10 or Windows 11
    if ($OSName -Like "*11*") {
        $AllUserPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" -ErrorAction Ignore).AllowNewsAndInterests
    }
    else {
        $AllUserPath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -ErrorAction Ignore).EnableFeeds
    }

    # Issues a warning prior to removing the registry key that prevents changes from end-users
    if ($AllUserPath -ge 0) {
        $EnableOrDisable = switch ($AllUserPath) {
            1 { "revealed" }
            default { "hidden" }
        }

        if (-not ($PreventChanges)) {
            Write-Warning "News and Interests is currently $EnableOrDisable for all users. Removing 'Prevent Changes' setting to replace it with individual user setting as requested."
            
            if ($OSName -Like "*11*") {
                Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests"
            }
            else {
                Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds"
            }
        }
    }

    if ($OSName -Like "*11*") {
        $KeyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh"
        $KeyName = "AllowNewsAndInterests"
        $Value = if ($Enable) { 1 }else { 0 }
    }
    else {
        $KeyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
        $KeyName = "EnableFeeds"
        $Value = if ($Enable) { 1 }else { 0 }
    }

    # Sets a per user registry key if the end-user lock isn't set
    if (-not ($PreventChanges)) {
        $UserProfiles = Get-UserHives -Type "All"

        $KeyPath = New-Object System.Collections.Generic.List[string]
        $LoadedProfiles = New-Object System.Collections.Generic.List[Object]

        Foreach ($UserProfile in $UserProfiles) {
            # Load User ntuser.dat if it's not already loaded
            If ((Test-Path "Registry::HKEY_USERS\$($UserProfile.SID)" -ErrorAction Ignore) -eq $false) {
                $LoadedProfiles.Add($UserProfile)
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            }
            if ($OSName -Like "*11*") {
                $KeyPath.Add("Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
            }
            else {
                $KeyPath.Add("Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Feeds")
            }
        }

        if ($OSName -Like "*11*") {
            $KeyName = "TaskbarDa"
            $Value = if ($Enable) { 1 }else { 0 }
        }
        else {
            $KeyName = "ShellFeedsTaskbarViewMode"
            $Value = if ($Enable) { 0 }else { 2 }
        }
    }

    # Change the message depending on if we're hiding or showing the menu
    if ($Enable) {
        Write-Host "Revealing News and Interests for all users!"
    }
    else {
        Write-Warning "Hiding News and Interests from the taskbar for all users!"
    }
    
    # Setting the registry key
    $KeyPath | ForEach-Object { Set-RegKey -Path $_ -Name $KeyName -Value $Value }

    # Unload any profiles we loaded up earlier (if any)
    Foreach ($LoadedProfile in $LoadedProfiles) {
        [gc]::Collect()
        Start-Sleep 1
        Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($LoadedProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
    }

    # Restart explorer.exe
    if ($RestartExplorer) {
        Write-Host "`nRestarting Explorer.exe as requested."

        # Stop all instances of Explorer
        Get-Process explorer | Stop-Process -Force
        
        Start-Sleep -Seconds 1

        # Restart Explorer if not running as System and Explorer is not already running
        if (!(Test-IsSystem) -and !(Get-Process -Name "explorer")) {
            Start-Process explorer.exe
        }
    }
    else {
        Write-Warning "This script will take effect the next time the user completes a full sign-in or restarts."
    }
}
end {
    
    
    
}
