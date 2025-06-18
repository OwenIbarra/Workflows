# Enables or disables showing the file extensions in Windows Explorer.
#Requires -Version 5.1

<#
.SYNOPSIS
    Enables or disables showing the file extensions in Windows Explorer.
.DESCRIPTION
    Enables or disables showing the file extensions in Windows Explorer.

PARAMETER: -Action "Enable"
    Enables showing the file extensions in Windows Explorer.
.EXAMPLE
    -Action "Enable"
    ## EXAMPLE OUTPUT WITH Action ##
    [Info] Enabling showing file extensions for user tuser
    [Info] Successfully enabled showing file extensions for user tuser

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet("Enable", "Disable")]
    [String]$Action,
    [Parameter()]
    [Switch]$RestartExplorer = [System.Convert]::ToBoolean($env:restartExplorer)
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Test-IsSystem {
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
        # Check if the current identity's name matches "NT AUTHORITY*"
        # or if the identity represents the SYSTEM account
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }
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
    
        # Define the SID patterns to match based on the selected user type
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # Retrieve user profile information based on the defined patterns
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } | 
                Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                @{Name = "Username"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                @{Name = "Path"; Expression = { $_.ProfileImagePath } }
        }
    
        # If the IncludeDefault switch is set, add the Default profile to the results
        switch ($IncludeDefault) {
            $True {
                $DefaultProfile = "" | Select-Object Username, SID, UserHive, Path
                $DefaultProfile.Username = "Default"
                $DefaultProfile.SID = "DefaultProfile"
                $DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                $DefaultProfile.Path = "C:\Users\Default"
    
                # Exclude users specified in the ExcludedUsers list
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.Username }
            }
        }
    
        # Return the list of user profiles, excluding any specified in the ExcludedUsers list
        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.Username }
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
    $ExitCode = 0
}
process {
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }
    if (-not $Action) {
        Write-Host -Object "[Error] You must specify an action (Enable or Disable)"
        exit 1
    }

    # Check if the action is valid
    if ($Action -ne "Enable" -and $Action -ne "Disable") {
        Write-Host -Object "[Error] The action '$Action' is invalid. 'Enable' or 'Disable' are the only valid actions"
        exit 1
    }

    if ((Test-IsSystem)) {
        # When running as a system account or elevated

        # Local Machine

        # Set the registry key if the action is Enable
        if ($Action -eq "Enable") {
            try {
                Write-Host -Object "[Info] Enabling showing file extensions for local machine"
                Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force -ErrorAction Stop
                Write-Host -Object "[Info] Successfully enabled showing file extensions for local machine"
            }
            catch {
                Write-Host -Object "[Error] Failed to enable showing file extensions for local machine"
            }
        }

        # Set the registry key if the action is Disable
        if ($Action -eq "Disable") {
            try {
                Write-Host -Object "[Info] Disabling showing file extensions for local machine"
                Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -Force -ErrorAction Stop
                Write-Host -Object "[Info] Successfully disabled showing file extensions for local machine"
            }
            catch {
                Write-Host -Object "[Error] Failed to disable showing file extensions for local machine"
            }
        }

        # User Profiles

        # Get all user profiles on the machine
        $UserProfiles = Get-UserHives -Type "All"
        $ProfileWasLoaded = New-Object System.Collections.Generic.List[object]

        # Loop through each profile on the machine
        ForEach ($UserProfile in $UserProfiles) {
            # Load User ntuser.dat if it's not already loaded
            If (!(Test-Path -Path Registry::HKEY_USERS\$($UserProfile.SID) -ErrorAction SilentlyContinue)) {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
                $ProfileWasLoaded.Add($UserProfile)
            }
            # Set the registry key if the action is Enable
            if ($Action -eq "Enable") {
                try {
                    Write-Host -Object "[Info] Enabling showing file extensions for user $($UserProfile.UserName)"
                    Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force -ErrorAction Stop
                    Write-Host -Object "[Info] Successfully enabled showing file extensions for user $($UserProfile.UserName)"
                }
                catch {
                    Write-Host -Object "[Error] Failed to enable showing file extensions for user $($UserProfile.UserName)"
                }
            }

            # Set the registry key if the action is Disable
            if ($Action -eq "Disable") {
                try {
                    Write-Host -Object "[Info] Disabling showing file extensions for user $($UserProfile.UserName)"
                    Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -Force -ErrorAction Stop
                    Write-Host -Object "[Info] Successfully disabled showing file extensions for user $($UserProfile.UserName)"
                }
                catch {
                    Write-Host -Object "[Error] Failed to disable showing file extensions for user $($UserProfile.UserName)"
                }
            }
        }

        # If user profiles were loaded, unload the profiles
        if ($ProfileWasLoaded.Count -gt 0) {
            ForEach ($UserProfile in $ProfileWasLoaded) {
                # Unload NTuser.dat
                [gc]::Collect()
                Start-Sleep 1
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
            }
        }
    }
    else {
        # When running as a user account

        # Set the registry key if the action is Enable
        if ($Action -eq "Enable") {
            try {
                Write-Host -Object "[Info] Enabling showing file extensions for user $($env:USERNAME)"
                Set-RegKey -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Force -ErrorAction Stop
                Write-Host -Object "[Info] Successfully enabled showing file extensions for user $($env:USERNAME)"
            }
            catch {
                Write-Host -Object "[Error] Failed to enable showing file extensions for user $($env:USERNAME)"
            }
        }

        # Set the registry key if the action is Disable
        if ($Action -eq "Disable") {
            try {
                Write-Host -Object "[Info] Disabling showing file extensions for user $($env:USERNAME)"
                Set-RegKey -Path "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -Force -ErrorAction Stop
                Write-Host -Object "[Info] Successfully disabled showing file extensions for user $($env:USERNAME)"
            }
            catch {
                Write-Host -Object "[Error] Failed to disable showing file extensions for user $($env:USERNAME)"
            }
        }
    }

    # Check if the $RestartExplorer flag is set
    if ($RestartExplorer) {
        # Display a message indicating that Explorer.exe is being restarted
        Write-Host "`nRestarting Explorer.exe as requested."

        try {
            # Stop all instances of Explorer
            if (Test-IsSystem) {
                Get-Process -Name "explorer" | Stop-Process -Force -ErrorAction Stop
            }
            else {
                Get-Process -Name "explorer" | Where-Object { $_.SI -eq (Get-Process -PID $PID).SessionId } | Stop-Process -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Host -Object "[Error] Failed to stop explorer.exe"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
        
        # Pause for 1 second to ensure processes have fully stopped before restarting
        Start-Sleep -Seconds 1
    
        # If not running as the System account and Explorer.exe is not already running, start a new instance
        if (!(Test-IsSystem) -and !(Get-Process -Name "explorer" -ErrorAction SilentlyContinue)) {
            try {
                Start-Process -FilePath "$env:SystemRoot\explorer.exe" -Wait -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to start explorer.exe"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                $ExitCode = 1
            }
        }
    }
    else {
        # If $RestartExplorer is not set, warn the user that they may need to manually restart Explorer.exe
        Write-Host -Object ""
        Write-Warning -Message "You may need to restart Explorer.exe for the script to take effect immediately."
    }

    # Exit the script with the predefined $ExitCode.
    exit $ExitCode
}
end {
    
    
    
}
