# Enable or disable the viewing of hidden files and folders for all users (when run as System) or just the current user (when run as Current Logged On User).
#Requires -Version 5.1

<#
.SYNOPSIS
    Enable or disable the viewing of hidden files and folders for all users (when run as 'System') or just the current user (when run as 'Current Logged On User').
.DESCRIPTION
    Enable or disable the viewing of hidden files and folders for all users (when run as 'System') or just the current user (when run as 'Current Logged On User').
.EXAMPLE
    -Action "Enable"

    Enabling 'Show hidden files and folders' for all users.

    Enabling 'Show hidden files and folders' for user 'tuser'.
    Registry::HKEY_USERS\S-1-5-21-2311417250-918970610-4221123468-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden changed from 1 to 1

    Enabling 'Show hidden files and folders' for user 'Administrator'.
    Registry::HKEY_USERS\S-1-5-21-2311417250-918970610-4221123468-500\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden changed from 2 to 1

    Finished enabling 'Show hidden files and folders'.
    
    WARNING: You may need to restart Explorer.exe for the script to take effect immediately.

PARAMETER: -Action "ReplaceMeWithYourDesiredAction"
    Specify whether you would like to disable or enable the viewing of hidden files or folders. Valid actions are 'Enable' or 'Disable'.

PARAMETER: -RestartExplorer
    You may need to restart explorer.exe for this script to take effect immediately. Use this switch to do so upon completion.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action,
    [Parameter()]
    [Switch]$RestartExplorer = [System.Convert]::ToBoolean($env:restartExplorer)
)

begin {
    # Check if the environment variable 'action' is set and is not null
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }

    # If $Action has a value, trim any leading or trailing whitespace
    if ($Action) {
        $Action = $Action.Trim()
    }

    # If $Action is empty or null after trimming, display an error message indicating that an action must be specified
    if (!$Action) {
        Write-Host -Object "[Error] You must specify an action."
        exit 1
    }

    # Define a list of valid actions: "Enable" and "Disable"
    $ValidActions = "Enable", "Disable"

    # Check if the value of $Action is not one of the valid actions
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] Invalid action '$Action' provided. Please specify either 'Enable' or 'Disable'."
        exit 1
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
            try {
                Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction Stop |
                    Where-Object { $_.PSChildName -match $Pattern } | 
                    Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                    @{Name = "Username"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                    @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                    @{Name = "Path"; Expression = { $_.ProfileImagePath } }
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
            }
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
    function Test-IsSystem {
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
        # Check if the current identity's name matches "NT AUTHORITY*"
        # or if the identity represents the SYSTEM account
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Retrieve all user profile registry hives (including system profiles).
    $UserProfiles = Get-UserHives -Type "All"

    # Check if the script is not running as the system account.
    if (!(Test-IsSystem)) {
        # Depending on the value of $Action, display the corresponding message for the current user.
        switch ($Action) {
            "Enable" { Write-Host -Object "Enabling 'Show hidden files and folders' for the current user." }
            "Disable" { Write-Host -Object "Disabling 'Show hidden files and folders' for the current user." }
        }

        # Filter user profiles to only include the current user's SID.
        try {
            $UserProfiles = $UserProfiles | Where-Object { $_.SID -match "$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)" }
        }
        catch {
            # If an error occurs (e.g., failed to retrieve the current user's SID), display an error and exit.
            Write-Host -Object "[Error] Failed to get current user's SID."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        # If running as the system account, display a message for all users depending on the value of $Action.
        switch ($Action) {
            "Enable" { Write-Host -Object "Enabling 'Show hidden files and folders' for all users." }
            "Disable" { Write-Host -Object "Disabling 'Show hidden files and folders' for all users." }
        }
    }

    # Create a list to track which user profiles had their NTuser.dat loaded.
    $ProfileWasLoaded = New-Object System.Collections.Generic.List[object]

    # Check if any user profiles were retrieved.
    if (!$UserProfiles) {
        Write-Host -Object "[Error] No user profiles found."
        exit 1
    }

    # Iterate through each user profile.
    ForEach ($UserProfile in $UserProfiles) {
        # Check if the NTuser.dat file (the user's registry hive) is not already loaded for the user.
        If (!(Test-Path -Path Registry::HKEY_USERS\$($UserProfile.SID) -ErrorAction SilentlyContinue)) {
            # Load the user's NTuser.dat into the registry under HKEY_USERS using reg.exe.
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            
            # Add the profile to the list of loaded profiles for later unloading.
            $ProfileWasLoaded.Add($UserProfile)
        }
    }

    # Set the appropriate registry value for hidden files based on the $Action.
    switch ($Action) {
        "Enable" { $HiddenFilesValue = 1 }
        "Disable" { $HiddenFilesValue = 2 }
    }

    # Iterate through each user profile to apply the registry change.
    ForEach ($UserProfile in $UserProfiles) {
        $CurrentHiddenFilesOption = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Hidden"

        # If the requested action has already been applied, display a message indicating the action has already been applied for the user.
        if ($HiddenFilesValue -eq $CurrentHiddenFilesOption) {
            switch ($Action) {
                "Enable" { Write-Host -Object "`n'Show hidden files and folders' is already enabled for user '$($UserProfile.Username)'." }
                "Disable" { Write-Host -Object "`n'Show hidden files and folders' is already disabled for user '$($UserProfile.Username)'." }
            }
            continue
        }

        # Display a message indicating the action being applied for the user.
        switch ($Action) {
            "Enable" { Write-Host -Object "`nEnabling 'Show hidden files and folders' for user '$($UserProfile.Username)'." }
            "Disable" { Write-Host -Object "`nDisabling 'Show hidden files and folders' for user '$($UserProfile.Username)'." }
        }

        # Modify the registry key to set the visibility of hidden files and folders for the user.
        Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value $HiddenFilesValue
    }

    # Display a final message indicating that the process is complete.
    switch ($Action) {
        "Enable" { Write-Host -Object "`nFinished enabling 'Show hidden files and folders'." }
        "Disable" { Write-Host -Object "`nFinished disabling 'Show hidden files and folders'." }
    }

    # Unload NTuser.dat for any profiles that were loaded earlier.
    if ($ProfileWasLoaded.Count -gt 0) {
        ForEach ($UserProfile in $ProfileWasLoaded) {
            # Unload NTuser.dat
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
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
