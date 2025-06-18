# Enable or Disable Spotlight and Suggestions in the Start Menu.
#Requires -Version 5.1

<#
.SYNOPSIS
    Enable or Disable Spotlight and Suggestions in the Start Menu.
.DESCRIPTION
    Enable or Disable Spotlight and Suggestions in the Start Menu.
.EXAMPLE
    (No Parameters)

    On Windows 11, only recommendations for tips, shortcuts, and new apps are disabled/enabled from the Start Menu.
    Attempting to Disable Spotlight and Start Menu Suggestions
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338389Enabled changed from 0 to 0
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338388Enabled changed from 0 to 0
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SystemPaneSuggestionsEnabled changed from 0 to 0
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsSpotlightFeatures changed from 1 to 1
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_IrisRecommendations changed from 0 to 0
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338389Enabled changed from 0 to 0
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SubscribedContent-338388Enabled changed from 0 to 0
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SystemPaneSuggestionsEnabled changed from 0 to 0
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsSpotlightFeatures changed from 1 to 1
    Registry::HKEY_USERS\S-1-11-1-1111111111-1111111111-1111111111-1111111111\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_IrisRecommendations changed from 0 to 0

PARAMETER: -Enable
    Enables Spotlight and Suggestions in the Start Menu.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$Enable
)

begin {
    # Retrieve Dynamic Script Form Values
    if ($env:enableOrDisable -and $env:enableOrDisable -notlike "null") {
        if ($env:enableOrDisable -eq "Enable") { $Enable = $True }
    }

    # Local Admin Privileges are required to set other users' registry keys
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see the error below!"
                Write-Error $_
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see the error below!"
                Write-Error $_
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name)"
        }
    }

    # Gets the OS Name, e.g., Windows 10 Enterprise or Windows 11 Enterprise
    function Get-OSName {
        systeminfo | findstr /B /C:"OS Name"
    }

    $OSName = Get-OSName
}
process {

    # Error out if the script doesn't have local administrator privileges
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges." -Exception (New-Object -TypeName System.UnauthorizedAccessException) -Category PermissionDenied
        exit 1
    }

    # Get the registry hive for all users
    $UserProfiles = Get-UserHives -Type "All"

    # Initialize generic list for the keys we're going to set
    $Keys = New-Object System.Collections.Generic.List[Object]
    $LoadedProfiles = New-Object System.Collections.Generic.List[Object]

    Foreach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        if ((Test-Path "Registry::HKEY_USERS\$($UserProfile.SID)" -ErrorAction Ignore) -eq $false) {
            $LoadedProfiles.Add($UserProfile)
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
        }

        $Keys.Add(
            [PSCustomObject]@{
                Path  = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name  = "SubscribedContent-338389Enabled"
                Value = if ($Enable) { 1 }Else { 0 }
            }
        )

        $Keys.Add(
            [PSCustomObject]@{
                Path  = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name  = "SubscribedContent-338388Enabled"
                Value = if ($Enable) { 1 }Else { 0 }
            }
        )

        $Keys.Add(
            [PSCustomObject]@{
                Path  = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
                Name  = "SystemPaneSuggestionsEnabled"
                Value = if ($Enable) { 1 }Else { 0 }
            }
        )

        # This key only works on Windows 10/11 Enterprise
        if ($OSName -Like "*Enterprise*") {
            $Keys.Add(
                [PSCustomObject]@{
                    Path  = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
                    Name  = "DisableWindowsSpotlightFeatures"
                    Value = if ($Enable) { 0 }Else { 1 }
                }
            )
        }
        else {
            Write-Warning "Disabling Spotlight is only possible on an Enterprise edition of Windows." 
        }

        # The recommended section in Windows 11 is slightly helpful; this will simply remove the ads but keep the useful frequently used section.
        if ($OSName -Like "*11*") {
            $Keys.Add(
                [PSCustomObject]@{
                    Path  = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                    Name  = "Start_IrisRecommendations"
                    Value = if ($Enable) { 1 }Else { 0 }
                }
            )
        }
    }

    if($OSName -Like "*11*"){
        Write-Host "On Windows 11, only recommendations for tips, shortcuts, and new apps are disabled/enabled from the Start Menu."
    }
    
    if ($Enable) {
        Write-Host "Attempting to Enable Spotlight and Start Menu Suggestions"
    }
    else {
        Write-Host "Attempting to Disable Spotlight and Start Menu Suggestions"
    }

    # Set all the registry keys
    $Keys | ForEach-Object { Set-RegKey -Path $_.Path -Name $_.Name -Value $_.Value }

    # Unload any profiles we loaded up earlier (if any)
    Foreach ($LoadedProfile in $LoadedProfiles) {
        [gc]::Collect()
        Start-Sleep 1
        Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($LoadedProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
    }
}
end {
    
    
    
}
