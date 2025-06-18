# Enable or disable macros in Excel, Word, Access, Outlook, and PowerPoint for all users.
#Requires -Version 5.1

<#
.SYNOPSIS
    Enable or disable macros in Excel, Word, Access, Outlook, and PowerPoint for all users.
.DESCRIPTION
    Enable or disable macros in Excel, Word, Access, Outlook, and PowerPoint for all users.

.EXAMPLE
    -Action "Disable all macros without notification"

    Disabling all macros without notification for user 'Administrator'.
    Applying setting for Office 2019.
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\17.0\Excel\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\17.0\Word\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\17.0\Access\Security\vbawarnings changed from 4 to 4
    Set Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\17.0\Outlook\Security\level to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\17.0\PowerPoint\Security\vbawarnings changed from 4 to 4

    Applying setting for Office 2016/365.
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\16.0\Excel\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\16.0\Word\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\16.0\Access\Security\vbawarnings changed from 4 to 4
    Set Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\16.0\Outlook\Security\level to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\16.0\PowerPoint\Security\vbawarnings changed from 4 to 4

    Applying setting for Office 2013.
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\15.0\Excel\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\15.0\Word\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\15.0\Access\Security\vbawarnings changed from 4 to 4
    Set Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\15.0\Outlook\Security\level to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\15.0\PowerPoint\Security\vbawarnings changed from 4 to 4

    Applying setting for Office 2010.
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\14.0\Excel\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\14.0\Word\Security\vbawarnings changed from 4 to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\14.0\Access\Security\vbawarnings changed from 4 to 4
    Set Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\14.0\Outlook\Security\level to 4
    Registry::HKEY_USERS\S-1-5-21-1270107344-3493626221-2610808627-500\Software\Policies\Microsoft\Office\14.0\PowerPoint\Security\vbawarnings changed from 4 to 4

PARAMETER: -Action "Disable all macros with notification"
    Specify the macro setting you would like to set for all users. Valid options are: "Disable all macros with notification", "Disable all macros except digitally signed macros", "Disable all macros without notification", "Enable all macros", "Reset to Default".

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action = "Disable all macros with notification"
)

begin {
    # If script form variables are used replace command line parameters with them.
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }

    # If $Action is not set (i.e., no action was provided) error out.
    if (!$Action) {
        Write-Host -Object "[Error] No action given. You must specify an action to take."
        exit 1
    }

    # Define a list of valid actions
    $ValidActions = "Enable all macros", "Disable all macros with notification", "Disable all macros except digitally signed macros", "Disable all macros without notification", "Reset to Default"

    # Check if the provided action is not in the list of valid actions
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] An invalid action of '$Action' was given. Only the following actions are valid."
        Write-Host -Object '"Enable all macros", "Disable all macros with notification", "Disable all macros except digitally signed macros", "Disable all macros without notification" or "Reset to Default"'
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
    
        # User account SID's follow a particular patter depending on if they're azure AD or a Domain account or a local "workgroup" account.
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # We'll need the NTuser.dat file to load each users registry hive. So we grab it if their account sid matches the above pattern. 
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

    # Function to find installation keys based on the display name, optionally returning uninstall strings
    function Find-InstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString,
            [Parameter()]
            [String]$UserBaseKey
        )
        process {
            # Initialize an empty list to hold installation objects
            $InstallList = New-Object System.Collections.Generic.List[Object]

            # If no user base key is specified, search in the default system-wide uninstall paths
            if (!$UserBaseKey) {
                # Search for programs in 32-bit and 64-bit locations. Then add them to the list if they match the display name
                $Result = Get-ChildItem -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }

                $Result = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
            else {
                # If a user base key is specified, search in the user-specified 64-bit and 32-bit paths.
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
    
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
    
            # If the UninstallString switch is specified, return only the uninstall strings; otherwise, return the full installation objects.
            if ($UninstallString) {
                $InstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $InstallList
            }
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
        if (-not (Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            try {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host -Object "[Error] Unable to create the registry path $Path for $Name. Please see the error below!"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host -Object "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host -Object "$Path\$Name changed from $CurrentValue to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host -Object "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host -Object "Set $Path\$Name to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated (administrator) privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Create a new list to store Office installation keys
    $OfficeInstalls = New-Object System.Collections.Generic.List[object]

    # Find and add installation keys for "Microsoft 365" or "Microsoft Office" to the list
    Find-InstallKey -DisplayName "Microsoft 365" | ForEach-Object {
        $OfficeInstalls.Add($_)
    }
    Find-InstallKey -DisplayName "Microsoft Office" | ForEach-Object {
        $OfficeInstalls.Add($_)
    }

    # Get all user profiles on the machine
    $UserProfiles = Get-UserHives -Type "All"
    # Create a new list to store the profiles that were loaded during the script
    $ProfileWasLoaded = New-Object System.Collections.Generic.List[string]

    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        If ((Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            $ProfileWasLoaded.Add("$($UserProfile.SID)")
        }

        # Find and add installation keys for "Microsoft 365" or "Microsoft Office" to the list
        Find-InstallKey -DisplayName "Microsoft 365" -UserBaseKey "Registry::HKEY_USERS\$($UserProfile.SID))" | ForEach-Object {
            $OfficeInstalls.Add($_)
        }
        Find-InstallKey -DisplayName "Microsoft Office" -UserBaseKey "Registry::HKEY_USERS\$($UserProfile.SID))" | ForEach-Object {
            $OfficeInstalls.Add($_)
        }
    }

    # If no Office installations are found, output an error message and exit the script with error code 1
    if ($OfficeInstalls.Count -eq 0) {
        Write-Host -Object "[Error] Microsoft Office is not installed!"
        exit 1
    }

    # Loop through each user profile again to apply the macro settings
    Foreach ($UserProfile in $UserProfiles) {
        Write-Host -Object ""

        # Determine the registry key value based on the specified action
        switch ($Action) {
            "Enable all macros" { 
                Write-Host -Object "Enabling macros for user '$($UserProfile.Username)'." 
                $RegistryKeyValue = 1
            }
            "Disable all macros with notification" { 
                Write-Host -Object "Disabling macros with notification for user '$($UserProfile.Username)'."
                $RegistryKeyValue = 2 
            }
            "Disable all macros except digitally signed macros" { 
                Write-Host -Object "Disabling all macros except digitally signed macros for user '$($UserProfile.Username)'."
                $RegistryKeyValue = 3 
            }
            "Disable all macros without notification" { 
                Write-Host -Object "Disabling all macros without notification for user '$($UserProfile.Username)'." 
                $RegistryKeyValue = 4
            }
            "Reset to Default" { 
                Write-Host -Object "Resetting macros to the default for user '$($UserProfile.Username)'." 
            }
        }

        # Define the Office versions to apply the settings for
        $OfficeVersions = "17.0", "16.0", "15.0", "14.0"
        $OfficeVersions | ForEach-Object {
            # Output the Office version being processed
            switch ($_) {
                "17.0" { Write-Host -Object "Applying setting for Office 2019." }
                "16.0" { Write-Host -Object "Applying setting for Office 2016/365." }
                "15.0" { Write-Host -Object "Applying setting for Office 2013." }
                "14.0" { Write-Host -Object "Applying setting for Office 2010." }
            }
            
            # If the action is "Reset to Default", remove the VBA warnings registry keys
            if ($Action -eq "Reset to Default") {
                $vbawarningsExcel = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Excel\Security" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty vbawarnings
                $vbawarningsWord = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Word\Security" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty vbawarnings
                $vbawarningsAccess = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Access\Security" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty vbawarnings
                $vbawarningsOutlook = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Outlook\Security" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty level
                $vbawarningsPowerpoint = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\PowerPoint\Security" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty vbawarnings

                try {
                    if ($vbawarningsExcel) {
                        Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Excel\Security" -Name "vbawarnings" -ErrorAction Stop
                        Write-Host -Object "Successfully removed registry key 'vbawarnings' from 'Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Excel\Security'."
                    }
                    if ($vbawarningsWord) {
                        Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Word\Security" -Name "vbawarnings" -ErrorAction Stop
                        Write-Host -Object "Successfully removed registry key 'vbawarnings' from 'Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Word\Security'."
                    }
                    if ($vbawarningsAccess) {
                        Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Access\Security" -Name "vbawarnings" -ErrorAction Stop
                        Write-Host -Object "Successfully removed registry key 'vbawarnings' from 'Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Access\Security'."
                    }
                    if ($vbawarningsOutlook) {
                        Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Outlook\Security" -Name "level" -ErrorAction Stop
                        Write-Host -Object "Successfully removed registry key 'level' from 'Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Outlook\Security'."
                    }
                    if ($vbawarningsPowerpoint) {
                        Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\PowerPoint\Security" -Name "vbawarnings" -ErrorAction Stop
                        Write-Host -Object "Successfully removed registry key 'vbawarnings' from 'Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\PowerPoint\Security'."
                    }
                }
                catch {
                    Write-Host -Object "[Error] Failed to remove registry key at path HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\*\Security."
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    exit 1
                }

                Write-Host -Object ""
                return
            }

            # Set the VBA warnings registry keys based on the specified action
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Excel\Security" -Name "vbawarnings" -Value $RegistryKeyValue
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Word\Security" -Name "vbawarnings" -Value $RegistryKeyValue
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Access\Security" -Name "vbawarnings" -Value $RegistryKeyValue
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\Outlook\Security" -Name "level" -Value $RegistryKeyValue
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Policies\Microsoft\Office\$_\PowerPoint\Security" -Name "vbawarnings" -Value $RegistryKeyValue
            Write-Host -Object ""
        }
    }

    # Unload all hives that were loaded for this script.
    ForEach ($UserHive in $ProfileWasLoaded) {
        [gc]::Collect()
        Start-Sleep 1
        Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserHive)" -Wait -WindowStyle Hidden | Out-Null
    }

    exit $ExitCode
}
end {
    
    
    
}
