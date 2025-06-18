# Sets the required registry key to either block the forced migration from classic Outlook to New Outlook and optionally hides the Try the New Outlook toggle button.
#Requires -Version 5.1

<#
.SYNOPSIS
    Sets the required registry key to either block the forced migration from 'classic Outlook' to 'New Outlook' and optionally hides the 'Try the New Outlook' toggle button.
.DESCRIPTION
    Sets the required registry key to either block the forced migration from 'classic Outlook' to 'New Outlook' and optionally hides the 'Try the New Outlook' toggle button.
.EXAMPLE
    -NewOutlookToggle "Hide Toggle"
    
    [Warning] This device is currently joined to a domain. This setting could be overridden by a group policy in the future.
    [Warning] https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/get-started/control-install#prevent-users-from-switching-to-new-outlook
    Gathering all user profiles.
    Successfully retrieved one or more profiles.

    Setting the New Outlook forced migration policy for all users.

    Setting the New Outlook forced migration policy for the user 'Administrator' to disabled.
    Set Registry::HKEY_USERS\S-1-5-21-1045302187-3297466791-1554884838-500\Software\Policies\Microsoft\office\16.0\outlook\preferences\NewOutlookMigrationUserSetting to 0
    Successfully set the New Outlook forced migration policy for the user 'Administrator'.

    Setting the New Outlook forced migration policy for the user 'tuser1' to disabled.
    Set Registry::HKEY_USERS\S-1-5-21-1308996835-875450383-3441943874-1104\Software\Policies\Microsoft\office\16.0\outlook\preferences\NewOutlookMigrationUserSetting to 0
    Successfully set the New Outlook forced migration policy for the user 'tuser1'.

    Setting the New Outlook forced migration policy for the user 'cheart' to disabled.
    Set Registry::HKEY_USERS\S-1-5-21-1308996835-875450383-3441943874-1113\Software\Policies\Microsoft\office\16.0\outlook\preferences\NewOutlookMigrationUserSetting to 0
    Successfully set the New Outlook forced migration policy for the user 'cheart'.

    Setting the New Outlook forced migration policy for the user 'Administrator' to disabled.
    Set Registry::HKEY_USERS\S-1-5-21-1308996835-875450383-3441943874-500\Software\Policies\Microsoft\office\16.0\outlook\preferences\NewOutlookMigrationUserSetting to 0
    Successfully set the New Outlook forced migration policy for the user 'Administrator'.

    Successfully set the New Outlook forced migration policy for all users.

    Setting the 'Try the new outlook' toggle for all users.

    Setting the 'Try the New Outlook' toggle for user 'Administrator' to hidden.
    Set Registry::HKEY_USERS\S-1-5-21-1045302187-3297466791-1554884838-500\Software\Microsoft\Office\16.0\Outlook\Options\General\HideNewOutlookToggle to 1
    Successfully set the 'Try the new outlook' toggle for user 'Administrator'

    Setting the 'Try the New Outlook' toggle for user 'tuser1' to hidden.
    Set Registry::HKEY_USERS\S-1-5-21-1308996835-875450383-3441943874-1104\Software\Microsoft\Office\16.0\Outlook\Options\General\HideNewOutlookToggle to 1
    Successfully set the 'Try the new outlook' toggle for user 'tuser1'

    Setting the 'Try the New Outlook' toggle for user 'cheart' to hidden.
    Set Registry::HKEY_USERS\S-1-5-21-1308996835-875450383-3441943874-1113\Software\Microsoft\Office\16.0\Outlook\Options\General\HideNewOutlookToggle to 1
    Successfully set the 'Try the new outlook' toggle for user 'cheart'

    Setting the 'Try the New Outlook' toggle for user 'Administrator' to hidden.
    Set Registry::HKEY_USERS\S-1-5-21-1308996835-875450383-3441943874-500\Software\Microsoft\Office\16.0\Outlook\Options\General\HideNewOutlookToggle to 1
    Successfully set the 'Try the new outlook' toggle for user 'Administrator'

    Successfully set the 'Try the New Outlook' toggle for all users. You may need to close and re-open Outlook for your change to take effect.

PARAMETER: -MigrationPolicy "Disable"
    Sets a policy to either disable or enable the automatic forced migration of classic Outlook to New Outlook.

PARAMETER: -NewOutlookToggle "Hide Toggle"
    Hide or show the toggle button to migrate to the new outlook.

PARAMETER: -UserToSetPolicyFor "ReplaceMeWithAValidUsername"
    The username you would like to set the policy for. Leave blank for all users.

.LINK
    https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/get-started/control-install
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$MigrationPolicy = "Disable",
    [Parameter()]
    [String]$NewOutlookToggle,
    [Parameter()]
    [String]$UserToSetPolicyFor
)

begin {
    # If the script form variables are used, replace the command line parameters with their value.
    if ($env:migrationAction -and $env:migrationAction -ne "null") { $MigrationPolicy = $env:migrationAction }
    if ($env:toggleButtonAction -and $env:toggleButtonAction -ne "null") { $NewOutlookToggle = $env:toggleButtonAction }
    if ($env:usernameToSetPolicyFor -and $env:usernameToSetPolicyFor -ne "null") { $UserToSetPolicyFor = $env:usernameToSetPolicyFor }
    
    # Check if a specific username was provided for setting the policy.
    if ($UserToSetPolicyFor) {
        # Trim any leading or trailing spaces from the username.
        $UserToSetPolicyFor = $UserToSetPolicyFor.Trim()

        # Validate that the username is not empty after trimming.
        if (!$UserToSetPolicyFor) {
            Write-Host -Object "[Error] An invalid username was given. Please specify a valid username."
            exit 1
        }

        # Ensure the username does not contain any illegal characters.
        if ($UserToSetPolicyFor -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|,|"|@') {
            Write-Host -Object ("[Error] $UserToSetPolicyFor contains one of the following invalid characters." + ' " [ ] : ; | = + * ? < > / \ , @')
            exit 1
        }

        # Ensure the username does not contain spaces.
        if ($UserToSetPolicyFor -match '\s') {
            Write-Host -Object ("[Error] '$UserToSetPolicyFor' contains a space.")
            exit 1
        }

        # Ensure the username does not exceed 20 characters.
        $UserNameCharacters = $UserToSetPolicyFor | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($UserNameCharacters -gt 20) {
            Write-Host -Object "[Error] '$UserToSetPolicyFor' is too long. The username must not exceed 20 characters."
            exit 1
        }
    }

    # Check if a migration policy was provided and trim any leading/trailing spaces.
    if ($MigrationPolicy) {
        $MigrationPolicy = $MigrationPolicy.Trim()
    }

    # Check if the "Try the New Outlook" toggle policy was provided and trim spaces.
    if ($NewOutlookToggle) {
        $NewOutlookToggle = $NewOutlookToggle.Trim()

        # Validate that the toggle action is not empty after trimming.
        if (!$NewOutlookToggle) {
            Write-Host -Object "[Error] An invalid 'Try the new outlook' toggle button action was given. Please specify either 'Hide Toggle', 'Show Toggle', 'Default' or nothing."
            exit 1
        }
    }

    # Ensure that a migration policy was specified.
    if (!$MigrationPolicy) {
        Write-Host -Object "[Error] Please specify a valid migration policy action. Valid migration actions include 'Enable', 'Disable' or 'Default'."
        exit 1
    }

    
    # Define valid migration policy actions and ensure the input is valid.
    $ValidMigrationPolicyActions = "Enable", "Disable", "Default"
    if ($ValidMigrationPolicyActions -notcontains $MigrationPolicy) {
        Write-Host -Object "[Error] An invalid migration policy of '$MigrationPolicy' was given. Please specify a valid migration action such as 'Enable', 'Disable' or 'Default'."
        exit 1
    }

    # Define valid New Outlook toggle actions and ensure the input is valid.
    $ValidNewOutlookTogglePolicy = "Hide Toggle", "Show Toggle", "Default"
    if ($NewOutlookToggle -and $ValidNewOutlookTogglePolicy -notcontains $NewOutlookToggle) {
        Write-Host -Object "[Error] An invalid 'Try the new outlook' toggle button action of '$NewOutlookToggle' was given. Please specify either 'Hide Toggle', 'Show Toggle', 'Default' or nothing."
        exit 1
    }

    # To check if office is installed on the machine.
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
            # Initialize a list to store found installation keys
            $InstallList = New-Object System.Collections.Generic.List[Object]
    
            # If no custom user base key is provided, search in the standard HKLM paths
            if (!$UserBaseKey) {
                $ErrorActionPreference = "Stop"
                # Search in the 32-bit uninstall registry key and add results to the list
                try {
                    $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }
    
                # Search in the 64-bit uninstall registry key and add results to the list
                try {
                    $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }
    
                $ErrorActionPreference = "Continue"
            }
            else {
                $ErrorActionPreference = "Stop"
                # If a custom user base key is provided, search in the corresponding Wow6432Node path and add results to the list
                try {
                    $Result = Get-ChildItem -Path "$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at '$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }
    
                try {
                    # Search in the custom user base key for the standard uninstall path and add results to the list
                    $Result = Get-ChildItem -Path "$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at '$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }
    
                $ErrorActionPreference = "Continue"
            }
    
            # If the UninstallString switch is set, return only the UninstallString property of the found keys
            if ($UninstallString) {
                $InstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $InstallList
            }
        }
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
        try {
            $UserProfiles = Foreach ($Pattern in $Patterns) { 
                Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction Stop |
                    Where-Object { $_.PSChildName -match $Pattern } | 
                    Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                    @{Name = "Username"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                    @{Name = "Domain"; Expression = { if ($_.PSChildName -match "S-1-12-1-(\d+-?){4}$") { "AzureAD" }else { $Null } } }, 
                    @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                    @{Name = "Path"; Expression = { $_.ProfileImagePath } }
            }
        }
        catch {
            Write-Host -Object "[Error] Failed to scan registry keys at 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        # If the IncludeDefault switch is set, add the Default profile to the results
        switch ($IncludeDefault) {
            $True {
                $DefaultProfile = "" | Select-Object Username, SID, UserHive, Path
                $DefaultProfile.Username = "Default"
                $DefaultProfile.Domain = $env:COMPUTERNAME
                $DefaultProfile.SID = "DefaultProfile"
                $DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                $DefaultProfile.Path = "C:\Users\Default"
    
                # Exclude users specified in the ExcludedUsers list
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.Username }
            }
        }
    
        try {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                $AllAccounts = Get-WmiObject -Class "win32_UserAccount" -ErrorAction Stop
            }
            else {
                $AllAccounts = Get-CimInstance -ClassName "win32_UserAccount" -ErrorAction Stop
            }
        }
        catch {
            Write-Host -Object "[Error] Failed to gather complete profile information."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        $CompleteUserProfiles = $UserProfiles | ForEach-Object {
            $SID = $_.SID
            $Win32Object = $AllAccounts | Where-Object { $_.SID -like $SID }
    
            if ($Win32Object) {
                $Win32Object | Add-Member -NotePropertyName UserHive -NotePropertyValue $_.UserHive
                $Win32Object
            }
            else {
                [PSCustomObject]@{
                    Name     = $_.Username
                    Domain   = $_.Domain
                    SID      = $_.SID
                    UserHive = $_.UserHive
                    Path     = $_.Path
                }
            }
        }
    
        # Return the list of user profiles, excluding any specified in the ExcludedUsers list
        $CompleteUserProfiles | Where-Object { $ExcludedUsers -notcontains $_.Name }
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

    function Test-IsDomainJoined {
        # Check the PowerShell version to determine the appropriate cmdlet to use
        try {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            }
            else {
                return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a part of a domain."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    function Test-IsDomainController {
        # Determine the method to retrieve the operating system information based on PowerShell version
        try {
            $OS = if ($PSVersionTable.PSVersion.Major -lt 3) {
                Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            }
            else {
                Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a domain controller."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        # Check if the ProductType is "2", which indicates that the system is a domain controller
        if ($OS.ProductType -eq "2") {
            return $true
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
    # Check if the script is running with elevated (Administrator) privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the current device is either joined to a domain or is a domain controller
    if (Test-IsDomainJoined -or Test-IsDomainController) {
        # Display a warning indicating that the device is joined to a domain
        Write-Host -Object "[Warning] This device is currently joined to a domain. This setting could be overridden by a group policy in the future."

        # Display additional information about the group policy that can override the setting
        Write-Host -Object "[Warning] https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/get-started/control-install#prevent-users-from-switching-to-new-outlook"
    }

    # Search for Office installations (both legacy and Microsoft 365 versions)
    $OfficeInstallations = Find-InstallKey -DisplayName "Office 201"
    $Microsoft365Installations = Find-InstallKey -DisplayName "Microsoft 365"

    # Exit if no Office installations are detected
    if (!$OfficeInstallations -and !$Microsoft365Installations) {
        Write-Host -Object "[Error] Microsoft Office was not detected on this device. Please ensure that it is installed and listed in the Control Panel."
        exit 1
    }

    # Create lists to store registry paths for Outlook migration and New Outlook toggle policies
    $OutlookMigrationRegistryPaths = New-Object System.Collections.Generic.List[object]
    $NewOutlookToggleRegistryPaths = New-Object System.Collections.Generic.List[object]

    # Check if a specific user is targeted for the policy
    if ($UserToSetPolicyFor) {
        Write-Host -Object "Retrieving the user profile for '$UserToSetPolicyFor'."
    }
    else {
        Write-Host -Object "Gathering all user profiles."
    }

    # Retrieve all user profiles (hives) on the system
    $UserProfiles = Get-UserHives -Type "All"
    $ProfileWasLoaded = New-Object System.Collections.Generic.List[object]

    # If a specific user is targeted, filter the retrieved profiles to find a match
    if ($UserToSetPolicyFor) {
        $ProfileToSet = $UserProfiles | Where-Object { $_.Name -eq $UserToSetPolicyFor }

        # Exit if no matching profile is found
        if (!$ProfileToSet) {
            Write-Host -Object "[Error] No user profiles matching '$UserToSetPolicyFor' were found. Below is a list of existing users on the system."
            Write-Host -Object "[Error] You can also leave the 'Username to Set Policy For' field blank to set the policy for all users."
            Write-Host -Object "### User Profiles ###"
            ($UserProfiles | Format-Table -Property Name, Path, SID | Out-String).Trim() | Write-Host
            exit 1
        }else{
            $UserProfiles = $ProfileToSet
        }
    }

    # Load user registry hives (NTUSER.DAT) if not already loaded
    ForEach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        If (!(Test-Path -Path Registry::HKEY_USERS\$($UserProfile.SID) -ErrorAction SilentlyContinue)) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            $ProfileWasLoaded.Add($UserProfile)
        }
    }

    # Construct the registry paths for Outlook migration and New Outlook toggle settings
    $UserProfiles | ForEach-Object {
        # Add Outlook migration policy registry path
        $OutlookMigrationRegistryPaths.Add(
            [PSCustomObject]@{
                Username = $_.Name
                Path     = "Registry::HKEY_USERS\$($_.SID)\Software\Policies\Microsoft\office\16.0\outlook\preferences"
            }
        )

        # Add New Outlook toggle policy registry path
        $NewOutlookToggleRegistryPaths.Add(
            [PSCustomObject]@{
                Username = $_.Name
                BasePath = "Registry::HKEY_USERS\$($_.SID)\Software\Microsoft\Office"
                Path     = "Registry::HKEY_USERS\$($_.SID)\Software\Microsoft\Office\16.0\Outlook\Options\General"
            }
        )
    }

    # Validate that registry paths have been generated successfully
    if ($OutlookMigrationRegistryPaths.Count -lt 1 -or $NewOutlookToggleRegistryPaths.Count -lt 1) {
        Write-Host -Object "[Error] Failed to retrieve any user profiles."
        exit 1
    }
    else {
        Write-Host -Object "Successfully retrieved one or more profiles."
    }

    # Check whether a specific user is targeted for the policy, and output a message accordingly.
    if ($UserToSetPolicyFor) {
        Write-Host -Object "`nSetting the New Outlook forced migration policy for '$UserToSetPolicyFor'."
    }
    else {
        Write-Host -Object "`nSetting the New Outlook forced migration policy for all users."
    }

    # Set the Outlook migration policy for each user
    $OutlookMigrationRegistryPaths | ForEach-Object {
        $Username = $_.Username
        Write-Host -Object ""

        # Determine the action to take based on the $MigrationPolicy variable
        switch ($MigrationPolicy) {
            "Enable" { 
                Write-Host -Object "Setting the New Outlook forced migration policy for the user '$Username' to enabled." 
                $RegValue = 1
            }
            "Disable" { 
                Write-Host -Object "Setting the New Outlook forced migration policy for the user '$Username' to disabled."
                $RegValue = 0
            }
            "Default" { 
                Write-Host -Object "Setting the New Outlook forced migration policy back to the default for the user '$Username'."
            }
        }

        # If the policy is set to "Default," remove the registry key if it exists
        if ($MigrationPolicy -eq "Default") {
            # Check if the registry path exists
            if (!(Test-Path -Path $_.Path -ErrorAction SilentlyContinue)) {
                Write-Host -Object "The registry key '$($_.Path)\NewOutlookMigrationUserSetting' has already been removed."
                Write-Host -Object "Successfully set the New Outlook forced migration policy for the user '$Username'."
                return
            }

            try {
                # Check for an existing registry value
                $ExistingValue = Get-ItemProperty -Path $_.Path -ErrorAction Stop | Select-Object -ExpandProperty "NewOutlookMigrationUserSetting" -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to check if the new outlook forced migration policy is already set to the default."
                $ExitCode = 1
                return
            }

            # Remove the registry value if it exists
            if (!$ExistingValue -and $ExistingValue -ne 0) {
                Write-Host -Object "The registry key '$($_.Path)\NewOutlookMigrationUserSetting' has already been removed."
                Write-Host -Object "Successfully set the New Outlook forced migration policy for the user '$Username'."
                return
            }

            try {
                Remove-ItemProperty -Path $_.Path -Name "NewOutlookMigrationUserSetting" -ErrorAction Stop
                Write-Host -Object "Removed the registry key '$($_.Path)\NewOutlookMigrationUserSetting'."
                Write-Host -Object "Successfully set the New Outlook forced migration policy for the user '$Username'."
                return
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to remove the registry key '$($_.Path)\NewOutlookMigrationUserSetting'."
                Write-Host -Object "[Error] Failed to set the new outlook forced migration policy for user '$Username' to the default."
                $ExitCode = 1
                return
            }
        }

        # Set the specified registry key value for Outlook migration
        Set-RegKey -Path $_.Path -Name "NewOutlookMigrationUserSetting" -Value $RegValue
        Write-Host -Object "Successfully set the New Outlook forced migration policy for the user '$Username'."
    }

    # If user profiles were loaded and a New Outlook toggle policy was not specified, unload their registry hives
    if (!$NewOutlookToggle -and $ProfileWasLoaded.Count -gt 0) {
        ForEach ($UserProfile in $ProfileWasLoaded) {
            # Unload NTuser.dat
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Check whether a specific user is targeted for the policy, and output a message accordingly.
    if ($UserToSetPolicyFor -and $ExitCode -eq 0) {
        Write-Host -Object "`nSuccessfully set the New Outlook forced migration policy for '$UserToSetPolicyFor'."
    }
    elseif ($ExitCode -eq 0) {
        Write-Host -Object "`nSuccessfully set the New Outlook forced migration policy for all users."
    }

    # Exit if no New Outlook toggle policy is specified
    if (!$NewOutlookToggle) {
        exit $ExitCode
    }

    # Check whether a specific user is targeted for the policy, and output a message accordingly.
    if ($UserToSetPolicyFor) {
        Write-Host -Object "`nSetting the 'Try the new outlook' toggle for '$UserToSetPolicyFor'."
    }
    else{
        Write-Host -Object "`nSetting the 'Try the new outlook' toggle for all users."
    }

    # Process each New Outlook toggle registry path for user profiles
    $NewOutlookToggleRegistryPaths | ForEach-Object {
        Write-Host -Object ""
        $Username = $_.Username

        # Set the New Outlook toggle value based on the specified policy
        switch ($NewOutlookToggle) {
            "Hide Toggle" { 
                Write-Host -Object "Setting the 'Try the New Outlook' toggle for user '$Username' to hidden."
                $RegValue = 1
            }
            "Show Toggle" { 
                Write-Host -Object "Setting the 'Try the new outlook' toggle for user '$Username' to show."
                $RegValue = 0
            }
            "Default" { 
                Write-Host -Object "Setting the 'Try the new outlook' toggle back to the default for user '$Username'" 
            }
        }

        # Handle the "Default" policy by removing the registry key if it exists
        if ($NewOutlookToggle -eq "Default") {
            if (!(Test-Path -Path $_.Path -ErrorAction SilentlyContinue)) {
                Write-Host -Object "The registry key '$($_.Path)\HideNewOutlookToggle' has already been removed."
                Write-Host -Object "Successfully set the 'Try the new outlook' toggle to the default for user '$Username'"
                return
            }

            # Attempt to retrieve the existing registry value
            try {
                $ExistingValue = Get-ItemProperty -Path $_.Path -ErrorAction Stop | Select-Object -ExpandProperty "HideNewOutlookToggle" -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to verify whether the 'Try the new outlook' toggle is already set to the default."
                $ExitCode = 1
                return
            }

            # If the registry key does not exist, confirm it has already been removed
            if (!$ExistingValue -and $ExistingValue -ne 0) {
                Write-Host -Object "The registry key '$($_.Path)\HideNewOutlookToggle' has already been removed."
                Write-Host -Object "Successfully set the 'Try the new outlook' toggle to the default for user '$Username'"
                return
            }
            
            # Remove the specific registry key property
            try {
                Remove-ItemProperty -Path $_.Path -Name "HideNewOutlookToggle" -ErrorAction Stop
                Write-Host -Object "Removed the registry key '$($_.Path)\HideNewOutlookToggle'."
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to remove the registry key '$($_.Path)\HideNewOutlookToggle'."
                Write-Host -Object "[Error] Failed to set the 'Try the new outlook' toggle to the default for user '$Username'"
                $ExitCode = 1
                return
            }

            # Confirm successful removal of the registry key
            Write-Host -Object "Successfully set the 'Try the new outlook' toggle to the default for user '$Username'"
            return
        }

        # Ensure the base registry path exists; create it if necessary
        $BasePath = $_.BasePath
        if (!(Test-Path -Path $BasePath -ErrorAction SilentlyContinue)) {
            # Create the missing base registry path
            try {
                New-Item -Path $BasePath -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to create the base path '$BasePath', which is required to set the registry key."
                Write-Host -Object "[Error] https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/get-started/control-install#prevent-users-from-switching-to-new-outlook"
                $ExitCode = 1
                return
            }
        }

        # Set the registry key value for the specified toggle policy
        Set-RegKey -Path $_.Path -Name "HideNewOutlookToggle" -Value $RegValue
        Write-Host -Object "Successfully set the 'Try the new outlook' toggle for user '$Username'"
    }

    # If user profiles were loaded during the process, unload their registry hives
    if ($ProfileWasLoaded.Count -gt 0) {
        ForEach ($UserProfile in $ProfileWasLoaded) {
            # Collect garbage to release memory and avoid locking issues
            [gc]::Collect()
            Start-Sleep 1
            # Unload the user's NTUSER.DAT registry hive
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Check whether a specific user is targeted for the policy, and output a message accordingly.
    if ($UserToSetPolicyFor -and $ExitCode -eq 0) {
        Write-Host -Object "`nSuccessfully set the 'Try the new outlook' toggle for '$UserToSetPolicyFor'.  You may need to close and re-open Outlook for your change to take effect."
    }
    elseif ($ExitCode -eq 0) {
        Write-Host -Object "`nSuccessfully set the 'Try the New Outlook' toggle for all users. You may need to close and re-open Outlook for your change to take effect."
    }

    exit $ExitCode
}
end {
    
    
    
}
