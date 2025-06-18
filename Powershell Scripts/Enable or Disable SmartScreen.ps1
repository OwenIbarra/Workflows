# Changes the SmartScreen state for all users and configures it based on your selected options. Some settings require the device to be domain or entra joined.
#Requires -Version 5.1

<#
.SYNOPSIS
    Changes the SmartScreen state for all users and configures it based on your selected options. Some settings require the device to be domain or entra joined.
.DESCRIPTION
    Changes the SmartScreen state for all users and configures it based on your selected options. Some settings require the device to be domain or entra joined.
.EXAMPLE
    -Action "Enable" -Level "Block" -Explorer

    Applying Registry Change for Explorer.
    Set HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen to 1
    Set HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel to Block

    Updating policy...

    Computer Policy update has completed successfully.
    User Policy update has completed successfully.

    A reboot, or three, may be required for this policy to take effect.

PARAMETER: -Action "replaceWithAction"
    Enable, disable, or remove the registry keys. Removing the registry keys unlocks the SmartScreen configuration settings, allowing end-users to enable or disable them at will.

PARAMETER: -Level "replaceWithWarnOrBlock"
    Sets SmartScreen's default behavior of Warn or to Block/Warn and Prevent Override.

PARAMETER: -Explorer
    Enables checking of Apps and Files downloaded from the web.

PARAMETER: -Edge
    Enables Microsoft Edge integration to block or warn of malicious sites and downloads. Requires device to be joined with Active Directory or Microsoft Entra.

PARAMETER: -MicrosoftStore
    Configures SmartScreen to check web content that Microsoft Store Apps use.

PARAMETER: -PotentiallyUnwantedApp
    Configures SmartScreen to block low-reputation apps that might cause unexpected behaviour. Microsoft Edge also has integrations with this feature that requires the device to be joined with Active Directory or Microsoft Entra.

PARAMETER: -PhishingProtection
    Enables Windows 11-only feature for Enhanced Phishing Protection. Helps protect Microsoft school or work passwords against phishing and unsafe usage on sites and apps.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Combined with SmartScreen Windows Store script, added more configuration options.
.COMPONENT
    OSSecurity
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action,
    [Parameter()]
    [String]$Level = "Warn",
    [Parameter()]
    [Switch]$Explorer = [System.Convert]::ToBoolean($env:windowsExplorerProtection),
    [Parameter()]
    [Switch]$Edge = [System.Convert]::ToBoolean($env:microsoftEdgeProtection),
    [Parameter()]
    [Switch]$MicrosoftStore = [System.Convert]::ToBoolean($env:microsoftStoreProtection),
    [Parameter()]
    [Switch]$PotentiallyUnwantedApp = [System.Convert]::ToBoolean($env:potentiallyUnwantedAppProtection),
    [Parameter()]
    [Switch]$PhishingProtection = [System.Convert]::ToBoolean($env:phishingProtection)
)

begin {

    # Input Validation
    if ($env:level -and $env:level -notlike "null") {
        $Level = $env:level
    }

    if ($env:action -and $env:action -notlike "null") {
        $Action = $env:action
    }

    if (-not $Action) {
        Write-Host "[Error] Please specify an action"
        exit 1
    }

    $ValidActions = "Enable", "Disable", "Remove Registry Keys"
    if ($ValidActions -notcontains $Action) {
        Write-Host "[Error] Invalid Action given. Please specify either 'Enable' or 'Disable'."
        exit 1
    }

    $ValidLevels = "Warn", "Block"
    if ($ValidLevels -notcontains $Level) {
        Write-Host "[Error] only Warn and Block are valid levels to set Smart Screen to."
        exit 1
    }

    if(-not $Explorer -and -not $Edge -and -not $MicrosoftStore -and -not $PotentiallyUnwantedApp -and -not $PhishingProtection){
        Write-Host "[Error] You must select at least one item for SmartScreen to protect!"
        exit 1
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Check's if the OS running the script is Windows 11
    function Test-IsWindows11 { 
        if ($PSversionTable.PSVersion.Major -lt 5){ 
            return $False 
        }
        
        (Get-CimInstance Win32_OperatingSystem).Caption -Match "Windows 11"
    }

    function Test-IsAzureJoined {
        if ([environment]::OSVersion.Version.Major -ge 10) {
            $dsreg = dsregcmd.exe /status | Select-String "AzureAdJoined : YES"
        }
    
        if ($dsreg) { return $True }else { return $False }
    }

    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    # Helper function for setting registry keys.
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
                Write-Host "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Host "[Error] $($_.Message)"
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
                Write-Host "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Host "[Error] $($_.Message)"
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    # Retrieve all user profiles on a machine as well as the path to their respective registry hive.
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
    $ExitCode = 0
}
process {

    # These actions will require local administrator rights.
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }
    
    # Set $State to 1 if -On was used or to 0 if -Off was used
    $State = switch ($Action) {
        "Enable" { 1 }
        "Disable" { 0 }
        "Remove Registry Keys" {}
        default {
            Write-Host "[Error] Unknown action specified!"
            exit 1
        }
    }

    # Preventing Overrides is reversed from the action of enabling or disabling
    if ($Action -eq "Disable" -or $Level -eq "Warn") {
        $PreventOverrideState = 0
    }
    else {
        $PreventOverrideState = 1
    }

    if($Level -eq "Block" -and -not (Test-IsAzureJoined) -and -not (Test-IsDomainJoined)){
        Write-Host "[Error] Device is not joined to a domain or to Microsoft Entra. The warning may be bypassed under certain circumstances!"
        Write-Host "[Info] https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#preventsmartscreenpromptoverride"
        Write-Host "[Info] https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#preventsmartscreenpromptoverrideforfiles"
        $ExitCode = 1
    }

    # Explorer
    if($Explorer){
        Write-Host "`nApplying Registry Change for Explorer."
    }
    
    if ($Explorer -and $Action -ne "Remove Registry Keys") {
        Set-RegKey -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value $State
        Set-RegKey -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value $Level -PropertyType String
    }
    elseif ($Explorer -and $Action -eq "Remove Registry Keys") {
        $EnableSmartScreen = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
        $ShellSmartScreenLevel = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -ErrorAction SilentlyContinue
        
        if ($EnableSmartScreen) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen"
            Write-Host "HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen original value is $($EnableSmartScreen.EnableSmartScreen)"
            Write-Host "Removed HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen"
        }

        if ($ShellSmartScreenLevel) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel"
            Write-Host "HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel original value is $($ShellSmartScreenLevel.ShellSmartScreenLevel)"
            Write-Host "Removed HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel"
        }
    }

    # Microsoft Edge
    if($Edge){
        Write-Host "`nApplying Registry Change for Microsoft Edge."
    }

    if($Edge -and -not (Test-IsAzureJoined) -and -not (Test-IsDomainJoined)){
        Write-Host "[Error] Device is not joined to a domain or to Microsoft Entra. Edge settings cannot be applied!"
        Write-Host "[Info] https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#smartscreenenabled"
        $ExitCode = 1
    }
    
    if ($Edge -and $Action -ne "Remove Registry Keys" -and ((Test-IsAzureJoined) -or (Test-IsDomainJoined))) {
        Set-RegKey -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value $State
        Set-RegKey -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value $PreventOverrideState
        Set-RegKey -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -Value $PreventOverrideState
    }
    elseif ($Edge -and $Action -eq "Remove Registry Keys" -and ((Test-IsAzureJoined) -or (Test-IsDomainJoined))) {
        $SmartScreenEnabled = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        $PreventSmartScreenPromptOverride = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -ErrorAction SilentlyContinue
        $PreventSmartScreenPromptOverrideForFiles = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -ErrorAction SilentlyContinue
    
        if ($SmartScreenEnabled) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenEnabled"
            Write-Host "HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled original value is $($SmartScreenEnabled.SmartScreenEnabled)"
            Write-Host "Removed HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled"
        }

        if ($PreventSmartScreenPromptOverride) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride"
            Write-Host "HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride original value is $($PreventSmartScreenPromptOverride.PreventSmartScreenPromptOverride)"
            Write-Host "Removed HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride"
        }

        if ($PreventSmartScreenPromptOverrideForFiles) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles"
            Write-Host "HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles original value is $($PreventSmartScreenPromptOverrideForFiles.PreventSmartScreenPromptOverrideForFiles)"
            Write-Host "Removed HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles"
        }
    }

    # Microsoft Store
    if($MicrosoftStore){
        Write-Host "`nApplying Registry Change for Microsoft Store."
    }
    
    if ($MicrosoftStore -and $Action -ne "Remove Registry Keys") {
        Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value $State
        Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -Value $PreventOverrideState

        $UserProfiles = Get-UserHives -Type "All" -IncludeDefault
        # Loop through each profile on the machine
        Foreach ($UserProfile in $UserProfiles) {
            # Load User ntuser.dat if it's not already loaded
            If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            }

            Write-Host "`nApplying Microsoft Store registry change for user $($UserProfile.UserName)."

            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value $State
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -Value $PreventOverrideState

            # Unload NTuser.dat
            If ($ProfileWasLoaded -eq $false) {
                [gc]::Collect()
                Start-Sleep 1
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
            }
        }
    }
    elseif ($MicrosoftStore -and $Action -eq "Remove Registry Keys") {
        $EnableWebContentEvaluation = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -ErrorAction SilentlyContinue
        $PreventOverride = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -ErrorAction SilentlyContinue
    
        if ($EnableWebContentEvaluation) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"
            Write-Host "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation original value is $($EnableWebContentEvaluation.EnableWebContentEvaluation)"
            Write-Host "Removed HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation"
        }

        if ($PreventOverride) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride"
            Write-Host "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\PreventOverride original value is $($PreventOverride.PreventOverride)"
            Write-Host "Removed HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\PreventOverride"
        }

        $UserProfiles = Get-UserHives -Type "All" -IncludeDefault
        # Loop through each profile on the machine
        Foreach ($UserProfile in $UserProfiles) {
            # Load User ntuser.dat if it's not already loaded
            If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            }

            Write-Host "`nApplying Microsoft Store registry change for user $($UserProfile.UserName)."
            
            $UserEnableWebContentEvaluation = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -ErrorAction SilentlyContinue
            $UserPreventOverride = Get-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride" -ErrorAction SilentlyContinue
    
            if ($UserEnableWebContentEvaluation) {
                Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"
                Write-Host "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation original value is $($UserEnableWebContentEvaluation.UserEnableWebContentEvaluation)"
                Write-Host "Removed Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation"
            }

            if ($UserPreventOverride) {
                Remove-ItemProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "PreventOverride"
                Write-Host "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\PreventOverride original value is $($UserPreventOverride.UserPreventOverride)"
                Write-Host "Removed Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost\PreventOverride"
            }

            # Unload NTuser.dat
            If ($ProfileWasLoaded -eq $false) {
                [gc]::Collect()
                Start-Sleep 1
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
            }
        }
    }

    # Potentially Unwanted App
    if($PotentiallyUnwantedApp){
        Write-Host "`nApplying Registry Change for Potentially Unwanted Apps."

        if($Edge -and -not (Test-IsAzureJoined) -and -not (Test-IsDomainJoined)){
            Write-Host "[Error] Device is not joined to a domain or to Microsoft Entra. Edge settings for Potentially Unwanted Apps cannot be applied!"
            Write-Host "[Info] https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-policies#smartscreenpuaenabled"
            $ExitCode = 1
        }
    }

    if ($PotentiallyUnwantedApp -and $Action -ne "Remove Registry Keys") {
        Set-RegKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -Value $State

        if ($Edge -and ((Test-IsAzureJoined) -or (Test-IsDomainJoined))) {
            Set-RegKey -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Value $State
        }
        elseif(((Test-IsAzureJoined) -or (Test-IsDomainJoined)) -and $Action -eq "Enabled") {
            Write-Warning "There are additional Potentially Unwanted App settings that can be set with Microsoft Edge Protection Turned on."
            Write-Warning "Re-Run this script with Edge and Potentially Unwanted App Protection turned on to enable them."
        }
    }
    elseif ($PotentiallyUnwantedApp -and $Action -eq "Remove Registry Keys") {
        $PUAProtection = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection" -ErrorAction SilentlyContinue
    
        if ($PUAProtection) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "PUAProtection"
            Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection original value is $($PUAProtection.PUAProtection)"
            Write-Host "Removed HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\PUAProtection"
        }

        if ($Edge -and ((Test-IsAzureJoined) -or (Test-IsDomainJoined))) {
            $SmartScreenPUAEnabled = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -ErrorAction SilentlyContinue
        
            if ($SmartScreenPUAEnabled) {
                Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled"
                Write-Host "HKLM:\Software\Policies\Microsoft\Edge\SmartScreenPUAEnabled original value is $($SmartScreenPUAEnabled.SmartScreenPUAEnabled)"
                Write-Host "Removed HKLM:\Software\Policies\Microsoft\Edge\SmartScreenPUAEnabled"
            }
        }
        elseif(((Test-IsAzureJoined) -or (Test-IsDomainJoined)) -and $Action -eq "Enabled") {
            Write-Warning "There are additional Potentially Unwanted App settings that can be set with Microsoft Edge Protection Turned on."
            Write-Warning "Re-Run this script with Edge and Potentially Unwanted App Protection turned on to enable them."
        }
    }

    # Phishing Protection
    if($PhishingProtection -and (Test-IsWindows11)){
        Write-Host "`nApplying Registry Change for Phishing Protection."
    }

    if ($PhishingProtection -and -not $Edge -and (Test-IsWindows11) -and $Action -eq "Enabled") {
        Write-Host ""
        Write-Warning "There are additional Phishing Protection settings that can be set with Microsoft Edge Protection Turned on." 
        Write-Warning "Re-Run this script with Edge and Phishing Protection turned on to enable them."
    }

    if ($PhishingProtection -and -not (Test-IsWindows11) -and $Action -eq "Enabled"){
        Write-Host ""
        Write-Warning "Enhanced Phishing Protection is only available in Windows 11."
        Write-Warning "https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/enhanced-phishing-protection?tabs=intune"
    }

    if ($PhishingProtection -and $Action -ne "Remove Registry Keys" -and (Test-IsWindows11)) {
        Set-RegKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyMalicious" -Value $State
        Set-RegKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyPasswordReuse" -Value $State
        Set-RegKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyUnsafeApp" -Value $State
        Set-RegKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "ServiceEnabled" -Value $State
    }
    elseif ($PhishingProtection -and $Action -eq "Remove Registry Keys" -and (Test-IsWindows11)) {
        $NotifyMalicious = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyMalicious" -ErrorAction SilentlyContinue
        $NotifyPasswordReuse = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyPasswordReuse" -ErrorAction SilentlyContinue
        $NotifyUnsafeApp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyUnsafeApp" -ErrorAction SilentlyContinue
        $ServiceEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "ServiceEnabled" -ErrorAction SilentlyContinue

        if ($NotifyMalicious) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyMalicious"
            Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyMalicious original value is $($NotifyMalicious.NotifyMalicious)"
            Write-Host "Removed HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyMalicious"
        }

        if ($NotifyPasswordReuse) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyPasswordReuse"
            Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyPasswordReuse original value is $($NotifyPasswordReuse.NotifyPasswordReuse)"
            Write-Host "Removed HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyPasswordReuse"
        }

        if ($NotifyUnsafeApp) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "NotifyUnsafeApp"
            Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyUnsafeApp original value is $($NotifyUnsafeApp.NotifyUnsafeApp)"
            Write-Host "Removed HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\NotifyUnsafeApp"
        }

        if ($ServiceEnabled) {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components" -Name "ServiceEnabled"
            Write-Host "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\ServiceEnabled original value is $($ServiceEnabled.ServiceEnabled)"
            Write-Host "Removed HKLM:\SOFTWARE\Policies\Microsoft\Windows\WTDS\Components\ServiceEnabled"
        }
    }

    if ($Edge -and $PhishingProtection -and $Action -ne "Remove Registry Keys" -and (Test-IsWindows11)) {
        Set-RegKey -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -Value $State
        Set-RegKey -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -Value $PreventOverrideState
        Set-RegKey -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown" -Value $PreventOverrideState
    }
    elseif ($Edge -and $PhishingProtection -and $Action -eq "Remove Registry Keys" -and (Test-IsWindows11)) {
        $EnabledV9 = Get-ItemProperty -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -ErrorAction SilentlyContinue
        $PreventOverride = Get-ItemProperty -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "PreventOverride" -ErrorAction SilentlyContinue
        $PreventOverrideAppRepUnknown = Get-ItemProperty -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown" -ErrorAction SilentlyContinue

        if ($EnabledV9) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "EnabledV9"
            Write-Host "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter\EnabledV9 original value is $($EnabledV9.EnabledV9)"
            Write-Host "Removed HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter\EnabledV9"
        }

        if ($PreventOverride) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "PreventOverride"
            Write-Host "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter\PreventOverride original value is $($PreventOverride.PreventOverride)"
            Write-Host "Removed HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter\PreventOverride"
        }

        if ($PreventOverrideAppRepUnknown) {
            Remove-ItemProperty -Path "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter" -Name "PreventOverrideAppRepUnknown"
            Write-Host "HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown original value is $($PreventOverrideAppRepUnknown.PreventOverrideAppRepUnknown)"
            Write-Host "Removed HKLM:\Software\Policies\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown"
        }
    }

    Write-Host ""
  
    gpupdate.exe /force
    Write-Host "A reboot, or three, may be required for this policy to take effect."

    exit $ExitCode
}
end {
    
    
    
}


