# Set the wallpaper for either an individual user (if run as Current Logged on User) or for all users with modifications disabled (if run as System). Set Image and Disable Modifications will set the lockscreen wallpaper and prevent end-users from changing their lockscreen image.
#Requires -Version 5.1

<#
.SYNOPSIS
    Set the wallpaper for either an individual user (if run as "Current Logged on User") or for all users with modifications disabled (if run as "System"). "Set Image and Disable Modifications" will set the lockscreen wallpaper and prevent end-users from changing their lockscreen image.
.DESCRIPTION
    Set the wallpaper for either an individual user (if run as "Current Logged on User") or for all users with modifications disabled (if run as "System"). "Set Image and Disable Modifications" will set the lockscreen wallpaper and prevent end-users from changing their lockscreen image.
.EXAMPLE
    (Running as 'System')

    -Action "Set Image and Disable Modifications" -Image "https://www.microsoft.com/en-us/microsoft-365/blog/wp-content/uploads/sites/2/2021/06/Msft_Nostalgia_Landscape.jpg"

    URL 'https://www.microsoft.com/en-us/microsoft-365/blog/wp-content/uploads/sites/2/2021/06/Msft_Nostalgia_Landscape.jpg' was given.
    Downloading the file...
    Waiting for 13 seconds.
    Download Attempt 1
    Successfully downloaded image.
    Moving image from 'C:\Windows\TEMP\269145468.jpg' to destination.
    Image already existed at destination, using 'C:\ProgramData\Lockscreen\290C1A587FB5E6A9AC97EE526FF8D6C7.jpg' instead.
    Setting lock screen to 'C:\ProgramData\Lockscreen\290C1A587FB5E6A9AC97EE526FF8D6C7.jpg' and applying modification lock.
    Set Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP\LockScreenImagePath to C:\ProgramData\Lockscreen\290C1A587FB5E6A9AC97EE526FF8D6C7.jpg
    Lock screen has been successfully set.

.EXAMPLE
    (Running as 'Current Logged on User')
    
    -Action "Set Image" -Image "https://www.microsoft.com/en-us/microsoft-365/blog/wp-content/uploads/sites/2/2021/06/Msft_Nostalgia_Landscape.jpg"

    Creating destination folder at 'C:\ProgramData\Lockscreen'
    Successfully created folder at 'C:\ProgramData\Lockscreen'.
    URL 'https://www.microsoft.com/en-us/microsoft-365/blog/wp-content/uploads/sites/2/2021/06/Msft_Nostalgia_Landscape.jpg' was given.
    Downloading the file...
    Waiting for 8 seconds.
    Download Attempt 1
    Successfully downloaded image.
    Moving image from 'C:\Users\Administrator\AppData\Local\Temp\1665473157.jpg' to destination.
    Moved image to destination 'C:\ProgramData\Lockscreen\290C1A587FB5E6A9AC97EE526FF8D6C7.jpg'.
    Setting lock screen to 'C:\ProgramData\Lockscreen\290C1A587FB5E6A9AC97EE526FF8D6C7.jpg' for Administrator.
    Successfully set lock screen for Administrator.

PARAMETER: -Action "Set Image and Disable Modifications"
    Specify an action to perform on the lock screen. Valid actions include 'Set Image', 'Set Image and Disable Modifications', 'Use Windows Spotlight', and 'Remove Modification Lock'.

    'Set Image' - Will set the lockscreen image. Script must be run as the 'Current Logged on User'
    'Set Image and Disable Modifications' - Will set the lockscreen image for all users and prevent end-users from changing their lockscreen.
    'Use Windows Spotlight' - Will set the lockscreen image to Windows Spotlight.
    'Remove Modification Lock' - Will remove the 'lock' that prevents end-users from updating their lockscreen.

PARAMETER: -Image "https://www.example.com/image.jpg"
    Specify either a link or a local path to an image you would like to use as the lock screen background.

PARAMETER: -Destination "C:\ProgramData\ReplaceMe"
    Specify a folder to store the wallpaper in. Defaults to C:\ProgramData\Lockscreen.

PARAMETER: -ForceRestart
    If no one is signed into the machine, a restart may be required for the script to take immediate effect.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action = "Set Image and Disable Modifications",
    [Parameter()]
    [String]$Image,
    [Parameter()]
    [String]$Destination = "$env:ProgramData\Lockscreen",
    [Parameter()]
    [Switch]$ForceRestart = [System.Convert]::ToBoolean($env:forceRestart)
)

begin {
    # If script form variables are used, replace command line parameters with the form values.
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }
    if ($env:urlOrLocalPathToImage -and $env:urlOrLocalPathToImage -notlike "null") { $Image = $env:urlOrLocalPathToImage }
    if ($env:wallpaperStoragePath -and $env:wallpaperStoragePath -notlike "null") { $Destination = $env:wallpaperStoragePath }

    # Check if the Action parameter is specified
    if (!$Action) {
        Write-Host -Object "[Error] You must specify an action to perform. Valid actions include 'Set Image', 'Set Image and Disable Modifications', 'Use Windows Spotlight', and 'Remove Modification Lock'."
        exit 1
    }

    # Define valid actions
    $ValidActions = "Set Image", "Set Image and Disable Modifications", "Use Windows Spotlight", "Remove Modification Lock"
    
    # Check if the provided Action is valid
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] An invalid action of '$Action' was given. Please specify a valid action such as 'Set Image', 'Set Image and Disable Modifications', 'Use Windows Spotlight', or 'Remove Modification Lock'."
        exit 1
    }

    # Check if modification of the lock screen is currently disabled
    if ($Action -ne "Set Image and Disable Modifications" -and $Action -ne "Remove Modification Lock") {
        $ModificationLock = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LockScreenImagePath -ErrorAction SilentlyContinue

        if ($ModificationLock) {
            Write-Host -Object "[Error] Currently, modification of the lock screen is disabled. Please use the action 'Remove Modification Lock' to remove the lock."
            exit 1
        }
    }

    # Function to check if the script is running as SYSTEM
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    # Function to check if the script is running with elevated (Administrator) privileges
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    try {
        # Load the Windows Runtime assembly
        Add-Type -AssemblyName System.Runtime.WindowsRuntime -ErrorAction Stop

        # Inform PowerShell that we'll be using two UWP Classes
        [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null
        [Windows.System.UserProfile.LockScreen, Windows.System.UserProfile, ContentType = WindowsRuntime] | Out-Null
    }
    catch {
        if ($Action -eq "Set Image") {
            Write-Host -Object "[Error] Failed to load required libraries!"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Check if the script is running as SYSTEM and the action is "Set Image"
    if ($Action -eq "Set Image" -and (Test-IsSystem)) {
        Write-Host -Object "[Error] Script is running as 'SYSTEM'. In order to set the lock screen image without disabling modifications, this script must be run as the 'Current Logged on User'."
        exit 1
    }

    # Check if the script is not running with elevated privileges and the action requires elevation
    if (!(Test-IsElevated) -and $Action -ne "Set Image" -and $Action -ne "Use Windows Spotlight") {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges to add or remove the modification lock of the lock screen."
        exit 1
    }

    # Check if the destination should be nullified for certain actions
    if (($Action -eq "Remove Modification Lock" -or $Action -eq "Use Windows Spotlight") -and $Destination -eq "$env:ProgramData\Lockscreen") {
        $Destination = $Null
    }

    # Check if the action is "Remove Modification Lock" and both image or destination are provided
    if ($Action -eq "Remove Modification Lock" -and ($Image -or $Destination)) {
        Write-Host -Object "[Error] You cannot remove the modification lock and set the lock screen at the same time."
        exit 1
    }

    # Check if the action is "Use Windows Spotlight" and both image or destination are provided
    if ($Action -eq "Use Windows Spotlight" -and ($Image -or $Destination)) {
        Write-Host -Object "[Error] You cannot set an image and turn on Windows Spotlight at the same time."
        exit 1
    }

    # Remove quotations from the image path if they exist
    if ($Image) {
        if ($Image.Trim() -match "^'" -or $Image.Trim() -match "'$" -or $Image.Trim() -match '^"' -or $Image.Trim() -match '"$') {
            $QuotationsFound = $true
        }
        $Image = ($Image.Trim() -replace "^'" -replace "'$" -replace '^"' -replace '"$').Trim()

        if ($QuotationsFound) {
            Write-Host -Object "[Warning] Removing quotations from your path. Your new path is '$Image'."
        }
    }

    # Remove quotations from the destination path if they exist
    if ($Destination) {
        if ($Destination.Trim() -match "^'" -or $Destination.Trim() -match "'$" -or $Destination.Trim() -match '^"' -or $Destination.Trim() -match '"$') {
            $DestinationQuotationsFound = $true
        }
        $Destination = ($Destination.Trim() -replace "^'" -replace "'$" -replace '^"' -replace '"$').Trim()

        if ($DestinationQuotationsFound) {
            Write-Host -Object "[Warning] Removing quotations from your path. Your new path is '$Destination'."
        }
    }

    # Check if the image is not provided for actions that require an image
    if (!$Image -and $Action -ne "Remove Modification Lock" -and $Action -ne "Use Windows Spotlight") {
        Write-Host -Object "[Error] You must specify either a link to an image or a local path to an image."
        exit 1
    }

    # Validate the local path of the image if it contains invalid characters or does not exist
    if ($Image -match "\\") {
        if ($Image -match '[<>/|?]' -or $Image -match ':.*:' -or $Image -match '.+".+') {
            Write-Host -Object "[Error] The local path '$Image' contains one of the following invalid characters: '<>/|?:`"'."
            exit 1
        }

        if (!(Test-Path -Path $Image -ErrorAction SilentlyContinue)) {
            Write-Host -Object "[Error] Unable to find image file at local path '$Image'."
            exit 1
        }

        try {
            $ImageFile = Get-Item -Path $Image -Force -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Unable to retrieve image at local path '$Image'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        if ($ImageFile.PSIsContainer) {
            Write-Host -Object "[Error] A folder '$Image' was given. Please specify an individual file."
            exit 1
        }
    }
    elseif ($Action -ne "Remove Modification Lock" -and $Action -ne "Use Windows Spotlight") {
        # Validate the URL of the image if it is provided
        
        if ($Image -notmatch '.*\..*') {
            Write-Host -Object "[Error] No top-level domain found in URL '$Image'."
            exit 1
        }

        if ($Image -match '^http[s]?://http[s]?://') {
            Write-Host -Object "[Error] URL '$Image' contains multiple http(s)://."
            exit 1
        }

        if ($Image -match '^http' -and $Image -notmatch '^http[s]?://') {
            Write-Host -Object "[Error] URL '$Image' is malformed. It should start with 'https://' or 'http://'."
            exit 1
        }

        # Validate $Image as a URI
        try {
            [System.Uri]$Image | Out-Null
        }
        catch {
            Write-Host -Object "[Error] URL '$Image' is malformed."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        if (!$Destination) {
            Write-Host -Object "[Error] A destination folder is required!"
            exit 1
        }
    }

    # Validate the destination path to ensure it does not contain invalid characters and exists
    if ($Destination) {
        if ($Destination -match '[<>/|?]' -or $Destination -match ':.*:' -or $Destination -match '.+".+') {
            Write-Host -Object "[Error] The destination path '$Destination' contains one of the following invalid characters: '<>/|?:`"'."
            exit 1
        }

        if (!(Test-Path -Path $Destination -ErrorAction SilentlyContinue)) {
            Write-Host -Object "Creating destination folder at '$Destination'"
            
            try {
                New-Item -Path $Destination -ItemType Directory -ErrorAction Stop | Out-Null
                Write-Host -Object "Successfully created folder at '$Destination'."
            }
            catch {
                Write-Host -Object "[Error] Unable to create destination folder at '$Destination'."
                exit 1
            }
        }

        try {
            $DestinationFolder = Get-Item -Path $Destination -Force -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Unable to find destination path '$Destination'."
            exit 1
        }

        if (!($DestinationFolder.PSIsContainer)) {
            Write-Host -Object "[Error] A file '$Destination' was given. Please specify a folder."
            exit 1
        }
    }

    # Utility function for downloading files.
    function Invoke-Download {
        param(
            [Parameter()]
            [String]$URL,
            [Parameter()]
            [String]$BasePath,
            [Parameter()]
            [String]$Path,
            [Parameter()]
            [int]$Attempts = 3,
            [Parameter()]
            [Switch]$SkipSleep = [System.Convert]::ToBoolean($env:skipSleep)
        )
        Write-Host -Object "URL '$URL' was given."
        Write-Host -Object "Downloading the file..."

        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Not everything requires TLS 1.2, but we'll try anyway.
            Write-Warning "TLS 1.2 and or TLS 1.3 are not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        $i = 1
        While ($i -le $Attempts) {
            # Some cloud services have rate-limiting
            if (-not ($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
        
            if ($i -ne 1) { Write-Host "" }
            Write-Host "Download Attempt $i"

            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                # Invoke-WebRequest is preferred because it supports links that redirect, e.g., https://t.ly
                if ($PSVersionTable.PSVersion.Major -lt 4) {
                    # Downloads the file
                    $WebClient = New-Object System.Net.WebClient
                    $Response = $WebClient.OpenRead($Url)
                    $MimeType = $WebClient.ResponseHeaders["Content-Type"]
                    $DesiredExtension = switch -regex ($MimeType) {
                        "image/jpeg|image/jpg" { "jpg" }
                        "image/png" { "png" }
                        "image/gif" { "gif" }
                        "image/bmp|image/x-windows-bmp|image/x-bmp" { "bmp" }
                        default {
                            throw [System.BadImageFormatException]::New("The URL you provided does not provide a supported image type. Image types supported: jpg, jpeg, bmp, png, and gif. Image type detected: $MimeType")
                        }
                    }
                    $Path = "$BasePath.$DesiredExtension"
                    $WebClient.DownloadFile($URL, $Path)
                    $Response.Close()
                }
                else {
                    # Use Invoke-WebRequest for newer PowerShell versions
                    $WebRequestArgs = @{
                        Uri                = $URL
                        MaximumRedirection = 10
                        UseBasicParsing    = $true
                    }

                    # Get MIME type and download the file
                    $Response = Invoke-WebRequest @WebRequestArgs -Method "Head" -ErrorAction Stop
                    $MimeType = $Response.Headers."Content-Type"
                    $DesiredExtension = switch -regex ($MimeType) {
                        "image/jpeg|image/jpg" { "jpg" }
                        "image/png" { "png" }
                        "image/gif" { "gif" }
                        "image/bmp|image/x-windows-bmp|image/x-bmp" { "bmp" }
                        default { 
                            throw [System.BadImageFormatException]::New("The URL you provided does not provide a supported image type. Image types supported: jpg, jpeg, bmp, png, and gif. Image type detected: $MimeType")

                        }
                    }
                    $Path = "$BasePath.$DesiredExtension"
                    Invoke-WebRequest @WebRequestArgs -OutFile $Path -ErrorAction Stop
                }

                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch [System.BadImageFormatException] {
                # If a bad image format exception occurs, exit the loop
                $i = $Attempts
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
            catch {
                Write-Warning "An error has occurred while downloading!"
                Write-Warning $_.Exception.Message

                if ($Path -and (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            $ProgressPreference = $PreviousProgressPreference
            if ($File) {
                $i = $Attempts
            }
            else {
                Write-Warning "File failed to download."
                Write-Host ""
            }

            $i++
        }

        if (!$Path -or !(Test-Path $Path)) {
            Write-Host -Object "[Error] Failed to download file."
            Write-Host -Object "Please verify the URL of '$URL'."
            exit 1
        }
        else {
            try {
                $FileObject = $Path | Get-Item -Force -ErrorAction Stop
                Write-Host -Object "Successfully downloaded image."
            }
            catch {
                Write-Host -Object "[Error] Failed to get downloaded file info."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }

            return $FileObject
        }
    }

    Function Wait-RtTask {
        param(
            $WinRtTask,
            $ResultType
        )

        $GenericAsTaskMethod = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' } | ForEach-Object {
            $ParameterMethods = $_.GetParameters()
            if ($ParameterMethods.Count -eq 1 -and $ParameterMethods.ParameterType.Name -eq 'IAsyncOperation`1') {
                $_
            }
        }
        $GenericAsTaskMethod = $GenericAsTaskMethod.MakeGenericMethod($ResultType)
        $DotNetTask = $GenericAsTaskMethod.Invoke($null, @($WinRtTask))
        $DotNetTask.Wait(-1) | Out-Null
        $DotNetTask.Result
    }
    Function Wait-RtAction {
        param(
            $WinRtAction
        )

        $AsTaskMethod = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and !($_.IsGenericMethod) } | ForEach-Object {
            $ParameterMethods = $_.GetParameters()
            if ($ParameterMethods.Count -eq 1) {
                $_
            }
        }
        $DotNetTask = $AsTaskMethod.Invoke($null, @($WinRtAction))
        $DotNetTask.Wait(-1) | Out-Null
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
                Write-Host "[Error] Unable to create the registry path $Path for $Name. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
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
                Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host "Set $Path\$Name to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
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

    function Get-User {
        $quser = quser.exe 2>&1 | Where-Object { $_ -notlike "No User exists for *" }
        $quser -replace '\s{2,}', ',' -replace '>' | ConvertFrom-Csv
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # If the destination is specified, retrieve the full path of the destination
    if ($Destination) {
        try {
            $DestinationPath = Get-Item -Path $Destination -Force -ErrorAction Stop | Select-Object -ExpandProperty FullName -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Unable to find destination path '$Destination'."
            exit 1
        }
    }

    # If the action is to remove the modification lock, proceed with the removal
    if ($Action -eq "Remove Modification Lock") {
        Write-Host -Object "Removing modification lock."
        $ModificationLock = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LockScreenImagePath -ErrorAction SilentlyContinue

        if ($ModificationLock) {
            try {
                Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImagePath" -Force
                Write-Host -Object "Removed registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP\LockScreenImagePath'."
            }
            catch {
                Write-Host -Object "[Error] Unable to remove the registry key at 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP\LockScreenImagePath'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }

        Write-Host -Object "Successfully removed modification lock."
        exit $ExitCode
    }

    # If the action is to use Windows Spotlight, proceed with the configuration
    if ($Action -eq "Use Windows Spotlight") {
        if (!(Test-IsSystem)) {
            Write-Host -Object "Setting lock screen to 'Windows Spotlight' for $env:USERNAME."
            Set-RegKey -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 1
            Write-Host -Object "Successfully set lock screen for $env:USERNAME."

            exit $ExitCode
        }

        $UserProfiles = Get-UserHives -Type "All"

        # Loop through each profile on the machine
        foreach ($UserProfile in $UserProfiles) {
            # Load User ntuser.dat if it's not already loaded
            If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            }

            Write-Host -Object "`nSetting lock screen to 'Windows Spotlight' for $($UserProfile.Username)."
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 1
            Write-Host -Object "Successfully set lock screen to 'Windows Spotlight' for $($UserProfile.Username)."
            
            # Unload NTuser.dat
            If ($ProfileWasLoaded -eq $false) {
                [gc]::Collect()
                Start-Sleep 1
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
            }
        }

        exit $ExitCode
    }

    # Check if the image is a URL (does not contain a backslash)
    if ($Image -notmatch "\\") {
        # Download the image from the URL to a temporary location
        $ImageFile = Invoke-Download -BasePath "$env:TEMP\$(Get-Random)" -URL $Image

        # Output message indicating the image is being moved to the destination
        Write-Host -Object "Moving image from '$($ImageFile.FullName)' to destination."

        # Generate the hash of the downloaded image file using the MD5 algorithm and get the file extension.
        $ImageHash = Get-FileHash -Path $ImageFile -Algorithm "MD5" | Select-Object -ExpandProperty Hash
        $Extension = $ImageFile | Select-Object -ExpandProperty Extension

        # Rename the image file to its hash value if it doesn't already exist
        if (!(Test-Path -Path "$DestinationPath\$ImageHash$Extension" -ErrorAction SilentlyContinue)) {
            try {
                # Move the image file to the destination with the hashed name
                Move-Item -Path $ImageFile -Destination "$DestinationPath\$ImageHash$Extension" -Force -ErrorAction Stop
                $DesiredLockscreen = Get-Item -Path "$DestinationPath\$ImageHash$Extension" -Force -ErrorAction Stop
                Write-Host -Object "Moved image to destination '$DestinationPath\$ImageHash$Extension'."
            }
            catch {
                # Output error message if unable to move the image
                Write-Host -Object "[Error] Unable to move image into the desired destination folder."
                Write-Host -Object "[Error] $($_.Exception.Message)"
            }
        }
        else {
            # Output message indicating the image already exists at the destination
            Write-Host -Object "Image already existed at destination using '$DestinationPath\$ImageHash$Extension' instead."
        }

        # Check if the image file exists at the destination and clean up the temporary download location
        if (Test-Path -Path "$DestinationPath\$ImageHash$Extension" -ErrorAction SilentlyContinue) {
            try {
                # Remove the temporary downloaded image file
                Remove-Item -Path $ImageFile -Force -ErrorAction SilentlyContinue
                $DesiredLockscreen = Get-Item -Path "$DestinationPath\$ImageHash$Extension" -Force -ErrorAction Stop
            }
            catch {
                # Output error message if unable to retrieve the image info from the destination
                Write-Host -Object "[Error] Unable to retrieve image file at '$DestinationPath\$ImageHash$Extension'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
    }

    # Check if the image is a local path and the destination is specified
    if ($Image -match "\\" -and $Destination) {
        # Retrieve the image file from the specified path
        $ImageFile = Get-Item -Path $Image -Force

        # Output message indicating the image is being copied
        Write-Host -Object "Copying image from '$($ImageFile.FullName)' to destination."

        # Generate the hash of the image file using MD5 algorithm and get the file extension.
        $ImageHash = Get-FileHash -Path $ImageFile -Algorithm "MD5" | Select-Object -ExpandProperty Hash
        $Extension = $ImageFile | Select-Object -ExpandProperty Extension

        # Check if the image with the hashed name already exists at the destination
        if (!(Test-Path -Path "$DestinationPath\$ImageHash$Extension" -ErrorAction SilentlyContinue)) {
            try {
                # Copy the image file to the destination with the hashed name
                Copy-Item -Path $ImageFile -Destination "$DestinationPath\$ImageHash$Extension" -Force -ErrorAction Stop
                Write-Host -Object "Successfully copied image to '$DestinationPath\$ImageHash$Extension'."
            }
            catch {
                # Output error message if unable to copy the image
                Write-Host -Object "[Error] Unable to copy image into the desired destination folder."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }

        try {
            # Retrieve the copied image file from the destination
            $DesiredLockscreen = Get-Item -Path "$DestinationPath\$ImageHash$Extension" -Force -ErrorAction Stop
            Write-Host -Object "Image already existed at destination using '$DestinationPath\$ImageHash$Extension' instead."
        }
        catch {
            # Output error message if unable to retrieve the image info from the destination
            Write-Host -Object "[Error] Unable to retrieve image info for '$DestinationPath\$ImageHash$Extension'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
    elseif ($Image -match "\\") {
        # Check if the image is a local path but the destination is not specified

        # Retrieve the image file from the specified path
        $DesiredLockscreen = Get-Item -Path $Image -Force

        # Output message indicating the lock screen is being set to the image file
        Write-Host -Object "Setting lock screen to '$($ImageFile.FullName)'."
    }

    # Perform actions based on the specified action
    switch ($Action) {
        "Set Image" {
            try {
                Write-Host -Object "Setting lock screen to '$($DesiredLockscreen.FullName)' for $env:USERNAME."
                $IStorageFile = Wait-RtTask -WinRtTask ([Windows.Storage.StorageFile]::GetFileFromPathAsync($($DesiredLockscreen.FullName))) -ResultType ([Windows.Storage.StorageFile])
                Wait-RtAction -WinRtAction ([Windows.System.UserProfile.LockScreen]::SetImageFileAsync($IStorageFile))
                Write-Host -Object "Successfully set lock screen for $env:USERNAME."
            }
            catch {
                Write-Host -Object "[Error] Unable to set lock screen wallpaper."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
        "Set Image and Disable Modifications" {
            Write-Host -Object "Setting lock screen to '$($DesiredLockscreen.FullName)' and applying modification lock."
            Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImagePath" -Value "$($DesiredLockscreen.FullName)" -PropertyType String
            Write-Host -Object "Lockscreen has been successfully set."
        }
    }

    if (!(Get-User) -and !$ForceRestart) {
        Write-Host -Object "[Warning] A restart may be required for the script to take immediate effect."
    }

    if ($ForceRestart) {
        Write-Host -Object "Scheduling restart for $((Get-Date).AddSeconds(60)) as requested."
        Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
    }

    exit $ExitCode
}
end {
    
    
    
}
