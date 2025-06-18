# This sets the desktop background for all existing users (if run as System) or the currently logged-in user (if run as Current Logged on User). To have the wallpaper change take effect immediately, please select Replace Transcoded Wallpaper File and Restart Explorer.

<#
.SYNOPSIS
    This sets the desktop background for all existing users (if run as System) or the currently logged-in user (if run as 'Current Logged on User'). To have the wallpaper change take effect immediately, please select "Replace Transcoded Wallpaper File" and "Restart Explorer".
.DESCRIPTION
    This sets the desktop background for all existing users (if run as System) or the currently logged-in user (if run as 'Current Logged on User'). To have the wallpaper change take effect immediately, please select "Replace Transcoded Wallpaper File" and "Restart Explorer".

PARAMETER: -WallpaperFile "https://www.example.com/image.png"
    A URL link or file path to your desired wallpaper.

PARAMETER: -WallpaperFile "C:\image.png"
    A URL link or file path to your desired wallpaper.

PARAMETER: -Directory "C:\Example\Example"
   Path to store the wallpaper file (must be accessible by user accounts using the wallpaper).

.EXAMPLE
    -WallpaperFile "https://www.microsoft.com/en-us/microsoft-365/blog/wp-content/uploads/sites/2/2021/06/Msft_Nostalgia_Landscape.jpg" -Directory "C:\ProgramData\Wallpaper" -ReplaceTranscodedWallpaperFile -RestartExplorer (Windows 10 as System)
    
    Waiting for 14 seconds.
    Download Attempt 1

    Setting wallpaper for tuser.
    Registry::HKEY_USERS\S-1-5-21-1216116932-1462928010-1466897618-1001\Control Panel\Desktop\Wallpaper changed from C:\ProgramData\Wallpaper\E6F3FA539619EE93CFA36A216782B3F7.jpg to C:\ProgramData\Wallpaper\4F9F3D77096E683EBD65ABFD5A529811.jpg
    Registry::HKEY_USERS\S-1-5-21-1216116932-1462928010-1466897618-1001\Control Panel\Desktop\WallpaperStyle changed from 10 to 10
    Registry::HKEY_USERS\S-1-5-21-1216116932-1462928010-1466897618-1001\Control Panel\Desktop\TileWallpaper changed from 0 to 0
    Replacing transcoded wallpaper file for tuser.

    Setting wallpaper for Administrator.
    Registry::HKEY_USERS\S-1-5-21-1216116932-1462928010-1466897618-500\Control Panel\Desktop\Wallpaper changed from C:\Users\ADMINI~1\AppData\Local\Temp\BGInfo.bmp to C:\ProgramData\Wallpaper\4F9F3D77096E683EBD65ABFD5A529811.jpg
    Registry::HKEY_USERS\S-1-5-21-1216116932-1462928010-1466897618-500\Control Panel\Desktop\WallpaperStyle changed from 0 to 10
    Registry::HKEY_USERS\S-1-5-21-1216116932-1462928010-1466897618-500\Control Panel\Desktop\TileWallpaper changed from 1 to 0
    Replacing transcoded wallpaper file for Administrator.

    Restarting Explorer.exe as requested.

PARAMETER: -WallpaperStyle "Fill"
    This option sets how the wallpaper is displayed in Windows (described as 'Fit' in the Control Panel). Valid Options: "Fill", "Fit", "Stretch", "Tile", "Center", "Span"

PARAMETER: -ReplaceTranscodedWallpaperFile
    Replace the file %APPDATA%\Microsoft\Windows\Themes\TranscodedWallpaper. This file is generated whenever the wallpaper is changed and is required for the wallpaper change to take immediate effect.

PARAMETER: -RestartExplorer
    Restart explorer.exe. This is required for the wallpaper change to take immediate effect.

.OUTPUTS
    None
.NOTES
    Minimum Supported OS: Windows 10+, Server 2012R2+
    Release Notes: Combined existing image option with wallpaper link. Switched to using file hash when saving a downloaded image. Added more input validation. Reorganized some of the code.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$WallpaperFile,
    [Parameter()]
    [String]$Directory,
    [Parameter()]
    [String]$WallpaperStyle = "Fill",
    [Parameter()]
    [Switch]$ReplaceTranscodedWallpaperFile = [System.Convert]::ToBoolean($env:replaceTranscodedWallpaperFile),
    [Parameter()]
    [Switch]$RestartExplorer = [System.Convert]::ToBoolean($env:restartExplorer)
)

begin {

    # Set Dynamic Script Variables (if used)
    if ($env:wallpaperFile -and $env:wallpaperFile -notlike "null") { $WallpaperFile = $env:wallpaperFile }
    if ($env:directoryToStoreWallpaperIn -and $env:directoryToStoreWallpaperIn -notlike "null") { $Directory = $env:directoryToStoreWallpaperIn }
    if ($env:wallpaperDisplayMode -and $env:wallpaperDisplayMode -notlike "null") { $WallpaperStyle = $env:wallpaperDisplayMode }

    # Warn that older operating systems may not show the wallpaper change immediately
    if ([System.Environment]::OSVersion.Version.Major -lt 10) {
        Write-Warning "On older operating systems, wallpaper changes may require the user to log out and log back in to take effect."
    }

    # Check if $WallpaperFile is not set, and if not, output an error and exit the script
    if (!$WallpaperFile) {
        Write-Host -Object "[Error] No image path or link given to use as a wallpaper!"
        exit 1
    }

    # If the wallpaper link starts with "www." and not "http", prepend "https://"
    if ($WallpaperFile.Trim() -match "^www\." -and $WallpaperFile.Trim() -notmatch "^http") {
        $WallpaperFile = "https://$WallpaperFile"
        Write-Warning -Message "Wallpaper link is missing the http(s). Link has been changed to the following: '$WallpaperFile'"
    }

    # If $WallpaperFile is not a URL and does not exist as a file, output an error and exit the script
    if ($WallpaperFile -notmatch "http" -and !(Test-Path -Path $WallpaperFile -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] Unable to find wallpaper at '$WallpaperFile'."
        exit 1
    }

    # If $WallpaperFile is not a URL and is a directory, output an error and exit the script
    if ($WallpaperFile -notmatch "http" -and (Get-Item -Path $WallpaperFile).PSIsContainer) {
        Write-Host -Object "[Error] The wallpaper file given is actually a folder. '$WallpaperFile'"
        exit 1
    }

    # If $WallpaperFile is a URL and contains invalid characters according to RFC3986, output an error and exit the script
    if ($WallpaperFile -match "http" -and $WallpaperFile -match "[^A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]") {
        Write-Host -Object "[Error] The url '$WallpaperFile' contains an invalid character according to RFC3986."
        exit 1
    }

    # If $Directory is not set, output an error and exit the script
    if (!$Directory) {
        Write-Host -Object "[Error] You must specify a location to store the wallpaper."
        exit 1
    }

    # If $Directory contains invalid characters, output an error and exit the script
    if ($Directory -and ($Directory -match '[/*?"<>|]' -or $Directory.SubString(3) -match "[:]")) {
        Write-Host -Object "[Error] The location you specified contains one of the following invalid characters. '/*?`"<>|:'"
        exit 1
    }

    # Check each folder in the directory path for reserved names and output an error if any are found
    if ($Directory) {
        $Directory -split '\\' | ForEach-Object {
            $Folder = ($_).Trim()
            if ($Folder -match '^CON$' -or $Folder -match '^PRN$' -or $Folder -match '^AUX$' -or $Folder -match '^NUL$' -or $Folder -match '^LPT\d$' -or $Folder -match '^COM\d+$') {
                Write-Host -Object "[Error] An invalid folder name was given in $Directory. The following folder names are reserved! 'CON, PRN, AUX, NUL, COM1-9, LPT1-9'"
                exit 1
            }
        }
    }

    # If $Directory does not exist, attempt to create it and output an error if it fails
    if ($Directory -and !(Test-Path -Path $Directory -ErrorAction SilentlyContinue)) {
        try {
            New-Item -Path $Directory -ItemType Directory -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Host -Object "[Error] Failed to create directory!"
            exit 1
        }
    }

    # If $WallpaperStyle is not set, output an error and exit the script
    if (!$WallpaperStyle) {
        Write-Host -Object "[Error] You must specify a 'Display Mode' for the wallpaper."
        exit 1
    }

    # Define allowed wallpaper display modes
    $AllowedFit = "Fill", "Fit", "Stretch", "Tile", "Center", "Span"

    # Check if the provided $WallpaperStyle is one of the allowed display modes
    if ($AllowedFit -notcontains $WallpaperStyle) {
        Write-Host -Object "[Error] Invalid Wallpaper Display Mode selected. Please use one of the following options. Fill, Fit, Stretch, Tile, Center or Span."
        exit 1
    }

    # Check if the $RestartExplorer flag is not set
    if (!$RestartExplorer) {
        Write-Warning "Restarting Explorer.exe is required for wallpaper change to take effect!"
    }

    # Utility function for downloading files.
    function Invoke-Download {
        param(
            [Parameter()]
            [String]$URL,
            [Parameter()]
            [String]$BaseName,
            [Parameter()]
            [String]$Path,
            [Parameter()]
            [int]$Attempts = 3,
            [Parameter()]
            [Switch]$SkipSleep
        )

        # Set supported TLS versions
        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Warning if TLS 1.2 or TLS 1.3 is not supported
            Write-Warning -Message "TLS 1.2 and or TLS 1.3 is not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning -Message "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        # Silence progress preference for speed boost
        $PreviousProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        $i = 1
        While ($i -le $Attempts) {
            # Introduce random sleep to avoid rate-limiting issues
            if (-not ($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host -Object "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
        
            if ($i -ne 1) { Write-Host -Object "" }
            Write-Host -Object "Download Attempt $i"

            try {
                if ($PSVersionTable.PSVersion.Major -lt 4) {
                    # Use WebClient for older PowerShell versions
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
                    $Path = "$BaseName.$DesiredExtension"
                    $WebClient.DownloadFile($URL, $Path)
                    $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
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
                    $Path = "$BaseName.$DesiredExtension"
                    Invoke-WebRequest @WebRequestArgs -OutFile $Path -ErrorAction Stop
                }

                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch [System.BadImageFormatException] {
                # If a bad image format exception occurs, exit the loop
                $i = $Attempts
                throw $_
            }
            catch {
                # Handle general download errors
                Write-Warning -Message "An error has occurred while downloading!"
                Write-Warning -Message $_.Exception.Message

                # Remove the partially downloaded file if it exists
                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item -Path $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            # Exit loop if the file is successfully downloaded
            if ($File) {
                $i = $Attempts
            }
            else {
                Write-Warning -Message "File failed to download."
                Write-Host -Object ""
            }

            $i++
        }

        $ProgressPreference = $PreviousProgressPreference

        if (-not (Test-Path -Path $Path)) {
            throw [System.IO.FileNotFoundException]::New("Failed to download file!")
        }
        else {
            return $Path
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
    
        # User account SIDs follow specific patterns depending on if they are Azure AD, Domain, or local accounts.
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # Retrieve user profiles by matching account SIDs to the defined patterns.
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } | 
                Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                @{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                @{Name = "Path"; Expression = { $_.ProfileImagePath } }
        }
    
        # Optionally include the .Default user profile if requested.
        switch ($IncludeDefault) {
            $True {
                $DefaultProfile = "" | Select-Object UserName, SID, UserHive, Path
                $DefaultProfile.UserName = "Default"
                $DefaultProfile.SID = "DefaultProfile"
                $DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                $DefaultProfile.Path = "C:\Users\Default"

                # Add default profile to the list if it's not in the excluded users list
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.UserName }
            }
        }

        # Filter out the excluded users from the user profiles list and return the result.
        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
    }

    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )

        # Check if the registry path exists; if not, create it
        if (!$(Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        # Check if the registry key already exists
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                # Set the value of the existing registry key
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                # Handle errors during setting the registry key
                Write-Host "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }

            # Output the change in registry key value
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            try {
                # Create a new registry key with the specified value and property type
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                # Handle errors during creating the registry key
                Write-Host "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }

            # Output the newly set registry key value
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    # Get-FileHash is not available until PowerShell 4
    if ($PSVersionTable.PSVersion.Major -lt 4) {
        # Define a function to get the hash of a file
        function Get-FileHash {
            param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
                [string[]]$Path,
                [Parameter(Mandatory = $false)]
                [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512", "MD5")]
                [string]$Algorithm = "SHA256"
            )

            # Process each path provided
            $Path | ForEach-Object {
                # Only hash files that exist
                $CurrentPath = $_
                if ($(Test-Path -Path $CurrentPath -ErrorAction SilentlyContinue)) {
                    # Create the hash algorithm object
                    $HashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
                    # Compute the hash of the file's contents
                    $Hash = [System.BitConverter]::ToString($hashAlgorithm.ComputeHash([System.IO.File]::ReadAllBytes($CurrentPath)))
                    # Create a new object with the hash information
                    New-Object psobject -Property @{
                        Algorithm = $Algorithm
                        Path      = $Path
                        Hash      = $Hash.Replace('-', '')
                    }
                }
            }
        }
    }

    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {

    # Check if the wallpaper file is a URL
    if ($WallpaperFile -match "http") {
        try {
            # Set the error action preference to stop on errors
            $ErrorActionPreference = "Stop"

            # Download the image and get the file item
            $Image = Invoke-Download -Url $WallpaperFile -BaseName "$Directory\$(Get-Random)" | Get-Item -Force

            # Get the full path and hash of the downloaded image
            $ImagePath = $Image | Select-Object -ExpandProperty FullName
            $ImageHash = Get-FileHash -Path "$ImagePath" -Algorithm "MD5" | Select-Object -ExpandProperty Hash
            $Extension = $Image | Select-Object -ExpandProperty Extension

            # Rename the image file to its hash value if it doesn't already exist
            if (!(Test-Path -Path "$Directory\$ImageHash$Extension")) {
                Rename-Item -Path $ImagePath -NewName "$ImageHash$Extension" -Force
            }
            else {
                # Remove the downloaded image if a file with the same hash already exists
                Remove-Item -Path $ImagePath -Force
            }

            # Set the path to the existing image
            $ExistingImage = "$Directory\$ImageHash$Extension"

            # Reset the error action preference
            $ErrorActionPreference = "Continue"
        }
        catch {
            # Handle errors during the download and processing of the image
            Write-Host -Object "[Error] Unable to use downloaded image!"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Check if the wallpaper file is not a URL
    if ($WallpaperFile -notmatch "http") {
        try {
            # Set the error action preference to stop on errors
            $ErrorActionPreference = "Stop"

            # Get the file item for the existing wallpaper
            $SourceWallpaper = Get-Item -Path $WallpaperFile -Force 
            $SourceWallpaperPath = $SourceWallpaper | Select-Object -ExpandProperty FullName
            $SourceWallpaperDirectory = $SourceWallpaper | Select-Object -ExpandProperty Directory | Select-Object -ExpandProperty FullName
            $SourceWallpaperExtension = $SourceWallpaper | Select-Object -ExpandProperty Extension

            # Get the full path of the destination directory
            $DestinationDirectory = Get-Item -Path $Directory -Force | Select-Object -ExpandProperty FullName
            $WallpaperName = $SourceWallpaperPath | Split-Path -Leaf

            # Check if the image file type is supported
            if ($SourceWallpaperExtension -notmatch 'jpeg|jpg|png|gif|bmp') {
                throw [System.BadImageFormatException]::New("The image you provided is not a supported image type. Image types supported: .jpg, .jpeg, .bmp, .png, and .gif. Image type detected: $SourceWallpaperExtension")
            }

            # Copy the image file to the destination directory if it's not already there
            if ($SourceWallpaperDirectory -ne $DestinationDirectory) {
                Copy-Item -Path $SourceWallpaperPath -Destination $Directory -Force
            }

            # Set the path to the existing image
            $ExistingImage = "$DestinationDirectory\$WallpaperName"
            # Reset the error action preference
            $ErrorActionPreference = "Continue"
        }
        catch {
            # Handle errors during the processing of the existing image
            Write-Host -Object "[Error] Unable to use existing image!"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Initialize a list to store user objects for whom the wallpaper will be changed
    $UsersToChangeWallpaperFor = New-Object System.Collections.Generic.List[object]

    # Check if the script is not running as System
    if (!(Test-IsSystem)) {
        # Add the currently logged-in user to the list
        $UsersToChangeWallpaperFor.Add(
            [PSCustomObject]@{
                Username       = $env:Username
                BasePath       = "Registry::HKEY_CURRENT_USER"
                TranscodedPath = $env:AppData
            }
        )
    }
    else {
        # If running as System, get all user profiles
        $UserProfiles = Get-UserHives -Type "All"
        $LoadedProfiles = New-Object System.Collections.Generic.List[string]

        # Iterate over each user profile
        Foreach ($UserProfile in $UserProfiles) {
            # Check if the user registry hive is not already loaded
            if ((Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
                $LoadedProfiles.Add("$($UserProfile.SID)")

                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            }

            # Add the user profile to the list
            $UsersToChangeWallpaperFor.Add(
                [PSCustomObject]@{
                    Username       = $UserProfile.UserName
                    BasePath       = "Registry::HKEY_USERS\$($UserProfile.SID)"
                    TranscodedPath = "$($UserProfile.Path)\AppData\Roaming"
                }
            )
        }
    }

    # Iterate over each user object in the list
    $UsersToChangeWallpaperFor | ForEach-Object {
        Write-Host "`nSetting wallpaper for $($_.Username)."

        # Define the registry key path for the desktop settings
        $RegKey = "$($_.BasePath)\Control Panel\Desktop"
        # Determine the wallpaper style value based on the provided style
        $Style = switch ($WallpaperStyle) {
            "Fill" { 10 }
            "Fit" { 6 }
            "Stretch" { 2 }
            "Tile" { 0 }
            "Center" { 0 }
            "Span" { 22 }
        }

        # Set the registry key values for the wallpaper and style
        Set-RegKey -Path $RegKey -Name "Wallpaper" -Value $ExistingImage -PropertyType "String"
        Set-RegKey -Path $RegKey -Name "WallpaperStyle" -Value $Style -PropertyType "String"
        if ($WallpaperStyle -eq "Tile") {
            Set-RegKey -Path $RegKey -Name "TileWallpaper" -Value 1 -PropertyType "String"
        }
        else {
            Set-RegKey -Path $RegKey -Name "TileWallpaper" -Value 0 -PropertyType "String"
        }

        # If replacing the transcoded wallpaper file is requested
        if ($ReplaceTranscodedWallpaperFile) {
            Write-Host "Replacing transcoded wallpaper file for $($_.Username)."

            # Check if the TranscodedWallpaper file exists, if not, create it
            if (!(Test-Path -Path "$($_.TranscodedPath)\Microsoft\Windows\Themes\TranscodedWallpaper" -ErrorAction SilentlyContinue)) {
                Write-Host -Object "Transcoded wallpaper file does not exist. Creating it."
                New-Item -ItemType "file" -Path "$($_.TranscodedPath)\Microsoft\Windows\Themes" -Name "TranscodedWallpaper" | Out-Null
    
                Start-Sleep -Seconds 7
            }

            # Get the TranscodedWallpaper file
            $TranscodedWallpaper = Get-ChildItem -Path "$($_.TranscodedPath)\Microsoft\Windows\Themes" | Where-Object { $_.Name -eq "TranscodedWallpaper" }

            # Check for multiple TranscodedWallpaper files
            if (($TranscodedWallpaper | Measure-Object).Count -gt 1) {
                Write-Warning -Message "There is more than 1 Transcoded wallpaper file. User $($_.Username) may have to log out and log back in again to complete the wallpaper update."

                return
            }
            
            # Check for missing TranscodedWallpaper files
            if (($TranscodedWallpaper | Measure-Object).Count -lt 1) {
                Write-Warning -Message "Transcoded wallpaper file does not exist. User $($_.Username) may have to log out and log back in again to complete the wallpaper update."

                return
            }

            # Try to update the TranscodedWallpaper file
            try {
                if (Test-Path -Path $TranscodedWallpaper.FullName -ErrorAction SilentlyContinue) { 
                    Get-Item -Path $TranscodedWallpaper.FullName | Remove-Item -Force 
                }
                Copy-Item -Path $ExistingImage -Destination $TranscodedWallpaper.FullName -Force -ErrorAction Stop
            }
            catch {
                Write-Warning -Message "Failed to update Transcoded wallpaper file. User $($_.Username) may have to log out and log back in again to complete the wallpaper update."
                Write-Warning -Message "$($_.Exception.Message)"
            }
        }
    }

    # Check if the script is running as System
    if (Test-IsSystem) {
        # Iterate over each loaded profile
        Foreach ($LoadedProfile in $LoadedProfiles) {
            [gc]::Collect()
            Start-Sleep -Seconds 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($LoadedProfile)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Check if restarting Explorer is requested
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

    exit $ExitCode
}
end {
    
    
    
}
