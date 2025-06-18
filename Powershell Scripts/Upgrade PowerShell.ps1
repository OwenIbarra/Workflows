# Cross-platform PowerShell installation and upgrade script. Supports Windows PowerShell 5.1 upgrade and PowerShell Core installation on Linux/macOS.
#Requires -Version 2.0

<#
.SYNOPSIS
    Cross-platform PowerShell installation and upgrade script. Upgrades Windows PowerShell to 5.1 or installs PowerShell Core on Linux/macOS.
.DESCRIPTION
    This script provides cross-platform PowerShell installation capabilities:
    - Windows: Upgrades PowerShell to version 5.1 by installing .NET Framework 4.5.2 and Windows Management Framework (WMF)
    - Linux: Installs PowerShell Core using package managers
    - macOS: Installs PowerShell Core using Homebrew or direct download
.EXAMPLE
    -ForceRestart

    - On Windows: Downloads and installs .NET Framework 4.5.2, followed by PowerShell 5.1, and schedules a restart.
    - On Linux/macOS: Installs PowerShell Core

PARAMETER: -ForceRestart
    Windows only: A system restart will be scheduled to occur 60 seconds after the script has successfully completed.

.NOTES
    Minimum OS Architecture Supported: Windows 7 SP1, Windows Server 2008 R2 SP1, Linux (various distributions), macOS 10.13+
    Release Notes: Updated for cross-platform support. Windows-specific functionality preserved for PowerShell 5.1 upgrade.
    Linux/macOS functionality added for PowerShell Core installation.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$DotNetDownloadLink = "http://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe",
    [Parameter()]
    [String]$ExpectedDotNetSHA256 = "6C2C589132E830A185C5F40F82042BEE3022E721A216680BD9B3995BA86F3781",
    [Parameter()]
    [String]$Win7AndW2K8R2WMF5164Link = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip",
    [Parameter()]
    [String]$ExpectedWin7AndW2K8R2WMF5164SHA256 = "F383C34AA65332662A17D95409A2DDEDADCEDA74427E35D05024CD0A6A2FA647",
    [Parameter()]
    [String]$Win7WMF5132Link = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7-KB3191566-x86.zip",
    [Parameter()]
    [String]$ExpectedWin7WMF5132SHA256 = "EB7E2C4CE2C6CB24206474A6CB8610D9F4BD3A9301F1CD8963B4FF64E529F563",
    [Parameter()]
    [String]$Win2012WMF51Link = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/W2K12-KB3191565-x64.msu",
    [Parameter()]
    [String]$ExpectedWin2012SHA256 = "4A1385642C1F08E3BE7BC70F4A9D74954E239317F50D1A7F60AA444D759D4F49",
    [Parameter()]
    [String]$Win81AndW2K12R2WMF5164Link = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1AndW2K12R2-KB3191564-x64.msu",
    [Parameter()]
    [String]$ExpectedWin81AndW2K12R264HA256 = "A8D788FA31B02A999CC676FB546FC782E86C2A0ACD837976122A1891CEEE42C0",
    [Parameter()]
    [String]$Win81WMF5132Link = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win8.1-KB3191564-x86.msu",
    [Parameter()]
    [String]$ExpectedWin81WMF5132SHA256 = "F3430A90BE556A77A30BAB3AC36DC9B92A43055D5FCC5869DA3BFDA116DBD817",
    [Parameter()]
    [Switch]$ForceRestart = [System.Convert]::ToBoolean($env:forceRestart)
)

begin {
    # Cross-platform OS detection
    function Get-OperatingSystem {
        if ($IsWindows -or $env:OS -like "Windows*") {
            return "Windows"
        } elseif ($IsLinux) {
            return "Linux"
        } elseif ($IsMacOS) {
            return "macOS"
        } else {
            return "Unknown"
        }
    }

    $OS = Get-OperatingSystem

    # Handle non-Windows systems differently
    if ($OS -eq "Linux") {
        Write-Host "Detected Linux system. Installing PowerShell Core..."
        
        # Detect Linux distribution
        if (Test-Path "/etc/os-release") {
            $OSRelease = Get-Content "/etc/os-release" | ConvertFrom-StringData
            $LinuxDistro = $OSRelease.ID
            
            switch ($LinuxDistro) {
                "ubuntu" {
                    Write-Host "Installing PowerShell Core on Ubuntu..."
                    Invoke-Expression "sudo apt-get update && sudo apt-get install -y wget apt-transport-https software-properties-common"
                    Invoke-Expression "wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb"
                    Invoke-Expression "sudo dpkg -i packages-microsoft-prod.deb"
                    Invoke-Expression "sudo apt-get update && sudo apt-get install -y powershell"
                }
                { $_ -eq "centos" -or $_ -eq "rhel" -or $_ -eq "fedora" } {
                    Write-Host "Installing PowerShell Core on RHEL/CentOS/Fedora..."
                    Invoke-Expression "sudo yum install -y https://packages.microsoft.com/config/rhel/7/packages-microsoft-prod.rpm"
                    Invoke-Expression "sudo yum install -y powershell"
                }
                default {
                    Write-Host "For other Linux distributions, please visit:"
                    Write-Host "https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux"
                }
            }
        }
        exit 0
    }
    
    if ($OS -eq "macOS") {
        Write-Host "Detected macOS system. Installing PowerShell Core..."
        
        # Check if Homebrew is available
        if (Get-Command "brew" -ErrorAction SilentlyContinue) {
            Write-Host "Installing PowerShell Core via Homebrew..."
            Invoke-Expression "brew install --cask powershell"
        } else {
            Write-Host "Homebrew not found. Please install Homebrew or visit:"
            Write-Host "https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-macos"
            Write-Host "To install via package: https://github.com/PowerShell/PowerShell/releases"
        }
        exit 0
    }
    
    if ($OS -ne "Windows") {
        Write-Host "Unsupported operating system: $OS"
        Write-Host "This script supports Windows, Linux, and macOS."
        exit 1
    }

    # Windows-specific code continues below...
    Write-Host "Detected Windows system. Proceeding with PowerShell 5.1 upgrade..."

    # Try to retrieve the list of currently installed services
    try {
        $CurrentServices = Get-Service -ErrorAction Stop | Select-Object -ExpandProperty ServiceName -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Unable to check for Exchange services."
        exit 1
    }

    # Define a list of Microsoft Exchange services that must not be installed
    $ExchangeServices = "MSExchangeADTopology", "MSExchangeAntispamUpdate", "MSExchangeEdgeSync", "MSExchangeFDS", "MSExchangeFrontEndTransport", 
    "MSExchangeIS", "MSExchangeMailboxAssistants", "MSExchangeMailboxReplication", "MSExchangePOP3", "MSExchangeTransport", "MSExchangeUM", "MSExchangeServiceHost"

    # Check if any of the Exchange services are installed
    $ExchangeServices | ForEach-Object {
        if ($CurrentServices -contains $_) {
            Write-Host -Object "[Error] Microsoft Exchange service '$_' was found. Upgrading PowerShell will break Exchange. Upgrade aborted."
            exit 1
        }
    }
    
    # Check if the Exchange setup executable exists
    if ($(Get-Command Exsetup.exe -ErrorAction SilentlyContinue | ForEach-Object { $_.FileVersionInfo })) {
        Write-Host -Object "[Error] The Microsoft Exchange command 'Exsetup.exe' was found. Upgrading PowerShell will break Exchange. Upgrade Aborted."
        exit 1
    }

    # Check for the presence of Exchange registry keys
    if ((Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\*\Setup" -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] A registry key for Microsoft Exchange was found. Upgrading PowerShell will break exchange. Upgrade aborted."
        Write-Host -Object "### Found Registry Keys ###"

        # List registry paths
        (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\*\Setup" -ErrorAction SilentlyContinue) | Select-Object -ExpandProperty PSPath | ForEach-Object {
            $_ -replace 'Microsoft\.PowerShell\.Core\\'
        } | Write-Host

        exit 1
    }

    # Try to detect the current PowerShell version
    try {
        $ErrorActionPreference = "Stop"
        [decimal]$PowerShellVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Unable to detect the PowerShell version."
        exit 1
    }
    finally {
        $ErrorActionPreference = "Continue"
    }

    # Ensure the PowerShell version was detected
    if (!$PowerShellVersion) {
        Write-Host -Object "[Error] Unable to detect the PowerShell version."
        exit 1
    }

    # If PowerShell 5.1 or later is already installed, abort the upgrade
    if ($PowerShellVersion -ge 5.1) {
        Write-Host -Object "[Error] The device is currently running PowerShell '$PowerShellVersion'. This script is designed to upgrade PowerShell to 5.1."
        Write-Host -Object "[Error] The device is already running either the targeted version or a newer version of PowerShell."
        exit 1
    }

    # Determine the required KB update based on the Windows build version
    switch ([System.Environment]::OSVersion.Version.Build) {
        { $_ -lt 7600 } {
            Write-Host -Object "[Error] A device with a build number of '$([System.Environment]::OSVersion.Version.Build)' is not compatible with PowerShell 5.1."
            Write-Host -Object "[Error] The device must be running at least Windows Server 2008 R2 Service Pack 1 or Windows 7 Service Pack 1."
            Write-Host -Object "[Error] https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf-overview"
            exit 1
        }
        { $_ -ge 7600 -and $_ -lt 9200 } { $RequiredKB = "KB3191566" }
        { $_ -ge 9200 -and $_ -lt 9600 } { $RequiredKB = "KB3191565" }
        { $_ -ge 9600 } { $RequiredKB = "KB3191564" }
        default {
            Write-Host -Object "[Error] A device with a build number of '$([System.Environment]::OSVersion.Version.Build)' should already include PowerShell 5.1"
            Write-Host -Object "[Error] You may need to reinstall or perform some other manual repair of Windows."
            Write-Host -Object "[Error] https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf-overview"
            exit 1
        }
    }

    # Check if the required KB update is already installed
    if (Get-HotFix -Id $RequiredKB -ErrorAction SilentlyContinue) {
        Write-Host -Object "[Error] This device already has PowerShell 5.1 installed. You may need to reboot the device."
        exit 1
    }

    # Define a custom Expand-Archive function if it doesn't already exist
    if (!$(Get-Command -Name "Expand-Archive" -ErrorAction SilentlyContinue).Count) {
        function Expand-Archive {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $True)]
                [String]$Path,
                [Parameter()]
                [String]$DestinationPath
            )

            # Verify that the specified ZIP file exists
            if (!(Test-Path -Path $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
                throw (New-Object System.IO.FileNotFoundException("The specified ZIP file could not be found at '$Path'."))
            }

            # Check the file extension to ensure it's a ZIP file
            try {
                $Extension = Get-Item -Path $Path -ErrorAction Stop | Select-Object -ExpandProperty Extension -ErrorAction SilentlyContinue
                $ValidExtensions = ".zip"
                if ($ValidExtensions -notcontains $Extension) {
                    throw (New-Object System.IO.InvalidDataException("The file extension '$Extension' is not supported. Only .zip files are allowed.")) 
                }
            }
            catch {
                throw $_
            }

            # Define default destination path if not provided
            if (!(Test-Path -Path $DestinationPath -ErrorAction SilentlyContinue)) {
                $DestinationName = Split-Path -Path $Path -Leaf
                $DestinationPath = ".\$($DestinationName -replace "$Extension")"
            }

            # Check if the destination path exists
            if (!(Test-Path -Path $DestinationPath -PathType Container -ErrorAction SilentlyContinue)) {
                (New-Object System.IO.IOException("[Error] The destination directory does not exist!"))
            }

            # Extract the ZIP file
            try {
                $Shell = New-Object -ComObject Shell.Application
                $Zip = $Shell.Namespace($Path)
                $Destination = $Shell.Namespace($DestinationPath)

                if (!$Zip -and !$Destination) {
                    throw (New-Object System.IO.IOException("Unable to extract the ZIP file. Ensure that the file is valid and not corrupted."))
                }

                $Destination.CopyHere($Zip.Items(), 16)
            }
            catch {
                throw $_
            }
        }
    }

    # Define a custom Get-FileHash function if it doesn't already exist
    if (!$(Get-Command -Name "Get-FileHash" -ErrorAction SilentlyContinue).Count) {
        function Get-FileHash {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [string]$Path,
                [Parameter(Mandatory = $false)]
                [ValidateSet("SHA1", "SHA256", "SHA384", "SHA512", "MD5")]
                [string]$Algorithm = "SHA256"
            )

            # Verify that the specified file exists
            if (!(Test-Path -Path $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
                throw (New-Object System.IO.FileNotFoundException("The specified file could not be found at '$Path'."))
            }

            # Compute the file hash using the specified algorithm
            try {
                $HashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
                $Hash = [System.BitConverter]::ToString($hashAlgorithm.ComputeHash([System.IO.File]::ReadAllBytes($Path)))
                New-Object -TypeName PSObject -Property @{
                    Algorithm = $Algorithm
                    Path      = $Path
                    Hash      = $Hash.Replace('-', '')
                }
            }
            catch {
                throw $_
            }
        }
    }

    # Utility function for downloading files.
    function Invoke-Download {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True)]
            [String]$URL,
            [Parameter(Mandatory = $True)]
            [String]$Path,
            [Parameter()]
            [int]$Attempts = 3,
            [Parameter()]
            [Switch]$SkipSleep,
            [Parameter()]
            [Switch]$Overwrite
        )

        # Determine the supported TLS versions and set the appropriate security protocol
        # Prefer Tls13 and Tls12 if both are available, otherwise just Tls12, or warn if unsupported.
        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Warn the user if TLS 1.2 and 1.3 are not supported, which may cause the download to fail
            Write-Host -Object "[Warning] TLS 1.2 and/or TLS 1.3 are not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Host -Object "[Warning] PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        # Trim whitespace from the URL and Path parameters.
        if ($URL) { $URL = $URL.Trim() }
        if ($Path) { $Path = $Path.Trim() }

        # Throw an error if no URL or Path was provided.
        if (!$URL) { throw (New-Object System.ArgumentNullException("You must provide a URL.")) }
        if (!$Path) { throw (New-Object System.ArgumentNullException("You must provide a file path.")) }

        # Display the URL being used for the download.
        Write-Host -Object "URL '$URL' was given."

        # If the URL doesn't start with http or https, prepend https.
        if ($URL -notmatch "^http") {
            $URL = "https://$URL"
            Write-Host -Object "[Warning] The URL given is missing http(s). The URL has been modified to the following '$URL'."
        }

        # Validate that the URL does not contain invalid characters according to RFC3986.
        if ($URL -match "[^A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]") {
            throw (New-Object System.IO.InvalidDataException("Error] The url '$URL' contains an invalid character according to RFC3986."))
        }

        # Check if the path contains invalid characters or reserved characters after the drive letter.
        if ($Path -and ($Path -match '[/*?"<>|]' -or $Path.SubString(3) -match "[:]")) {
            throw (New-Object System.IO.InvalidDataException("[Error] The file path specified '$Path' contains one of the following invalid characters: '/*?`"<>|:'"))
        }

        # Check each folder in the path to ensure it isn't a reserved name (CON, PRN, AUX, etc.).
        $Path -split '\\' | ForEach-Object {
            $Folder = ($_).Trim()
            if ($Folder -match '^CON$' -or $Folder -match '^PRN$' -or $Folder -match '^AUX$' -or $Folder -match '^NUL$' -or $Folder -match '^LPT\d$' -or $Folder -match '^COM\d+$') {
                throw (New-Object System.IO.InvalidDataException("[Error] An invalid folder name was given in '$Path'. The following folder names are reserved: CON, PRN, AUX, NUL, COM1-9, LPT1-9"))
            }
        }

        # Temporarily disable progress reporting to speed up script performance
        $PreviousProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        # If no filename is included in the path (no extension), try to determine it from Content-Disposition.
        if (($Path | Split-Path -Leaf) -notmatch "[.]") {

            Write-Host -Object "No filename provided in '$Path'. Checking the URL for a suitable filename."

            $ProposedFilename = Split-Path $URL -Leaf

            # Verify that the proposed filename doesn't contain invalid characters.
            if ($ProposedFilename -and $ProposedFilename -notmatch "[^A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]" -and $ProposedFilename -match "[.]") {
                $Filename = $ProposedFilename
            }

            # If running on older PowerShell versions without Invoke-WebRequest require a filename.
            if ($PSVersionTable.PSVersion.Major -lt 4) {
                # Restore the original progress preference setting
                $ProgressPreference = $PreviousProgressPreference

                throw (New-Object System.NotSupportedException("You must provide a filename for systems not running PowerShell 4 or higher."))
            }

            if (!$Filename) {
                Write-Host -Object "No filename was discovered in the URL. Attempting to discover the filename via the Content-Disposition header."
                $Request = 1

                # Make multiple attempts (as defined by $Attempts) to retrieve the Content-Disposition header.
                While ($Request -le $Attempts) {
                    # If SkipSleep is not set, wait for a random time between 3 and 15 seconds before each attempt
                    if (!($SkipSleep)) {
                        $SleepTime = Get-Random -Minimum 3 -Maximum 15
                        Write-Host -Object "Waiting for $SleepTime seconds."
                        Start-Sleep -Seconds $SleepTime
                    }
    
                    if ($Request -ne 1) { Write-Host "" }
                    Write-Host -Object "Attempt $Request"

                    # Perform a HEAD request to get headers only.
                    # If the HEAD request fails, print a warning.
                    try {
                        $HeaderRequest = Invoke-WebRequest -Uri $URL -Method "HEAD" -MaximumRedirection 10 -UseBasicParsing -ErrorAction Stop
                    }
                    catch {
                        Write-Host -Object "[Warning] $($_.Exception.Message)"
                        Write-Host -Object "[Warning] The header request failed."
                    }

                    # Check if the Content-Disposition header is present.
                    # If present, parse it to extract the filename.
                    if (!$HeaderRequest.Headers."Content-Disposition") {
                        Write-Host -Object "[Warning] The web server did not provide a Content-Disposition header."
                    }
                    else {
                        $Content = [System.Net.Mime.ContentDisposition]::new($HeaderRequest.Headers."Content-Disposition")
                        $Filename = $Content.FileName
                    }

                    # If a filename was found, break out of the loop.
                    if ($Filename) {
                        $Request = $Attempts
                    }

                    $Request++
                }
            }

            # If a filename is still not found, throw an error.
            if ($Filename) {
                $Path = "$Path\$Filename"
            }
            else {
                # Restore the original progress preference setting
                $ProgressPreference = $PreviousProgressPreference

                throw (New-Object System.IO.FileNotFoundException("Unable to find a suitable filename from the URL."))
            }
        }

        # If the file already exists at the specified path, restore the progress setting and throw an error.
        if ((Test-Path -Path $Path -ErrorAction SilentlyContinue) -and !$Overwrite) {
            # Restore the original progress preference setting
            $ProgressPreference = $PreviousProgressPreference

            throw (New-Object System.IO.IOException("A file already exists at the path '$Path'."))
        }

        # Ensure that the destination folder exists, if not, try to create it.
        $DestinationFolder = $Path | Split-Path
        if (!(Test-Path -Path $DestinationFolder -ErrorAction SilentlyContinue)) {
            try {
                Write-Host -Object "Attempting to create the folder '$DestinationFolder' as it does not exist."
                New-Item -Path $DestinationFolder -ItemType "directory" -ErrorAction Stop | Out-Null
                Write-Host -Object "Successfully created the folder."
            }
            catch {
                # Restore the original progress preference setting
                $ProgressPreference = $PreviousProgressPreference

                throw $_
            }
        }

        Write-Host -Object "Downloading the file..."

        $DigiCertG2IsPresent = Get-Item -Path Cert:\LocalMachine\Root\DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 -ErrorAction SilentlyContinue
        if ([System.Environment]::OSVersion.Version.Build -lt 9600 -and !$DigiCertG2IsPresent) {
            try {
                Write-Host -Object "`n[Warning] A legacy system with the build number '$([System.Environment]::OSVersion.Version.Build)' was detected with an outdated trusted root certificate store."
                Write-Host -Object "[Warning] Certificate validation errors will be temporarily ignored.`n"

                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
            catch {
                Write-Host -Object "[Warning] $($_.Exception.Message)"
                Write-Host -Object "[Warning] An error occurred while temporarily disabling certificate validation."
            }
        }

        # Initialize the download attempt counter.
        $DownloadAttempt = 1
        While ($DownloadAttempt -le $Attempts) {
            # If SkipSleep is not set, wait for a random time between 3 and 15 seconds before each attempt
            if (!($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host -Object "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
    
            # Provide a visual break between attempts
            if ($DownloadAttempt -ne 1) { Write-Host "" }
            Write-Host -Object "Download Attempt $DownloadAttempt"

            try {
                if ($PSVersionTable.PSVersion.Major -lt 4) {
                    # For older versions of PowerShell, use WebClient to download the file
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($URL, $Path)
                }
                else {
                    # For PowerShell 4.0 and above, use Invoke-WebRequest with specified arguments
                    $WebRequestArgs = @{
                        Uri                = $URL
                        OutFile            = $Path
                        MaximumRedirection = 10
                        UseBasicParsing    = $true
                    }

                    Invoke-WebRequest @WebRequestArgs
                }

                # Verify if the file was successfully downloaded
                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch {
                # Handle any errors that occur during the download attempt
                Write-Host -Object "[Warning] An error has occurred while downloading!"
                Write-Host -Object "[Warning] $($_.Exception.Message)"

                # If the file partially downloaded, delete it to avoid corruption
                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            # If the file was successfully downloaded, exit the loop
            if ($File) {
                $DownloadAttempt = $Attempts
            }
            else {
                # Warn the user if the download attempt failed
                Write-Host -Object "[Warning] File failed to download.`n"
            }

            # Increment the attempt counter
            $DownloadAttempt++
        }

        # Restore the original progress preference setting
        $ProgressPreference = $PreviousProgressPreference
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $Null

        # Final check: if the file still doesn't exist, report an error and exit
        if (!(Test-Path $Path)) {
            throw (New-Object System.IO.FileNotFoundException("[Error] Failed to download file. Please verify the URL of '$URL'."))
        }
        else {
            # If the download succeeded, return the path to the downloaded file
            return $Path
        }
    }

    # Function to install an application using a specified installer and arguments
    function Install-Application {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [String]$InstallerPath,
            [Parameter(Mandatory = $True)]
            [String[]]$Arguments
        )

        # Variable to store the installation status (0 = success, 1 = failure)
        $InstallerCode = 0

        # Verify that the specified installer file exists
        if (!(Test-Path -Path $InstallerPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            throw (New-Object System.IO.FileNotFoundException("[Error] The specified installer file could not be found at '$InstallerPath'."))
        }

        # Define log file paths for standard output and standard error
        $StandardOutLog = "$env:Temp\$(Get-Random)-InstallStdOut.log"
        $StandardErrorLog = "$env:Temp\$(Get-Random)-InstallStdErr.log"

        # Attempt to start the installation process
        try {
            $InstallProcess = Start-Process -ArgumentList $Arguments -FilePath $InstallerPath -RedirectStandardOutput $StandardOutLog -RedirectStandardError $StandardErrorLog -NoNewWindow -Wait -PassThru -ErrorAction Stop
        }
        catch {
            # Rethrow the caught exception
            throw $_
        }

        # Check if the installation process completed with a reboot-required exit code (3010)
        if ($InstallProcess.ExitCode -eq 3010) {
            Write-Host -Object "`n[Warning] Installation completed, but a reboot is required."
        }

        # Define acceptable exit codes (0 = success, 3010 = success but requires reboot)
        $DesiredExitCodes = 0, 3010

        # Check if the installation completed successfully
        if ($DesiredExitCodes -notcontains $InstallProcess.ExitCode) {
            Write-Host -Object "[Error] The exit code '$($InstallProcess.ExitCode)' does not indicate success."
            $InstallerCode = 1
        }

        # Check if the standard output log exists and process it
        if (Test-Path -Path $StandardOutLog -ErrorAction SilentlyContinue) {
            try {
                # Read and process the log file, trimming empty lines
                $StandardOutput = Get-Content -Path $StandardOutLog -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 25
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to retrieve the standard output log from '$StandardOutLog'."
                $InstallerCode = 1
            }

            # Remove the standard output log file if no errors occurred
            if ($InstallerCode -ne 1) {
                try {
                    Remove-Item -Path $StandardOutLog -ErrorAction Stop
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to remove the standard output log file at '$StandardOutLog'."
                    $InstallerCode = 1
                }
            }

            # Display the captured standard output logs (if any)
            if ($StandardOutput) {
                $StandardOutput | Write-Host
            }

            # Indicate if only a portion of the log was displayed
            if ($StandardOutput.Count -eq 25) {
                Write-Host -Object "..."
            }
        }

        # Check if the standard error log exists and process it
        if (Test-Path -Path $StandardErrorLog -ErrorAction SilentlyContinue) {
            try {
                Write-Host -Object ""

                # Read and process the error log file, trimming empty lines
                $StandardErr = Get-Content -Path $StandardErrorLog -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to retrieve the standard error log from '$StandardErrorLog'."
                $InstallerCode = 1
            }

            # Attempt to remove the standard error log file
            try {
                Remove-Item -Path $StandardErrorLog -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to remove the standard error log file at '$StandardErrorLog'."
                $InstallerCode = 1
            }

            # Display the captured standard error logs (if any)
            if ($StandardErr) {
                $StandardErr | ForEach-Object {
                    Write-Host -Object "[Error] $_"
                }

                $InstallerCode = 1
            }
        }

        # Return the final installer exit code (0 = success, 1 = failure)
        return $InstallerCode
    }

    function Test-IsServer {
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
            Write-Host -Object "[Error] Unable to validate whether or not this device is a server."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        # Check if the ProductType is "2", which indicates that the system is a domain controller or is a server
        if ($OS.ProductType -eq "2" -or $OS.ProductType -eq "3") {
            return $true
        }
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        # 544 is the value for the Built In Administrators role
        # Reference: https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsbuiltinrole?view=netframework-4.8.1
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]'544')
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

    # Check if the system is a 32-bit server, as PowerShell 5.1 is not supported on such systems
    if (!($env:PROCESSOR_ARCHITECTURE -eq "AMD64") -and (Test-IsServer)) {
        Write-Host -Object "[Error] PowerShell 5.1 is not available on 32-bit server operating systems."
        Write-Host -Object "[Error] https://www.microsoft.com/en-us/download/details.aspx?id=54616"
        exit 1
    }

    # Check if the operating system is at least Windows 7 SP1 or Server 2008 R2 SP1 (Build 7601+)
    if ([System.Environment]::OSVersion.Version.Build -lt 7601) {
        Write-Host -Object "[Error] The build number '$([System.Environment]::OSVersion.Version.Build)' indicates Service Pack 1 is not installed."
        Write-Host -Object "[Error] PowerShell 5.1 requires at least Service Pack 1 (KB976932) to be installed for either Windows 7 or Server 2008 R2. This requires manual intervention."
        Write-Host -Object "[Error] https://learn.microsoft.com/en-us/previous-versions/powershell/scripting/windows-powershell/wmf/setup/install-configure#wmf-51-prerequisites-for-windows-server-2008-r2-sp1-and-windows-7-sp1"
        Write-Host -Object "[Error] https://www.catalog.update.microsoft.com/Search.aspx?q=KB976932"
        exit 1
    }
    
    # Check if the system is running Windows 8 (which is unsupported for PowerShell 5.1)
    if ([System.Environment]::OSVersion.Version.Build -ge 9200 -and [System.Environment]::OSVersion.Version.Build -lt 9600 -and !(Test-IsServer)) {
        Write-Host -Object "[Error] PowerShell 5.1 is not available on Windows 8. It is only available on Windows 8.1."
        Write-Host -Object "[Error] https://learn.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf-overview#wmf-availability-across-windows-operating-systems"
        exit 1
    }

    # Check if .NET Framework 4.5.2 or later is installed
    Write-Host -Object "Checking if .NET Framework 4.5.2 is installed."

    try {
        # Retrieve .NET Framework installation status and version from the registry
        $DotNetIsInstalled = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Install -ErrorAction SilentlyContinue).install
        $DotNetRelease = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Release -ErrorAction SilentlyContinue).release
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to verify that .NET Framework 4.5.2 or later is installed."
        exit 1
    }

    # If .NET Framework 4.5.2 or later is installed, display a confirmation message
    if ($DotNetIsInstalled -eq 1 -and $DotNetRelease -ge 379893) {
        Write-Host -Object ".NET Framework 4.5.2 or higher is installed.`n"
    }

    # If .NET Framework 4.5.2 or later is not installed, proceed with installation
    if ($DotNetIsInstalled -ne 1 -or $DotNetRelease -lt 379893) {
        Write-Host -Object ".NET Framework 4.5.2 or higher is not installed. .NET Framework 4.5.2 or higher is required."
        $DotNetInstallPath = "$env:TEMP\NDP452-KB2901907-x86-x64-AllOS-ENU.exe"

        # Check if a previous download of the .NET Framework 4.5.2 installer file exists
        if (Test-Path -Path $DotNetInstallPath -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-Host -Object "A previous download was detected."

            # Verify the integrity of the previously downloaded file using SHA256 hash comparison
            try {
                Write-Host -Object "Verifying the .NET Framework 4.5.2 installer at '$DotNetInstallPath'."
                $DotNetFileHash = Get-FileHash -Path $DotNetInstallPath -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to verify the file hash for '$DotNetInstallPath'."
                exit 1
            }

            # Compare the computed hash with the expected hash to ensure file integrity
            if ($DotNetFileHash -ne $ExpectedDotNetSHA256) {
                Write-Host -Object "The SHA256 file hash of '$DotNetFileHash' does not match '$ExpectedDotNetSHA256'."
                Write-Host -Object "Removing the existing file and retrying the download."
                
                # Remove the corrupt or mismatched file before downloading a new one
                try {
                    Remove-Item -Path "$DotNetInstallPath" -ErrorAction Stop
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to remove the existing installer file at '$DotNetInstallPath'."
                    exit 1
                }
            }
        }

        # If no valid installer file exists, proceed with downloading .NET Framework 4.5.2
        if (!(Test-Path -Path $DotNetInstallPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            # Download .NET Framework 4.5.2
            try {
                Write-Host -Object "Downloading .NET Framework 4.5.2."
                Invoke-Download -Path $DotNetInstallPath -Url $DotNetDownloadLink -ErrorAction Stop

                Write-Host -Object "Completed download of .NET Framework 4.5.2."
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to download .NET Framework 4.5.2, which is required for PowerShell 5.1."
                exit 1
            }

            # Verify the file integrity of the downloaded installer
            try {
                Write-Host -Object "Verifying .NET Framework 4.5.2 installer."
                $DotNetFileHash = Get-FileHash -Path $DotNetInstallPath -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to verify the file hash for '$DotNetInstallPath'."
                exit 1
            }

            # Compare the computed hash with the expected hash to ensure file integrity
            if ($DotNetFileHash -ne $ExpectedDotNetSHA256) {
                Write-Host -Object "[Error] The SHA256 file hash of '$DotNetFileHash' does not match '$ExpectedDotNetSHA256'. The file may have been tampered with, corrupted, or replaced."
                exit 1
            }
        }

        # Install .NET Framework 4.5.2
        try {
            Write-Host -Object "`nInstalling .NET Framework 4.5.2."
            $InstallDotNet = Install-Application -InstallerPath $DotNetInstallPath -Arguments ("/q", "/norestart") -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to install the prerequisite .NET Framework 4.5.2."
            exit 1
        }

        # Remove the downloaded installer after installation
        try {
            Remove-Item -Path $DotNetInstallPath -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove the downloaded installer at '$DotNetInstallPath'."
            $ExitCode = 1
        }

        # If the installation process failed, update the exit code
        if ($InstallDotNet -ne 0) {
            $ExitCode = $InstallDotNet
        }

        # Verify the installation of .NET Framework 4.5.2 again
        try {
            $DotNetIsInstalled = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Install -ErrorAction SilentlyContinue).install
            $DotNetRelease = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\' -Name Release -ErrorAction SilentlyContinue).release
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to verify that .NET Framework 4.5.2 or later is installed."
            exit 1
        }

        # Confirm successful installation
        if ($DotNetRelease -and $DotNetIsInstalled -eq 1 -and $InstallDotNet -eq 0) {
            Write-Host -Object ".NET Framework 4.5.2 or later is installed.`n"

        }
        else {
            Write-Host -Object "[Error] .NET Framework 4.5.2 failed to install and is required."
            exit 1
        }
    }

    # Display the current OS build number
    Write-Host -Object "The current build is '$([System.Environment]::OSVersion.Version.Build)'"

    # Check if the system is running Windows 7 or Windows Server 2008 (Build < 9200)
    if ([System.Environment]::OSVersion.Version.Build -lt 9200) {
        Write-Host -Object "Windows 7 or Windows Server 2008 has been detected."

        # Define folder path for Windows Management Framework (WMF) 5.1 installation files
        $WMF51Folder = "$env:TEMP\Win7AndW2K8R2-KB3191566"

        # Check system architecture and set appropriate download links and expected hashes
        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            $Win7AndW2K8R2WMF51Link = $Win7AndW2K8R2WMF5164Link
            $WMF51InstallPath = "$WMF51Folder\Win7AndW2K8R2-KB3191566-x64.msu"
            $ExpectedWin7AndW2K8R2WMF51SHA256 = $ExpectedWin7AndW2K8R2WMF5164SHA256
        }
        else {
            $Win7AndW2K8R2WMF51Link = $Win7WMF5132Link
            $WMF51InstallPath = "$WMF51Folder\Win7-KB3191566-x86.msu"
            $ExpectedWin7AndW2K8R2WMF51SHA256 = $ExpectedWin7WMF5132SHA256
        }
        $Win7AndW2K8R2WMF51Path = "$env:TEMP\Win7AndW2K8R2-KB3191566.zip"

        # Check if a previous download of the WMF 5.1 ZIP file exists
        if (Test-Path -Path $Win7AndW2K8R2WMF51Path -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-Host -Object "A previous download was detected."

            # Verify the integrity of the previously downloaded file using SHA256 hash comparison
            try {
                Write-Host -Object "Verifying the WMF 5.1 ZIP archive."
                $Win7AndW2K8R2WMF51Hash = Get-FileHash -Path $Win7AndW2K8R2WMF51Path -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] Failed to verify the file hash for '$Win7AndW2K8R2WMF51Path'."
                exit 1
            }

            # Compare the computed hash with the expected hash to ensure file integrity
            if ($Win7AndW2K8R2WMF51Hash -ne $ExpectedWin7AndW2K8R2WMF51SHA256) {
                Write-Host -Object "The SHA256 file hash of '$Win7AndW2K8R2WMF51Hash' does not match '$ExpectedWin7AndW2K8R2WMF51SHA256'."
                Write-Host -Object "Removing the existing file and retrying the download."

                # Remove the corrupt or mismatched file before downloading a new one
                try {
                    Remove-Item -Path "$Win7AndW2K8R2WMF51Path" -ErrorAction Stop
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to remove the existing installer file at '$Win7AndW2K8R2WMF51Path'."
                    exit 1
                }
            }
        }

        # If no valid ZIP file exists, proceed with downloading WMF 5.1
        if (!(Test-Path -Path $Win7AndW2K8R2WMF51Path -PathType Leaf -ErrorAction SilentlyContinue)) {
            # Attempt to download the WMF 5.1 installation package
            try {
                Write-Host -Object "Downloading Windows Management Framework (WMF) 5.1."

                Invoke-Download -Url $Win7AndW2K8R2WMF51Link -Path $Win7AndW2K8R2WMF51Path -ErrorAction Stop

            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to download WMF 5.1."
                exit 1
            }

            # Verify the downloaded file's integrity using SHA256 hash comparison
            try {
                Write-Host -Object "Verifying the WMF 5.1 ZIP archive."
                $Win7AndW2K8R2WMF51Hash = Get-FileHash -Path $Win7AndW2K8R2WMF51Path -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] Failed to verify the file hash for '$Win7AndW2K8R2WMF51Path'."
                exit 1
            }

            # Compare computed file hash with expected hash
            if ($Win7AndW2K8R2WMF51Hash -ne $ExpectedWin7AndW2K8R2WMF51SHA256) {
                Write-Host -Object "[Error] The SHA256 file hash of '$Win7AndW2K8R2WMF51Hash' does not match '$ExpectedWin7AndW2K8R2WMF51SHA256'. The file may have been tampered with, corrupted, or replaced."
                exit 1
            }
        }

        # Extract the downloaded ZIP archive
        try {
            Write-Host -Object "Extracting the archive at '$Win7AndW2K8R2WMF51Path'."

            # Remove existing installation folder if it exists
            if (Test-Path -Path $WMF51Folder -PathType Container -ErrorAction SilentlyContinue) {
                Remove-Item -Path $WMF51Folder -Force -Recurse -Confirm:$False -ErrorAction Stop
            }
            
            # Create a new folder for extracted files
            if (!(Test-Path -Path $WMF51Folder -PathType Container -ErrorAction SilentlyContinue)) {
                New-Item -Path $WMF51Folder -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            # Extract the archive
            Expand-Archive -Path $Win7AndW2K8R2WMF51Path -DestinationPath $WMF51Folder -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to extract the zip file."
            exit 1
        }

        # Ensure the installation package was extracted successfully
        if (!(Test-Path -Path $WMF51InstallPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            Write-Host -Object "[Error] Failed to extract the required zip file at '$Win7AndW2K8R2WMF51Path'."
            exit 1
        }

        # Remove the downloaded ZIP file after extraction
        try {
            Remove-Item -Path $Win7AndW2K8R2WMF51Path -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove the downloaded ZIP archive at '$Win7AndW2K8R2WMF51Path'."
            $ExitCode = 1
        }
    }

    # Check if the system is running Windows Server 2012 (Build 9200-9600)
    if ([System.Environment]::OSVersion.Version.Build -ge 9200 -and [System.Environment]::OSVersion.Version.Build -lt 9600) {
        Write-Host -Object "Windows Server 2012 has been detected."
        $Win2012WMF51Path = "$env:TEMP\W2K12-KB3191565-x64.msu"

        # Check if a previous download of the WMF 5.1 installer file exists
        if (Test-Path -Path $Win2012WMF51Path -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-Host -Object "A previous download was detected."

            # Verify the integrity of the previously downloaded file using SHA256 hash comparison
            try {
                Write-Host -Object "Verifying the WMF 5.1 installer at '$Win2012WMF51Path'."
                $Win2012WMF51Hash = Get-FileHash -Path $Win2012WMF51Path -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] Failed to verify the file hash for '$Win2012WMF51Path'."
                exit 1
            }

            # Compare the computed hash with the expected hash to ensure file integrity
            if ($Win2012WMF51Hash -ne $ExpectedWin2012SHA256) {
                Write-Host -Object "The SHA256 file hash of '$Win2012WMF51Hash' does not match '$ExpectedWin2012SHA256'."
                Write-Host -Object "Removing the existing file and retrying the download."

                # Remove the corrupt or mismatched file before downloading a new one
                try {
                    Remove-Item -Path "$Win2012WMF51Path" -ErrorAction Stop
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to remove the existing installer file at '$Win2012WMF51Path'."
                    exit 1
                }
            }
        }

        # If no valid installer file exists, proceed with downloading WMF 5.1
        if (!(Test-Path -Path $Win2012WMF51Path -PathType Leaf -ErrorAction SilentlyContinue)) {
            # Attempt to download WMF 5.1 installer for Windows Server 2012
            try {
                Write-Host -Object "Downloading Windows Management Framework (WMF) 5.1."

                Invoke-Download -Url $Win2012WMF51Link -Path $Win2012WMF51Path -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to download WMF 5.1."
                exit 1
            }

            # Verify file integrity
            try {
                Write-Host -Object "Verifying the WMF 5.1 installer at '$Win2012WMF51Path'."
                $Win2012WMF51Hash = Get-FileHash -Path $Win2012WMF51Path -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] Failed to verify the file hash for '$Win2012WMF51Path'."
                exit 1
            }

            # Compare hash with expected hash
            if ($Win2012WMF51Hash -ne $ExpectedWin2012SHA256) {
                Write-Host -Object "[Error] The SHA256 file hash of '$Win2012WMF51Hash' does not match '$ExpectedWin2012SHA256'. The file may have been tampered with, corrupted, or replaced."
                exit 1
            }
        }

        $WMF51InstallPath = $Win2012WMF51Path
    }

    # Check if the system is running Windows 8.1 or Windows Server 2012 R2 (Build 9600+)
    if ([System.Environment]::OSVersion.Version.Build -ge 9600) {
        Write-Host -Object "Windows 8.1 or Windows Server 2012 R2 has been detected."

        # Set appropriate download links and expected hashes based on system architecture
        if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
            $Win81AndW2K12R2WMF51Link = $Win81AndW2K12R2WMF5164Link
            $Win81AndW2K12R2WMF51Path = "$env:TEMP\Win8.1AndW2K12R2-KB3191564-x64.msu"
            $ExpectedWin81AndW2K12R2WMF51SHA256 = $ExpectedWin81AndW2K12R264HA256
        }
        else {
            $Win81AndW2K12R2WMF51Link = $Win81WMF5132Link
            $Win81AndW2K12R2WMF51Path = "$env:TEMP\Win8.1-KB3191564-x86.msu"
            $ExpectedWin81AndW2K12R2WMF51SHA256 = $ExpectedWin81WMF5132SHA256
        }

        if (Test-Path -Path $Win81AndW2K12R2WMF51Path -PathType Leaf -ErrorAction SilentlyContinue) {
            Write-Host -Object "A previous download was detected."

            # Verify the integrity of the previously downloaded file using SHA256 hash comparison
            try {
                Write-Host -Object "Verifying the WMF 5.1 file at '$Win81AndW2K12R2WMF51Path'."
                $Win81AndW2K12R2WMF51Hash = Get-FileHash -Path $Win81AndW2K12R2WMF51Path -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] Failed to verify the file hash for '$Win81AndW2K12R2WMF51Path'."
                exit 1
            }

            # Compare the computed hash with the expected hash to ensure file integrity
            if ($Win81AndW2K12R2WMF51Hash -ne $ExpectedWin81AndW2K12R2WMF51SHA256) {
                Write-Host -Object "The SHA256 file hash of '$Win81AndW2K12R2WMF51Hash' does not match '$ExpectedWin81AndW2K12R2WMF51SHA256'."
                Write-Host -Object "Removing the existing file and retrying the download."

                # Remove the corrupt or mismatched file before downloading a new one
                try {
                    Remove-Item -Path "$Win81AndW2K12R2WMF51Path" -ErrorAction Stop
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to remove the existing installer file at '$Win81AndW2K12R2WMF51Path'."
                    exit 1
                }
            }
        }

        # If no valid installer file exists, proceed with downloading WMF 5.1
        if (!(Test-Path -Path $Win81AndW2K12R2WMF51Path -PathType Leaf -ErrorAction SilentlyContinue)) {
            # Attempt to download Windows Management Framework (WMF) 5.1
            try {
                Write-Host -Object "Downloading Windows Management Framework (WMF) 5.1."
                Invoke-Download -Url $Win81AndW2K12R2WMF51Link -Path $Win81AndW2K12R2WMF51Path -ErrorAction Stop

            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to download WMF 5.1."
                exit 1
            }

            # Verify the integrity of the downloaded file using SHA256 hash
            try {
                Write-Host -Object "Verifying the WMF 5.1 file at '$Win81AndW2K12R2WMF51Path'."
                $Win81AndW2K12R2WMF51Hash = Get-FileHash -Path $Win81AndW2K12R2WMF51Path -Algorithm "SHA256" -ErrorAction Stop | Select-Object -ExpandProperty Hash -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host -Object "[Error] Failed to verify the file hash for '$Win81AndW2K12R2WMF51Path'."
                exit 1
            }

            # Compare computed hash with the expected hash to ensure file integrity
            if ($Win81AndW2K12R2WMF51Hash -ne $ExpectedWin81AndW2K12R2WMF51SHA256) {
                Write-Host -Object "[Error] The SHA256 file hash of '$Win81AndW2K12R2WMF51Hash' does not match '$ExpectedWin81AndW2K12R2WMF51SHA256'. The file may have been tampered with, corrupted, or replaced."
                exit 1
            }
        }

        # Set the installation path for WMF 5.1
        $WMF51InstallPath = $Win81AndW2K12R2WMF51Path
    }

    # Install WMF 5.1 using the Windows Update Standalone Installer (wusa.exe)
    try {
        $InstallLog = "$env:Temp\$(Get-Random)-WMF51Installation.log.etl"
        
        Write-Host -Object "`nInstalling Windows Management Framework 5.1 (PowerShell 5.1)"
        $InstallWMF51 = Install-Application -InstallerPath "$env:SystemRoot\System32\wusa.exe" -Arguments ("$WMF51InstallPath", "/quiet", "/norestart", "/log:`"$InstallLog`"") -ErrorAction Stop
        
        Write-Host -Object "A log file is saved at '$InstallLog'."
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to install WMF 5.1."
        exit 1
    }

    # Remove the downloaded installer after installation
    try {
        Remove-Item -Path $WMF51InstallPath -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to remove the downloaded installer at '$WMF51InstallPath'."
        $ExitCode = 1
    }

    # Remove the extracted installation folder, if applicable
    if ($WMF51Folder) {
        try {
            Remove-Item -Path $WMF51Folder -Recurse -Force -Confirm:$False -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to remove leftover files at '$WMF51Folder'."
            $ExitCode = 1
        }
    }

    # If installation failed, set the exit code accordingly
    if ($InstallWMF51 -ne 0) {
        $ExitCode = $InstallWMF51
    }

    # Determine the required KB update for PowerShell 5.1 based on the OS build
    switch ([System.Environment]::OSVersion.Version.Build) {
        { $_ -lt 9200 } { $RequiredKB = "KB3191566" }
        { $_ -ge 9200 -and $_ -lt 9600 } { $RequiredKB = "KB3191565" }
        { $_ -ge 9600 } { $RequiredKB = "KB3191564" }
    }

    # Verify if the required KB update is installed
    try {
        $InstalledKB = Get-HotFix -Id $RequiredKB -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] PowerShell 5.1 was not detected on this device."
        exit 1
    }

    # Confirm successful installation
    if ($InstalledKB) {
        Write-Host -Object "`nPowerShell 5.1 was successfully installed."
    }
    else {
        Write-Host -Object "`n[Error] PowerShell 5.1 was not detected on this device."
        exit 1
    }

    # If a restart is required, schedule a system reboot
    if ($ForceRestart) {
        $RestartTime = "$((Get-Date).ToShortDateString()) $((Get-Date).AddMinutes(1).ToShortTimeString())"
        Write-Host -Object "Scheduling a system restart for '$RestartTime' as requested."

        try {
            Start-Process -FilePath "$env:SystemRoot\System32\shutdown.exe" -ArgumentList "/r /t 60" -Wait -NoNewWindow -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to schedule restart."
            exit 1
        }
    }
    else {
        Write-Host -Object "[Warning] A restart is usually required after upgrading PowerShell."
    }

    exit $ExitCode
}
end {
    
    
    
}
