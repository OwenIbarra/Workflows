# This script allows you to install, uninstall, or upgrade an application using Chocolatey. If Chocolatey is not installed or is outdated, options are available to install or upgrade it before proceeding with the application action.
#Requires -Version 4.0

<#
.SYNOPSIS
    This script allows you to install, uninstall, or upgrade an application using Chocolatey. If Chocolatey is not installed or is outdated, options are available to install or upgrade it before proceeding with the application action.
.DESCRIPTION
    This script allows you to install, uninstall, or upgrade an application using Chocolatey. If Chocolatey is not installed or is outdated, options are available to install or upgrade it before proceeding with the application action.
.EXAMPLE
    -Action "Install" -Name "vlc" -InstallChocolateyIfMissing -SkipSleep
    Chocolatey is not installed.
    Downloading Chocolatey's install script and installing.
    URL 'https://community.chocolatey.org/install.ps1' was given.
    Downloading the file...
    Download Attempt 1
    Forcing web requests to allow TLS v1.2 (Required for requests to Chocolatey.org)
    Getting latest version of the Chocolatey package for download.
    Not using proxy.
    Getting Chocolatey from https://community.chocolatey.org/api/v2/package/chocolatey/2.3.0.
    Downloading https://community.chocolatey.org/api/v2/package/chocolatey/2.3.0 to C:\Windows\TEMP\chocolatey\chocoInstall\chocolatey.zip
    Not using proxy.
    Extracting C:\Windows\TEMP\chocolatey\chocoInstall\chocolatey.zip to C:\Windows\TEMP\chocolatey\chocoInstall
    Downloading 7-Zip commandline tool prior to extraction.
    Downloading https://community.chocolatey.org/7za.exe to C:\Windows\TEMP\chocolatey\chocoInstall\7za.exe
    Not using proxy.
    Installing Chocolatey on the local machine
    WARNING: It's very likely you will need to close and reopen your shell 
    before you can use choco.
    PATH environment variable does not have C:\ProgramData\chocolatey\bin in it. Adding...
    WARNING: Not setting tab completion: Current user is SYSTEM user.
    Ensuring Chocolatey commands are on the path
    Ensuring chocolatey.nupkg is in the lib folder
    Creating ChocolateyInstall as an environment variable (targeting 'Machine') 
    Setting ChocolateyInstall to 'C:\ProgramData\chocolatey'
    Restricting write permissions to Administrators
    We are setting up the Chocolatey package repository.
    The packages themselves go to 'C:\ProgramData\chocolatey\lib'
    (i.e. C:\ProgramData\chocolatey\lib\yourPackageName).
    A shim file for the command line goes to 'C:\ProgramData\chocolatey\bin'
    and points to an executable in 'C:\ProgramData\chocolatey\lib\yourPackageName'.

    Creating Chocolatey CLI folders if they do not already exist.

    chocolatey.nupkg file not installed in lib.
    Attempting to locate it from bootstrapper.
    Chocolatey CLI (choco.exe) is now ready.
    You can call choco from anywhere, command line or powershell by typing choco.
    Run choco /? for a list of functions.
    You may need to shut down and restart powershell and/or consoles
    first prior to using choco.
    Installing the following packages:
    vlc
    By installing, you accept licenses for the packages.
    Downloading package from source 'https://community.chocolatey.org/api/v2/'

    chocolatey-compatibility.extension v1.0.0 [Approved]
    chocolatey-compatibility.extension package files install completed. Performing other installation steps.
    Installed/updated chocolatey-compatibility extensions.
    The install of chocolatey-compatibility.extension was successful.
    Deployed to 'C:\ProgramData\chocolatey\extensions\chocolatey-compatibility'
    Downloading package from source 'https://community.chocolatey.org/api/v2/'

    chocolatey-core.extension v1.4.0 [Approved]
    chocolatey-core.extension package files install completed. Performing other installation steps.
    Installed/updated chocolatey-core extensions.
    The install of chocolatey-core.extension was successful.
    Deployed to 'C:\ProgramData\chocolatey\extensions\chocolatey-core'
    Downloading package from source 'https://community.chocolatey.org/api/v2/'

    vlc.install v3.0.21 [Approved]
    vlc.install package files install completed. Performing other installation steps.
    Installing 64-bit vlc.install...
    vlc.install has been installed.
    WARNING: No registry key found based on  'vlc.install'
    WARNING: Can't find vlc.install install location
    vlc.install may be able to be automatically uninstalled.
    The install of vlc.install was successful.
    Deployed to 'C:\Program Files\VideoLAN\VLC'
    Downloading package from source 'https://community.chocolatey.org/api/v2/'

    vlc v3.0.21 [Approved]
    vlc package files install completed. Performing other installation steps.
    The install of vlc was successful.
    Deployed to 'C:\ProgramData\chocolatey\lib\vlc'

    Chocolatey installed 4/4 packages. 
    See the log for details (C:\ProgramData\chocolatey\logs\chocolatey.log).
    Exit Code: 0
    Successfully completed the action 'Install' for package 'vlc'.

PARAMETER: -Action "ReplaceMeWithValidAction"
    Valid actions are 'Install', 'Upgrade', or 'Uninstall' for your desired package.

PARAMETER: -Name "NameOfApplication"
    Name of the application you would like to uninstall, upgrade, or install. 
    https://community.chocolatey.org/packages is a good resource to find this.

PARAMETER: -Version "DesiredVersion"
    Optionally, specify a version to install.

PARAMETER: -AllowDowngrades
    Allows downgrading existing installations to the specified version.

PARAMETER: -InstallChocolateyIfMissing
    If Chocolatey isn't installed, this option installs it before starting your action.

PARAMETER: -UpgradeChocolatey
    If an update for Chocolatey itself is available, this option upgrades it to the latest version.

PARAMETER: -SkipSleep
    The script waits for a random interval between 1 and 15 minutes before performing an action with Chocolatey to help avoid rate limiting.
    Use this option to skip the wait. For more information, see https://docs.chocolatey.org/en-us/community-repository/community-packages-disclaimer#excessive-use.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Updated functions, removed writing to the error stream, removed update environment variables, added signature validation, updated comments, added the option to specify a version, and added data validation.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action,
    [Parameter()]
    [String]$Name,
    [Parameter()]
    [String]$Version,
    [Parameter()]
    [Switch]$AllowDowngrades = [System.Convert]::ToBoolean($env:allowDowngrades),
    [Parameter()]
    [Switch]$InstallChocolateyIfMissing = [System.Convert]::ToBoolean($env:installChocolateyIfNecessary),
    [Parameter()]
    [Switch]$UpgradeChocolatey = [System.Convert]::ToBoolean($env:upgradeChocolatey),
    [Parameter()]
    [Switch]$SkipSleep = [System.Convert]::ToBoolean($env:skipSleep)
)
# Helper functions and input validation
begin {
    # URL to Chocolatey installation script. Feel free to replace this with your own link.
    $InstallUri = "https://community.chocolatey.org/install.ps1"

    # If script form variables are used, replace the command line parameters with their value.
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }
    if ($env:packageName -and $env:packageName -notlike "null") { $Name = $env:packageName }
    if ($env:version -and $env:version -notlike "null") { $Version = $env:version }
    
    # Trim whitespace from the action if it's defined
    if ($Action) {
        $Action = $Action.Trim()
    }

    # Trim whitespace from the package name if it's defined
    if ($Name) {
        $Name = $Name.Trim()
    }

    # Trim whitespace from the version if it's defined
    if ($Version) {
        $Version = $Version.Trim()
    }

    # Ensure that both a package name and action are provided
    # If not, display an error message and exit with status code 1
    if (!($Name) -or !($Action)) {
        Write-Host -Object "[Error] You must provide a valid package name and action."
        exit 1
    }

    # Validate the package name format; it should only contain lowercase letters, hyphens, and dots
    if ($Name -cmatch "[^a-z0-9.-]") {
        Write-Host -Object "[Error] An invalid package name '$Name' was given. Chocolatey package names can only contain lowercase letters, numbers, hyphens, and dots."
        Write-Host -Object "[Error] https://docs.chocolatey.org/en-us/create/create-packages/#naming-your-package"
        exit 1
    }

    # Define a list of valid actions
    $ValidActions = "Install", "Upgrade", "Uninstall"

    # Check if the action is in the list of valid actions
    # If not, display an error message and exit with status code 1
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] An invalid action '$Action' was given. Only the following actions are supported: 'Install', 'Uninstall', 'Upgrade'."
        exit 1
    }

    # Check if the name is "All" and the action is not "Upgrade"
    # Display an error message and exit if an attempt is made to install or uninstall all packages at once
    if ($Name -like "All" -and $Action -ne "Upgrade") {
        Write-Host -Object "[Error] Installing or uninstalling all packages at once is not supported!"
        exit 1
    }

    # Check if a specific version is provided but the action is not "Install".
    if ($Version -and $Action -ne "Install") {
        Write-Host -Object "[Error] To install a specific version, you must specify 'Install', even if you're changing the version of an existing application."
        exit 1
    }

    # Validate the format of the version number.
    # If the version contains characters other than numbers or dots, print an error message and a reference URL, then exit.
    if ($Version -match "[^0-9.]") {
        Write-Host -Object "[Error] An invalid version '$Version' was given. Chocolatey version numbers can only contain numbers and dots."
        Write-Host -Object "[Error] https://docs.chocolatey.org/en-us/create/create-packages/#versioning-recommendations"
        exit 1
    }

    # Check if the user has allowed downgrades without specifying a version.
    # Print an error message and exit if downgrades are allowed but no version is specified.
    if ($AllowDowngrades -and !$Version) {
        Write-Host -Object "[Error] You must specify a version to allow downgrades to an older version."
        exit 1
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Local Administrator privileges or run as SYSTEM. https://ninjarmm.zendesk.com/hc/en-us/articles/360016094532-Credential-Exchange"
        exit 1
    }

    function Test-ChocolateyInstalled {
        [CmdletBinding()]
        param()
    
        # Try to retrieve the 'choco' command. If it exists, assign it to $Command, suppressing errors.
        $Command = Get-Command choco -ErrorAction SilentlyContinue

        # Check if the 'choco' command path is found and if it exists on the filesystem
        if ($Command.Path -and (Test-Path -Path $Command.Path -ErrorAction SilentlyContinue)) {
            return $true
        }

        # If 'choco' command was not found, check if 'Chocolatey\bin' is in the system PATH
        if (([Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)) -like "*chocolatey\bin*") {
            # Update the current session's PATH with the system PATH containing 'Chocolatey\bin'
            $env:Path = [Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine);

            # Re-check for the 'choco' command after updating the PATH
            $Command = Get-Command choco -ErrorAction SilentlyContinue
            if ($Command.Path -and (Test-Path -Path $Command.Path -ErrorAction SilentlyContinue)) {
                return $true
            }
            else {
                return $false
            }
        }
        
        # Check if the 'ChocolateyInstall' environment variable is set
        # Verify if 'choco' exists in the 'ChocolateyInstall\bin' directory
        if ($env:ChocolateyInstall -and (Test-Path -Path "$env:ChocolateyInstall\bin\choco" -ErrorAction SilentlyContinue)) {
            # Update the current session's PATH with the Chocolatey installation path
            $Env:Path = "$Env:Path;$env:ChocolateyInstall\bin"
            return $true
        }

        # As a last check, look for 'choco' in the default ProgramData path for Chocolatey
        if (Test-Path -Path "$env:ProgramData\chocolatey\bin\choco" -ErrorAction SilentlyContinue) {
            # Update the PATH to include the default Chocolatey ProgramData path
            $Env:Path = "$Env:Path;$env:ChocolateyInstall\bin"
            return $true
        }
    }

    function Test-ChocolateyInstallVariable {
        [CmdletBinding()]
        param()

        # Check if the 'ChocolateyInstall' environment variable is set
        if ($env:ChocolateyInstall) {
            return $True
        }

        # Check if the 'ChocolateyInstall' environment variable is set at the machine level.
        if (([Environment]::GetEnvironmentVariable('ChocolateyInstall', [System.EnvironmentVariableTarget]::Machine))) {
            $env:ChocolateyInstall = [Environment]::GetEnvironmentVariable('ChocolateyInstall', [System.EnvironmentVariableTarget]::Machine);
            return $true
        }

        # Try to retrieve the 'choco' command. If it exists, assign it to $Command, suppressing errors.
        $Command = Get-Command choco -ErrorAction SilentlyContinue

        # Verify that the 'choco' command path exists, is valid, and matches the typical path pattern for Chocolatey installations.
        if ($Command.Path -and (Test-Path -Path $Command.Path -ErrorAction SilentlyContinue) -and $Command.Path -like "*\bin\choco.exe") {
            # Set the 'ChocolateyInstall' environment variable based on the retrieved path.
            $env:ChocolateyInstall = $Command.Path -replace "\\bin\\choco.exe.*"
            return $true
        }

        # As a last check, look for 'choco' in the default ProgramData path for Chocolatey
        if (Test-Path -Path "$env:ProgramData\chocolatey\bin\choco.exe" -ErrorAction SilentlyContinue) {
            # Update the ChocolateyInstall variable to include the default Chocolatey ProgramData path
            $env:ChocolateyInstall = "$env:ProgramData\chocolatey"
            $Env:Path = "$Env:Path;$env:ChocolateyInstall\bin"
            return $true
        }
    }

    # Utility function for downloading files.
    function Invoke-Download {
        param(
            [Parameter()]
            [String]$URL,
            [Parameter()]
            [String]$Path,
            [Parameter()]
            [int]$Attempts = 3,
            [Parameter()]
            [Switch]$SkipSleep
        )

        # Display the URL being used for the download
        Write-Host -Object "URL '$URL' was given."
        Write-Host -Object "Downloading the file..."

        # Initialize the attempt counter
        $i = 1
        While ($i -le $Attempts) {
            # If SkipSleep is not set, wait for a random time between 3 and 15 seconds before each attempt
            if (!($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
        
            # Provide a visual break between attempts
            if ($i -ne 1) { Write-Host "" }
            Write-Host "Download Attempt $i"

            # Temporarily disable progress reporting to speed up script performance
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
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
                Write-Warning "An error has occurred while downloading!"
                Write-Warning $_.Exception.Message

                # If the file partially downloaded, delete it to avoid corruption
                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            # Restore the original progress preference setting
            $ProgressPreference = $PreviousProgressPreference
            # If the file was successfully downloaded, exit the loop
            if ($File) {
                $i = $Attempts
            }
            else {
                # Warn the user if the download attempt failed
                Write-Warning "File failed to download."
                Write-Host ""
            }

            # Increment the attempt counter
            $i++
        }

        # Final check: if the file still doesn't exist, report an error and exit
        if (!(Test-Path $Path)) {
            Write-Host -Object "[Error] Failed to download file."
            Write-Host -Object "Please verify the URL of '$URL'."
            exit 1
        }
        else {
            # If the download succeeded, return the path to the downloaded file
            return $Path
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if Chocolatey is installed and if InstallChocolateyIfMissing is false
    # If Chocolatey is not installed and installation is not allowed, exit with an error
    if (!$(Test-ChocolateyInstalled) -and !$InstallChocolateyIfMissing) {
        Write-Host -Object "[Error] Install Chocolatey If Necessary is not selected and chocolatey was not installed. Unable to continue."
        exit 1
    }

    # Determine the supported TLS versions and set the appropriate security protocol
    $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
    if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
    }
    elseif ( $SupportedTLSversions -contains 'Tls12' ) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    else {
        # Warn the user if TLS 1.2 and 1.3 are not supported, which may cause the script to fail
        Write-Warning "TLS 1.2 and/or TLS 1.3 are not supported on this system. This script may fail. https://blog.chocolatey.org/2020/01/remove-support-for-old-tls-versions/"
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
        }
    }

    if (!($SkipSleep)) {
        $SleepTime = Get-Random -Minimum 60 -Maximum 900
        $SleepTimeMinutes = [math]::Round($($SleepTime / 60))
        Write-Host "Waiting for $SleepTimeMinutes minutes."
        Start-Sleep -Seconds $SleepTime
    }

    # Check if Chocolatey is not installed but installation is allowed
    if (!$(Test-ChocolateyInstalled) -and $InstallChocolateyIfMissing) {
        Write-Host "Chocolatey is not installed."
        Write-Host "Downloading Chocolatey's install script and installing."

        # Define download arguments for Chocolatey installation script
        $DownloadArguments = @{
            Path = "$env:TEMP\install.ps1"
            URL  = $InstallUri
        }

        # Optionally add SkipSleep to download arguments if specified
        if ($SkipSleep) { $DownloadArguments["SkipSleep"] = $True }
        
        # Download and create the Chocolatey installation script
        $ChocolateyScriptFilePath = Invoke-Download @DownloadArguments

        # Validating signature of the installation script
        $ScriptSignature = Get-AuthenticodeSignature -FilePath $ChocolateyScriptFilePath -ErrorAction SilentlyContinue
        if (!$ScriptSignature) {
            Write-Host -Object "[Error] A signature was not found on the script file."
            exit 1
        }
        if ($ScriptSignature.Status -ne "Valid" -and $ScriptSignature.SignerCertificate.Subject -notlike "*Chocolatey Software, Inc*") {
            Write-Host -Object "[Error] The script file's signature is '$($ScriptSignature.Status)' with the subject '$($ScriptSignature.SignerCertificate.Subject)'."
            Write-Host -Object "[Error] Expected the signature to be valid and contain 'Chocolatey Software, Inc'"
            exit 1
        }

        # Convert the script into a script block
        $ChocolateyScript = [scriptblock]::Create($ChocolateyScriptFilePath)
        try {
            # Run the installation script
            $ChocolateyScript.Invoke()
            if (!(Test-ChocolateyInstalled)) {
                throw "Chocolatey is missing but the script didn't throw any terminating errors?"
            }
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host "Failed to install Chocolatey."
            exit 1
        }

        # Remove the installation script from the TEMP folder if it exists
        if (Test-Path "$env:TEMP\install.ps1" -ErrorAction SilentlyContinue) {
            try {
                Remove-Item -Path "$env:TEMP\install.ps1" -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to remove installation script at $env:TEMP\install.ps1"
                $ExitCode = 1
            }
        }
    }

    if (!(Test-ChocolateyInstallVariable) -and $UpgradeChocolatey) {
        Write-Host -Object "[Error] The environment variable 'ChocolateyInstall' is missing. You may need to restart or reinstall Chocolatey."
        exit 1
    }


    # Check for outdated Chocolatey version if upgrades are allowed
    $ChocolateyOutdated = & choco outdated --limitoutput
    if ($ChocolateyOutdated -match "chocolatey\|" -and $UpgradeChocolatey) {
        Write-Host "The current installation of Chocolatey is outdated."
        Write-Host ""
        Write-Host "Installed Package | Installed Version | Current Version | Pinned?"
        $ChocolateyOutdated | Write-Host
        Write-Host ""
        Write-Host "Upgrading..."

        # Define arguments to run Chocolatey upgrade command for Chocolatey itself
        $ChocoUpdateArgs = New-Object System.Collections.Generic.List[string]
        $ChocoUpdateArgs.Add("upgrade")
        $ChocoUpdateArgs.Add("chocolatey")
        $ChocoUpdateArgs.Add("--yes")
        $ChocoUpdateArgs.Add("--nocolor")
        $ChocoUpdateArgs.Add("--no-progress")
        $ChocoUpdateArgs.Add("--limitoutput")

        # Start the Chocolatey upgrade process and wait for completion
        $chocoupdate = Start-Process "choco" -ArgumentList $ChocoUpdateArgs -Wait -PassThru -NoNewWindow
        Write-Host "Exit Code: $($chocoupdate.ExitCode)"

        # Check the exit code of the upgrade process
        switch ($chocoupdate.ExitCode) {
            0 { }
            default { 
                Write-Host -Object "[Error] The exit code does not indicate success."
                exit $chocoupdate.ExitCode
            }
        }

        # If Chocolatey fails to update, log an error and exit.
        $ChocolateyOutdated = & choco outdated --limitoutput
        if ($ChocolateyOutdated -match "chocolatey\|") {
            Write-Host -Object "[Error] Failed to update Chocolatey."
            exit 1
        }
        else {
            Write-Host -Object "Chocolatey updated successfully.`n"
        }
    }
    elseif ($UpgradeChocolatey) {
        Write-Host -Object "`nChocolatey is already up-to-date.`n"
    }

    # Define arguments for the specified action (Install, Uninstall, Upgrade) on a package
    $ChocoArguments = New-Object System.Collections.Generic.List[string]
    switch ($Action) {
        "Install" { $ChocoArguments.Add("install") }
        "Uninstall" { $ChocoArguments.Add("uninstall") }
        "Upgrade" { $ChocoArguments.Add("upgrade") }
    }

    # Add the package name and other required options to the arguments list
    $ChocoArguments.Add($Name)
    if ($Version) {
        $ChocoArguments.Add("--version")
        $ChocoArguments.Add($Version)
    }
    if ($AllowDowngrades) {
        $ChocoArguments.Add("--allow-downgrade")
    }
    $ChocoArguments.Add("--yes")
    $ChocoArguments.Add("--nocolor")
    $ChocoArguments.Add("--no-progress")
    $ChocoArguments.Add("--limitoutput")

    # Start the specified Chocolatey action process (install, uninstall, or upgrade) and wait for completion
    $chocolatey = Start-Process "choco" -ArgumentList $ChocoArguments -Wait -PassThru -NoNewWindow

    # Display the exit code from the Chocolatey action process
    Write-Host "Exit Code: $($chocolatey.ExitCode)"
    switch ($chocolatey.ExitCode) {
        0 { Write-Host "Successfully completed the action '$Action' for package '$Name'." }
        default { 
            Write-Host -Object "[Error] The exit code does not indicate success." 
            exit $($chocolatey.ExitCode)
        }
    }

    exit $ExitCode
}
end {
    
    
    
}


