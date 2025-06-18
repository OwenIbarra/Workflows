# Installs an out-of-band patch given a URL or a local path.
#Requires -Version 5.1

<#
.SYNOPSIS
    Installs an out-of-band patch given a URL or a local path.
.DESCRIPTION
    Installs an out-of-band patch given a URL or a local path.
.EXAMPLE
    -MSU 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/07/windows10.0-kb5040427-x64_750f2819b527034dcdd10be981fa82d140767f8f.msu'
    
    URL 'https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/secu/2024/07/windows10.0-kb5040427-x64_750f2819b527034dcdd10be981fa82d140767f8f.msu' was given.
    Downloading the file...
    Waiting for 14 seconds.
    Download Attempt 1
    Installing update at C:\Windows\TEMP\windowsupdate-1135150612.msu.
    Exit Code: 3010
    [Warn] A reboot is required for this update to take effect.

PRESET PARAMETER: -MSU "https://www.replace.me"
    Specify either a link or a file path to the patch you would like to install.

PRESET PARAMETER: -ForceReboot
    Reboot the computer after successfully installing the requested patch.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$MSU,
    [Parameter()]
    [Switch]$ForceReboot = [System.Convert]::ToBoolean($env:forceReboot)
)

begin {
    if ($env:urlOrLocalPathToMsu -and $env:urlOrLocalPathToMsu -notlike "null") { $MSU = $env:urlOrLocalPathToMsu }

    # Check if $MSU is not provided
    if (!$MSU) {
        Write-Host -Object "[Error] An MSU was not provided. Please provide either a local file path or a URL to download the MSU."
        exit 1
    }

    # Remove quotations if given quotations
    if ($MSU) {
        if ($MSU.Trim() -match "^'" -or $MSU.Trim() -match "'$" -or $MSU.Trim() -match '^"' -or $MSU.Trim() -match '"$') {
            $QuotationsFound = $true
        }
        $MSU = ($MSU.Trim() -replace "^'" -replace "'$" -replace '^"' -replace '"$').Trim()

        if ($QuotationsFound) {
            Write-Host -Object "[Warning] Removing quotations from your path. Your new path is '$MSU'."
        }
    }

    # Check if $MSU is not a local file path
    if ($MSU -notmatch '^[A-Za-z]:\\') {
        # Check if $MSU starts with 'http' but not 'http[s]?://'
        if ($MSU -match '^http' -and $MSU -notmatch '^http[s]?://') {
            Write-Host -Object "[Error] URL '$MSU' is malformed."
            exit 1
        }

        # Check if $MSU contains double 'http[s]?://'
        if ($MSU -match '^http[s]?://http[s]?://') {
            Write-Host -Object "[Error] URL '$MSU' is malformed."
            exit 1
        }

        # Add 'https://' to $MSU if it does not start with 'http'
        if ($MSU -notmatch '^http') {
            $MSU = "https://$MSU"
            Write-Host -Object "[Warn] Missing http(s) from URL, changing URL to '$MSU'."
        }

        # Check if $MSU has a top-level domain
        if ($MSU -notmatch '.*\..*') {
            Write-Host -Object "[Error] No top-level domain found in URL."
            exit 1
        }
        
        # Validate $MSU as a URI
        try {
            [System.Uri]$MSU | Out-Null
        }
        catch {
            Write-Host -Object "[Error] URL '$MSU' is malformed."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
    
    # Check if $MSU is a local file path
    if ($MSU -match '^[A-Za-z]:\\') {
        # Check if $MSU contains invalid characters
        if ($MSU -match '[<>"/\|?]' -or $MSU -match ':.*:' -or $MSU -match '::') {
            Write-Host -Object "[Error] The file path '$MSU' contains one of the following invalid characters: < > : `" / \ | ? :"
            exit 1
        }

        # Check if the file at $MSU exists
        if (!(Test-Path -Path "$MSU" -ErrorAction SilentlyContinue)) {
            Write-Host -Object "[Error] File does not exist at path '$MSU'."
            exit 1
        }

        # Try to get the item at $MSU path
        try {
            $MSUFile = Get-Item -Path $MSU -Force -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Failed to retrieve file at path '$MSU'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        # Check if more than one file is found at $MSU path
        if ($MSUFile.Count -gt 1) {
            Write-Host -Object "[Error] Too many files were found at path '$MSU'; please be more specific."
        }

        # Check if the $MSU path is a folder
        if ($MSUFile.PSIsContainer) {
            Write-Host -Object "[Error] The given path '$MSU' is a folder and not an MSU file."
            exit 1
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
            Write-Warning -Message "TLS 1.2 and or TLS 1.3 are not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning -Message "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        $i = 1
        While ($i -le $Attempts) {
            # Some cloud services have rate-limiting
            if (-not ($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host -Object "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
        
            if ($i -ne 1) { Write-Host "" }
            Write-Host -Object "Download Attempt $i"

            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                # Invoke-WebRequest is preferred because it supports links that redirect, e.g., https://t.ly
                if ($PSVersionTable.PSVersion.Major -lt 4) {
                    # Downloads the file
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($URL, $Path)
                }
                else {
                    # Standard options
                    $WebRequestArgs = @{
                        Uri                = $URL
                        OutFile            = $Path
                        MaximumRedirection = 10
                        UseBasicParsing    = $true
                    }

                    # Downloads the file
                    Invoke-WebRequest @WebRequestArgs
                }

                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning -Message "An error has occurred while downloading!"
                Write-Warning -Message $_.Exception.Message

                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            $ProgressPreference = $PreviousProgressPreference
            if ($File) {
                $i = $Attempts
            }
            else {
                Write-Warning -Message "File failed to download."
                Write-Host -Object ""
            }

            $i++
        }

        if (-not (Test-Path $Path)) {
            Write-Host -Object "[Error] Failed to download file."
            Write-Host -Object "Please verify the URL of '$URL'."
            exit 1
        }
        else {
            return $Path
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

    # Check if $MSU is not a local file path and download it if it's a URL
    if ($MSU -notmatch '^[A-Za-z]:\\') {
        $MSU = Invoke-Download -URL $MSU -Path "$env:TEMP\windowsupdate-$(Get-Random).msu"
        $DownloadedUpdate = $True
    }

    # Set the log file location
    $LogLocation = "$env:TEMP\update-log-$(Get-Random).evt"

    # Inform the user that the update is being installed
    Write-Host -Object "Installing update at $MSU."

    # Prepare the arguments for the update process
    $UpdateArguments = "`"$MSU`"", "/quiet", "/norestart", "/log:`"$LogLocation`""
    $UpdateProcess = Start-Process -FilePath "$env:SystemRoot\System32\wusa.exe" -ArgumentList $UpdateArguments -Wait -NoNewWindow -PassThru

    # Check if the log file exists and try to read it
    if (Test-Path -Path $LogLocation -ErrorAction SilentlyContinue) {
        $LogFile = Get-WinEvent -Path $LogLocation -Oldest -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TimeCreated) $($_.Message)" }
        Remove-Item -Path $LogLocation -Force -ErrorAction SilentlyContinue
    }
    
    # Remove the downloaded update file if it was downloaded
    if ($DownloadedUpdate -and (Test-Path -Path $MSU -ErrorAction SilentlyContinue)) {
        Remove-Item -Path $MSU -Force
    }

    # Output the exit code of the update process
    Write-Host -Object "Exit Code: $($UpdateProcess.ExitCode)"

    # Check if the exit code indicates success
    $ValidExitCodes = "0", "3010"
    if ($ValidExitCodes -notcontains $UpdateProcess.ExitCode) {
        Write-Host -Object "[Error] Exit code does not indicate success!"

        # Output the update log if available
        if ($LogFile) {
            Write-Host -Object "`n### Update Log ###"
            Write-Host -Object $LogFile
        }
        exit 1
    }

    # Inform the user if a reboot is required
    if (!$ForceReboot -and $UpdateProcess.ExitCode -eq 3010) {
        Write-Host -Object "[Warn] A reboot is required for this update to take effect."
    }

    # Schedule a reboot if requested and the update was successful
    if ($ForceReboot -and $ExitCode -eq 0) {
        Write-Host "`nScheduling reboot for $((Get-Date).AddMinutes(1)) as requested."

        Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
    }

    exit $ExitCode
}
end {
    
    
    
}
