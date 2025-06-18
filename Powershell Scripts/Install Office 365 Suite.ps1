# Installs Office 365 from a config file or creates a generic config file and installs.
#Requires -Version 5.1

<#
.SYNOPSIS
    Installs Office 365 from a config file or creates a generic config file and installs.
.DESCRIPTION
    Installs Office 365 from a config file or creates a generic config file and installs.
.EXAMPLE
    No parameters need if you want to use the default config file OR change the $OfficeXML variable to use your XML config file's content.
.EXAMPLE
     -ConfigurationXMLFile https://replace.me/configuration.xml
    Install Office 365 and use a local config file.
    You can use https://config.office.com/deploymentsettings to help build the config file.
.OUTPUTS
    None
.NOTES
    This will reboot after a successful install.
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support, made restarts optional, changed default download path to %TEMP%\Office365Install, switched to downloading an xml instead of using a local path.
#>

[CmdletBinding()]
param(
    # Use a existing config file
    [Parameter()]
    [String]$ConfigurationXMLFile,
    # Path where we will store our install files and our XML file
    [Parameter()]
    [String]$OfficeInstallDownloadPath = "$env:TEMP\Office365Install",
    [Parameter()]
    [Switch]$Restart
)

begin {
    if ($env:linkToConfigurationXml -and $env:linkToConfigurationXml -notlike "null") { $ConfigurationXMLFile = $env:linkToConfigurationXml }
    if ($env:restartComputer -like "true") { $Restart = $True }

    $CleanUpInstallFiles = $True

    # In case 'https://' is omitted from the URL.
    if ($ConfigurationXMLFile -and $ConfigurationXMLFile -notmatch "^http(s)?://") {
        Write-Host "[Warn] http(s):// is required to download the file. Adding https:// to your input...."
        $ConfigurationXMLFile = "https://$ConfigurationXMLFile"
        Write-Host "[Warn] New Url $ConfigurationXMLFile."
    }

    # Set TLS Version
    $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
    if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
    }
    elseif ( $SupportedTLSversions -contains 'Tls12' ) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    else {
        # Not everything requires TLS 1.2, but we'll try anyway.
        Write-Host "[Warn] TLS 1.2 and or TLS 1.3 are not supported on this system. This script may fail!"
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Write-Host "[Warn] PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
        }
    }

    function Set-XMLFile {
        # XML data that will be used for the download/install
        # Example config below generated from https://config.office.com/
        # To use your own config, just replace <Configuration> to </Configuration> with your xml config file content.
        # Notes:
        #  "@ can not have any character after it
        #  @" can not have any spaces or character before it.
        $OfficeXML = [XML]@"
<Configuration ID="76b3b530-54a8-44d8-9689-278ec2547592">
  <Info Description="Example O365 install" />
  <Add OfficeClientEdition="64" Channel="MonthlyEnterprise" MigrateArch="TRUE">
    <Product ID="O365BusinessRetail">
      <Language ID="MatchOS" />
      <Language ID="MatchPreviousMSI" />
      <ExcludeApp ID="Access" />
      <ExcludeApp ID="Groove" />
      <ExcludeApp ID="Lync" />
      <ExcludeApp ID="Publisher" />
    </Product>
  </Add>
  <Property Name="SharedComputerLicensing" Value="0" />
  <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
  <Property Name="DeviceBasedLicensing" Value="0" />
  <Property Name="SCLCacheOverride" Value="0" />
  <Updates Enabled="TRUE" />
  <RemoveMSI />
  <AppSettings>
    <Setup Name="Company" Value="Ninja Example" />
    <User Key="software\microsoft\office\16.0\excel\options" Name="defaultformat" Value="51" Type="REG_DWORD" App="excel16" Id="L_SaveExcelfilesas" />
    <User Key="software\microsoft\office\16.0\powerpoint\options" Name="defaultformat" Value="27" Type="REG_DWORD" App="ppt16" Id="L_SavePowerPointfilesas" />
    <User Key="software\microsoft\office\16.0\word\options" Name="defaultformat" Value="" Type="REG_SZ" App="word16" Id="L_SaveWordfilesas" />
  </AppSettings>
  <Display Level="None" AcceptEULA="TRUE" />
  <Setting Id="SETUP_REBOOT" Value="Never" /> 
  <Setting Id="REBOOT" Value="ReallySuppress"/>
</Configuration>
"@
        #Save the XML file
        $OfficeXML.Save("$OfficeInstallDownloadPath\OfficeInstall.xml")
      
    }
    function Get-ODTURL {
        $Uri = 'https://www.microsoft.com/en-us/download/details.aspx?id=49117'
        $DownloadURL = ""
        for ($i = 1; $i -le 3; $i++) {
            try {
                $MSWebPage = Invoke-WebRequest -Uri $Uri -UseBasicParsing -MaximumRedirection 10
                $DownloadURL = $MSWebPage.Links | Where-Object { $_.href -like "*officedeploymenttool*.exe" } | Select-Object -ExpandProperty href -First 1
                if ($DownloadURL) {
                    break
                }
                Write-Host "[Warn] Unable to find the download link for the Office Deployment Tool at: $Uri. Attempt $i of 3."
                Start-Sleep -Seconds $($i * 30)
            }
            catch {
                Write-Host "[Warn] Unable to connect to the Microsoft website. Attempt $i of 3."
            }
        }
        
        if (-not $DownloadURL) {
            Write-Host "[Error] Unable to find the download link for the Office Deployment Tool at: $Uri"
            exit 1
        }
        return $DownloadURL
    }
    function Test-IsElevated {
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Create a WindowsPrincipal object based on the current identity
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)

        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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
        Write-Host "[Info] URL '$URL' was given."
        Write-Host "[Info] Downloading the file..."

        # Determine the supported TLS versions and set the appropriate security protocol
        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Warn the user if TLS 1.2 and 1.3 are not supported, which may cause the download to fail
            Write-Host "[Warn] TLS 1.2 and/or TLS 1.3 are not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Host "[Warn] PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        # Initialize the attempt counter
        $i = 1
        While ($i -le $Attempts) {
            # If SkipSleep is not set, wait for a random time between 3 and 15 seconds before each attempt
            if (!($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host "[Info] Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
            
            # Provide a visual break between attempts
            if ($i -ne 1) { Write-Host "" }
            Write-Host "[Info] Download Attempt $i"

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
                Write-Host "[Warn] An error has occurred while downloading!"
                Write-Host $_.Exception.Message

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
                Write-Host "[Warn] File failed to download."
                Write-Host ""
            }

            # Increment the attempt counter
            $i++
        }

        # Final check: if the file still doesn't exist, report an error and exit
        if (!(Test-Path $Path)) {
            Write-Host "[Error] Failed to download file."
            Write-Host "Please verify the URL of '$URL'."
            exit 1
        }
        else {
            # If the download succeeded, return the path to the downloaded file
            return $Path
        }
    }

    # Check's the two Uninstall registry keys to see if the app is installed. Needs the name as it would appear in Control Panel.
    function Find-UninstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString
        )
        process {
            $UninstallList = New-Object System.Collections.Generic.List[Object]

            $Result = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | 
                Where-Object { $_.DisplayName -like "*$DisplayName*" }

            if ($Result) { $UninstallList.Add($Result) }

            $Result = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | 
                Where-Object { $_.DisplayName -like "*$DisplayName*" }

            if ($Result) { $UninstallList.Add($Result) }

            # Programs don't always have an uninstall string listed here so to account for that I made this optional.
            if ($UninstallString) {
                # 64 Bit
                $UninstallList | Select-Object -ExpandProperty UninstallString -ErrorAction Ignore
            }
            else {
                $UninstallList
            }
        }
    }
}
process {
    $VerbosePreference = 'Continue'
    $ErrorActionPreference = 'Stop'

    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    if (-not (Test-Path $OfficeInstallDownloadPath )) {
        New-Item -Path $OfficeInstallDownloadPath -ItemType Directory | Out-Null
    }

    if (-not ($ConfigurationXMLFile)) {
        Set-XMLFile
    }
    else {
        Invoke-Download -URL $ConfigurationXMLFile -Path "$OfficeInstallDownloadPath\OfficeInstall.xml"
        try {
            [xml]::new().Load("$OfficeInstallDownloadPath\OfficeInstall.xml")
        }
        catch {
            Write-Host "[Error] The XML file is not valid. Please check the file and try again."
            exit 1
        }
    }

    $ConfigurationXMLPath = "$OfficeInstallDownloadPath\OfficeInstall.xml"
    $ODTInstallLink = Get-ODTURL

    #Download the Office Deployment Tool
    Write-Host "[Info] Downloading the Office Deployment Tool..."
    Invoke-Download -URL $ODTInstallLink -Path "$OfficeInstallDownloadPath\ODTSetup.exe"

    #Run the Office Deployment Tool setup
    try {
        Write-Host "[Info] Running the Office Deployment Tool..."
        Start-Process "$OfficeInstallDownloadPath\ODTSetup.exe" -ArgumentList "/quiet /extract:$OfficeInstallDownloadPath" -Wait -NoNewWindow
    }
    catch {
        Write-Host "[Warn] Error running the Office Deployment Tool. The error is below:"
        Write-Host "$_"
        exit 1
    }

    #Run the O365 install
    try {
        Write-Host "[Info] Downloading and installing Microsoft 365"
        $Install = Start-Process "$OfficeInstallDownloadPath\Setup.exe" -ArgumentList "/configure $ConfigurationXMLPath" -Wait -PassThru -NoNewWindow

        if ($Install.ExitCode -ne 0) {
            Write-Host "[Error] Exit Code does not indicate success!"
            exit 1
        }
    }
    Catch {
        Write-Host "[Warn] Error running the Office install. The error is below:"
        Write-Host "$_"
    }

    $OfficeInstalled = Find-UninstallKey -DisplayName "Microsoft 365"

    if ($CleanUpInstallFiles) {
        Write-Host "[Info] Cleaning up install files..."
        Remove-Item -Path $OfficeInstallDownloadPath -Force -Recurse
    }

    if ($OfficeInstalled) {
        Write-Host "[Info] $($OfficeInstalled.DisplayName) installed successfully!"
        if ($Restart) {
            Write-Host "[Info] Restarting the computer in 60 seconds..."
            Start-Process shutdown.exe -ArgumentList "-r -t 60" -Wait -NoNewWindow
        }
        exit 0
    }
    else {
        Write-Host "[Error] Microsoft 365 was not detected after the install ran!"
        exit 1
    }
}
end {
    
    
    
}

