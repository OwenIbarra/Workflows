# Download and Install ConnectWise ScreenConnect from the domain used for ScreenConnect. Supports automatic customization of the device type, location and other ScreenConnect Fields.

<#
.SYNOPSIS
Download and Install ConnectWise ScreenConnect from the domain used for ScreenConnect. Supports automatic customization of the device type, location and other ScreenConnect Fields.

.DESCRIPTION
Download and Install ConnectWise ScreenConnect from the domain used for ScreenConnect. Supports automatic customization of the device type, location and other ScreenConnect Fields.

.EXAMPLE
-ScreenConnectDomain "testscreen.screenconnect.com" -UseOrgName -UseLocation -UseDeviceType

Installer Log File location will be: C:\Windows\TEMP\tmp9A50.tmp
ScreenConnect Client (abcd123456) is not installed and will be installed.
Attempting to build from domain...
URL Built: https://testscreen.screenconnect.com/Bin/Test Company.ClientSetup.msi?e=Access&y=Guest&c=Kyle - OOB&c=Main Office&c=&c=Workstation&c=&c=&c=&c=
URL Given, Downloading the file...
Download Attempt 1
Exit Code: 0
Success

PRESET PARAMETER: -ScreenConnectDomain "your.domain.com"
Your ScreenConnect instance's domain name. The script will use this to construct a download URL from scratch with the options you selected.

PRESET PARAMETER: -UseOrgName
Modifies your URL to use the organization name in the Company Name Field in ScreenConnect.

PRESET PARAMETER: -UseLocation
Modifies your URL to use the Location Name in the Site Name Field in ScreenConnect.

PRESET PARAMETER: -UseDeviceType
Modifies your URL to include the type of device in ScreenConnect. (Server, Workstation, Laptop etc.)

PRESET PARAMETER: -Department "Your Department Name Here"
Modifies your URL to include your desired department name in ScreenConnect.

PRESET PARAMETER: -SkipSleep
By default the script sleeps for a random interval between 3 and 60 seconds prior to downloading the file. This parameter skips the sleep.

PRESET PARAMETER: -Force
If ScreenConnect is already installed attempt to install it anyways.

.NOTES
Minimum OS Architecture Supported: Windows 8, Windows Server 2012
Can work on lower versions of Windows, provided that the OS/.NET is able to download the file. PowerShell 2.0 might face issues due to its lack of TLS support in .NET 2.0.

Adapted from Chris White's script: https://ninjarmm.zendesk.com/hc/en-us/community/posts/7549797399821-Connectwise-Control-Installer

Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    # Change the defaults if you don't wish to use parameters when running this script
    [Parameter()]
    [String]$MSI = "ClientSetup.msi",
    [Parameter()]
    [String]$DestinationFolder = "$env:TEMP",
    [Parameter()]
    [String]$ScreenConnectDomain,
    [Parameter()]
    [String]$InstanceID,
    [Parameter()]
    [Switch]$UseOrgName = [System.Convert]::ToBoolean($env:useNinjaOrganizationName),
    [Parameter()]
    [Switch]$UseLocation = [System.Convert]::ToBoolean($env:useNinjaLocationName),
    [Parameter()]
    [Switch]$UseDeviceType = [System.Convert]::ToBoolean($env:addDeviceType),
    [Parameter()]
    [String]$Department,
    [Parameter()]
    [Switch]$SkipSleep = [System.Convert]::ToBoolean($env:skipSleep),
    [Parameter()]
    [Switch]$Force = [System.Convert]::ToBoolean($env:force)
)
begin {
    # If Script Form is used replace the parameters with what was filled in.
    if ($env:screenconnectDomainName -and $env:screenconnectDomainName -notlike "null") { $ScreenConnectDomain = $env:screenconnectDomainName }
    if ($env:department -and $env:department -notlike "null") { $Department = $env:department }

    # Some means of installing the file is required.
    if (-not ($ScreenConnectDomain)) { Write-Error "A domain is required to install control."; exit 1 }

    if ($ScreenConnectDomain -match "^http(s)?://") {
        Write-Warning "http(s):// is not part of the domain name. Removing http(s):// from your input...."
        $ScreenConnectDomain = $ScreenConnectDomain -replace "^http(s)?://"
        Write-Warning "New Domain Name $ScreenConnectDomain."
    }

    if ($ScreenConnectDomain -match "^C:/") {
        Write-Error "It looks like you entered in a file path by mistake. We actually need the domain name used to reach your ScreenConnect website for example 'companyname.screenconnect.com'"
        exit 1
    }
    
    #### Helper functions used throughout the script ####

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Extract the ProductName from the msi
    function Get-ControlPanelName {
        [CmdletBinding()]
        param (
            [Parameter()]
            [string]$msiPath
        )
        $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
        $database = $windowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $windowsInstaller, @($msiPath, 0))
        $query = "SELECT `Value` FROM `Property` WHERE `Property` = 'ProductName'"

        $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, $query)
        $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null)

        $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
        if ($record) {
            return $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, 1)
        }

        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null
        [System.GC]::Collect()
    }

    # Is it a Server or Desktop OS?
    function Get-ProductType {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object ProductType -ExpandProperty ProductType
        }
        else {
            $OS = Get-WmiObject -Class Win32_OperatingSystem | Select-Object ProductType -ExpandProperty ProductType
        }
        
        return $OS
    }

    # Check the Chassis type to find out if it's a laptop or not.
    function Test-IsLaptop {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $Chassis = Get-CimInstance -ClassName win32_systemenclosure | Select-Object ChassisTypes -ExpandProperty ChassisTypes
        }
        else {
            $Chassis = Get-WmiObject -Class win32_systemenclosure | Select-Object ChassisTypes -ExpandProperty ChassisTypes
        }

        switch ($Chassis) {
            9 { return $True }
            10 { return $True }
            14 { return $True }
            default { return $False }
        }
    }

    # Check's the two uninstall registry keys to see if the app is installed. Needs the name as it would appear in Control Panel.
    function Find-UninstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString
        )
        process {
            $UninstallList = New-Object System.Collections.Generic.List[Object]

            $Result = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($Result) { $UninstallList.Add($Result) }

            $Result = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($Result) { $UninstallList.Add($Result) }

            # Programs don't always have an uninstall string listed here so to account for that I made this optional.
            if ($UninstallString) {
                $UninstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $UninstallList
            }
        }
    }

    # Handy download function
    function Invoke-Download {
        param(
            [Parameter()]
            [String]$URL,
            [Parameter()]
            [String]$Path,
            [Parameter()]
            [Switch]$SkipSleep
        )
        Write-Host "URL given; downloading the file..."

        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Not everything requires TLS 1.2, but we'll try anyways.
            Write-Warning "TLS 1.2 and or TLS 1.3 isn't supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        $i = 1
        While ($i -lt 4) {
            if (-not ($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 30
                Start-Sleep -Seconds $SleepTime
            }

            Write-Host "Download Attempt $i"

            try {
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($URL, $Path)
                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "An error has occurred while downloading!"
                Write-Warning $_.Exception.Message
            }

            if ($File) {
                $i = 4
            }
            else {
                $i++
            }
        }

        if (-not (Test-Path $Path)) {
            Write-Error "Failed to download file!"
            Exit 1
        }
    }

    # This will build our screenconnect download url if only given a domain name or if modification is needed to include the device type, location, org name etc.
    function Build-URL {
        param(
            [Parameter()]
            [String]$BaseURL,
            [Parameter()]
            [String]$Domain,
            [Parameter()]
            [String]$MSI,
            [Parameter()]
            [String]$Department,
            [Parameter()]
            [Switch]$UseOrgName,
            [Parameter()]
            [Switch]$UseLocation,
            [Parameter()]
            [Switch]$UseDeviceType
        )

        Write-Host "Attempting to build from domain..."
        $URL = "https://$Domain/Bin/$env:NINJA_COMPANY_NAME.ClientSetup.msi`?e=Access&y=Guest"

        if ($UseOrgName) { $URL = $URL + "&c=$env:NINJA_ORGANIZATION_NAME" }else { $URL = $URL + "&c=" }
        if ($UseLocation) { $URL = $URL + "&c=$env:NINJA_LOCATION_NAME" }else { $URL = $URL + "&c=" }
        if ($Department) { $URL = $URL + "&c=$Department" }else { $URL = $URL + "&c=" }
        if ($UseDeviceType) {
            switch (Get-ProductType) {
                1 { if (Test-IsLaptop) { $URL = $URL + "&c=Laptop&c=&c=&c=&c=" }else { $URL = $URL + "&c=Workstation&c=&c=&c=&c=" } }
                2 { $URL = $URL + "&c=Domain Controller&c=&c=&c=&c=" }
                3 { $URL = $URL + "&c=Server&c=&c=&c=&c=" }
            }
        }
        else {
            $URL = $URL + "&c=&c=&c=&c=&c="
        }

        Write-Host "URL Built: $URL"

        return $URL
    }

    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    if (-not (Test-Path $DestinationFolder -ErrorAction SilentlyContinue)) {
        Write-Host "Destination Folder does not exist! Creating directory..."
        New-Item $DestinationFolder -ItemType Directory
    }

    #Set the log file as a temporary file, it will be created in the temp folder of the context the script runs in (c:\windows\temp or c:\users\username\appdata\temp)
    $InstallerLogFile = [IO.Path]::GetTempFileName()
    Write-Host "Installer Log File location will be: $InstallerLogFile"
}
process {
    # Arguments required to download the file
    $DownloadArgs = @{ Path = "$DestinationFolder\$MSI" }
    if ($SkipSleep) { $DownloadArgs["SkipSleep"] = $True }

    # Build the arguments needed to create the url
    $ArgumentList = @{ Domain = $ScreenConnectDomain }
    if ($UseOrgName) { $ArgumentList["UseOrgName"] = $True }
    if ($UseLocation) { $ArgumentList["UseLocation"] = $True }
    if ($UseDeviceType) { $ArgumentList["UseDeviceType"] = $True }
    if ($Department) { $ArgumentList["Department"] = $Department }

    # Build the URL and get it ready for download
    $DownloadArgs["URL"] = Build-Url @ArgumentList

    # Download the installer
    Invoke-Download @DownloadArgs

    # Grab the installer file
    $InstallerFile = Join-Path -Path $DestinationFolder -ChildPath $MSI -Resolve

    # Define the name of the software we are searching for and look for it in both the 64 bit and 32 bit registry nodes
    $ProductName = "$(Get-ControlPanelName -msiPath $InstallerFile)".Trim()
    if (-not $ProductName) { 
        Write-Error "Failed to fetch the product name from the MSI at path '$InstallerFile'. Ensure the MSI path is correct and the MSI contains the necessary product information."
        exit 1
    }

    # If already installed, exit.
    $IsInstalled = Find-UninstallKey -DisplayName $ProductName
    if ($IsInstalled -and -not ($Force)) {
        Write-Host "$ProductName is already installed; exiting..."
        exit 0
    }

    # ScreenConnect install arguments
    $Arguments = "/c msiexec /i ""$InstallerFile"" /qn /norestart /l ""$InstallerLogFile"" REBOOT=REALLYSUPPRESS"

    # Install and let the user know the exit code
    $Process = Start-Process -Wait cmd -ArgumentList $Arguments -PassThru
    Write-Host "Exit Code: $($Process.ExitCode)";

    # Interpret the exit code
    switch ($Process.ExitCode) {
        0 { Write-Host "Success" }
        3010 { Write-Host "Success. Reboot required to complete installation" }
        1641 { Write-Host "Success. Installer has initiated a reboot" }
        default {
            Write-Error "Exit code does not indicate success"
            Get-Content $InstallerLogFile -ErrorAction SilentlyContinue | Select-Object -Last 50 | Write-Host
        }
    }

    exit $Process.ExitCode
    
}
end {
    
    
    
}


