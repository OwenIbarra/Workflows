# Enable Optional Windows Features on Workstations.
#Requires -Version 5.1

<#

.SYNOPSIS
    Enable Optional Windows Features on Workstations.

.DESCRIPTION
    Enable Optional Windows Features on Workstations.

.PARAMETER GetFeatureNameList
    If selected, the script will list all available features to enable.

.PARAMETER FeatureNameToInstall
    The name of the feature to enable.

.PARAMETER RestartIfNeeded
    If selected, the system will RestartIfNeeded after enabling the feature.

.EXAMPLE
    -FeatureNameToInstall "Windows-Identity-Foundation"
    [Info] Enabling Windows-Identity-Foundation

.EXAMPLE
    -GetFeatureNameList
    [Info] The following features are available to enable:
    SimpleTCP
    Windows-Identity-Foundation
    WCF-HTTP-Activation
    WCF-NonHTTP-Activation
    WCF-HTTP-Activation45
    WCF-TCP-Activation45
    WCF-Pipe-Activation45
    WCF-MSMQ-Activation45
    DataCenterBridging
    Windows-Defender-Default-Definitions


.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Initial Release

#>

param (
    [switch]$GetFeatureNameList,
    [string]$FeatureNameToInstall,
    [switch]$RestartIfNeeded,
    [switch]$InstallParentOrDefaultFeatures
)

begin {
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
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
        # Create a WindowsPrincipal object based on the current identity
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    
        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Set-Feature {
        param (
            [string]$FeatureName
        )
        $script:ShouldRestart = $false

        $Splat = @{
            Online      = $true
            FeatureName = $FeatureName
            All         = $InstallParentOrDefaultFeatures
            NoRestart   = $true
            ErrorAction = 'Stop'
        }

        try {
            # Enable the Windows Optional Feature
            Write-Host -Object "[Info] Enabling $FeatureName"
            if ($RestartIfNeeded) {
                $(Enable-WindowsOptionalFeature @Splat -WarningVariable warn -ErrorVariable err -InformationVariable info -WarningAction SilentlyContinue) | Where-Object {
                    $_.RestartNeeded
                } | ForEach-Object {
                    $script:ShouldRestart = $true
                } | Out-Null
            }
            else {
                $(Enable-WindowsOptionalFeature @Splat -WarningVariable warn -ErrorVariable err -InformationVariable info -WarningAction SilentlyContinue) | Out-Null
            }
            Write-Host -Object "[Info] Enabled $FeatureName"
        }
        catch {
            Write-Host -Object "[Error] Unable to enable $FeatureName"
            if ($err) {
                Write-Host -Object "[Error] $($err.Exception.Message)"
            }
            else {
                Write-Host -Object "[Error] $($_.Exception.Message)"
            }
            exit 1
        }
        return $script:ShouldRestart
    }

    # List of features to exclude for security reasons
    $FeaturesToExclude = @(
        "SMB1Protocol",
        "SMB1Protocol-Client",
        "SMB1Protocol-Server",
        "TelnetClient",
        "TFTP",
        "IIS-FTPServer",
        "IIS-FTPSvc",
        "DirectPlay",
        "MicrosoftWindowsPowerShellV2",
        "MicrosoftWindowsPowerShellV2Root",
        "LegacyComponents",
        "IIS-CGI",
        "IIS-ASP",
        "IIS-ISAPIExtensions",
        "IIS-LegacyScripts",
        "IIS-LegacySnapIn",
        "Printing-Foundation-LPDPrintService",
        "Printing-Foundation-LPDPortMonitor",
        "Containers-HNS",
        "Containers-SDN",
        "Printing-Foundation-LPRPortMonitor",
        "SMB1Protocol-Deprecation"
    )

    function Get-FeatureNameList {
        $FeatureList = Get-WindowsOptionalFeature -Online | 
            Where-Object { $_.State -eq "Disabled" -and $_.FeatureName -notin $FeaturesToExclude } |
            Select-Object -ExpandProperty FeatureName
        return $FeatureList
    }

    # Check if the script is running as an administrator or the SYSTEM account
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] This script must be run as an administrator or SYSTEM."
        exit 1
    }

    # Check if the device is a server
    if (Test-IsServer) {
        Write-Host "[Error] This device is a server. Optional Windows Features are only available on Windows 10, 11 and above."
        exit 1
    }

    if ($env:getFeatureNameList -and $env:getFeatureNameList -eq "true") {
        $GetFeatureNameList = $true
    }

    if ($env:featureNameToInstall -and $env:featureNameToInstall -ne "null") {
        $FeatureNameToInstall = $env:featureNameToInstall
    }

    if ($env:restartIfNeeded -and $env:restartIfNeeded -eq "true") {
        $RestartIfNeeded = $true
    }

    if ($env:installParentOrDefaultFeatures -and $env:installParentOrDefaultFeatures -eq "true") {
        $InstallParentOrDefaultFeatures = $true
    }


    if ($GetFeatureNameList -and $FeatureNameToInstall) {
        Write-Host "[Error] The Get Feature Name List and Feature Name To Install parameters cannot be used together."
        exit 1
    }

    # Check if the feature to enable is in the list of features to exclude and exit if it is
    if ($FeatureNameToInstall -and $FeaturesToExclude -contains $FeatureNameToInstall) {
        Write-Host "[Error] The feature $FeatureNameToInstall cannot be enabled due to high security risk."
        exit 1
    }

}

process {

    if ($GetFeatureNameList) {
        # List all available features that can be enabled
        Write-Host "[Info] The following features are available to enable:"
        Get-FeatureNameList | Sort-Object | ForEach-Object { Write-Host "$_" }
    }
    elseif ($FeatureNameToInstall) {

        # Check if the feature to enable is available
        if ($FeatureNameToInstall -notin (Get-FeatureNameList)) {
            Write-Host "[Error] The feature $FeatureNameToInstall is not available to enable. Either is not a valid feature or is already enabled."
            exit 1
        }

        # Enable the feature
        if ($(Set-Feature -FeatureName $FeatureNameToInstall)) {
            if ($RestartIfNeeded) {
                Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
                Write-Host "[Info] The system will restart in 60 seconds."
            }
            else {
                Write-Host "[Info] Restart is needed."
            }
        }
        else {
            $exitCode = 0
            Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq $FeatureNameToInstall } | ForEach-Object {
                if ($_.State -eq "Enabled") {
                    Write-Host "[Info] The feature $FeatureNameToInstall is already enabled."
                }
                else {
                    Write-Host "[Error] The feature $FeatureNameToInstall could not be enabled."
                    $exitCode = 1
                }
            }
            exit $exitCode
        }
    }
}

end {
    
    
    
}

