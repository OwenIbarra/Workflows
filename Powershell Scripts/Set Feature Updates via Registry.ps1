# Lock Windows Update to only request a specific feature update that you specify.
#Requires -Version 5.1

<#
.SYNOPSIS
    Lock Windows Update to only request a specific feature update that you specify.
.DESCRIPTION
    Lock Windows Update to only request a specific feature update that you specify.
.EXAMPLE
    -TargetReleaseVersion 23H2
    
    Checking https://endoflife.date/windows for the latest Windows build information.
    Parsing the response from https://endoflife.date/windows
    Retrieving the system's current Windows version.
    Verifying a newer release was specified.
    Verifying that the specified release is not end-of-life.

    Attempting to set the feature update lock via the registry.
    Set Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\TargetReleaseVersionInfo to 23H2
    Set Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\TargetReleaseVersion to 1
    Set Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ProductVersion to Windows 11

    Successfully set the target feature update to 23H2.
    [Warning] Windows Update will target this feature update from now on and will ignore other releases until this script is run again to update it.

PARAMETER: -TargetReleaseVersion "24H2"
    Specify either the release codename e.g. '24H2' or the build number e.g. '26100'.

PARAMETER: -ResetToDefaults
    Reset the target feature update lock back to the Windows defaults.

.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$TargetReleaseVersion,
    [Parameter()]
    [Switch]$ResetToDefaults = [System.Convert]::ToBoolean($env:resetToDefaults),
    [Parameter()]
    [String]$EndOfLifeURL = "https://endoflife.date/api/windows.json"
)

begin {
    # If script-form variables are used, replace the command-line parameters with their values.
    if ($env:targetVersion -and $env:targetVersion -notlike "null") { $TargetReleaseVersion = $env:targetVersion }

    # Prevent specifying both a target release and the reset option at the same time.
    if ($TargetReleaseVersion -and $ResetToDefaults) {
        Write-Host -Object "[Error] Windows does not target a release by default. Do not specify a release if you would like to reset to the default."
        exit 1
    }

    # Trim any extra whitespace from the specified release version (if provided).
    if ($TargetReleaseVersion) {
        $TargetReleaseVersion = $TargetReleaseVersion.Trim()
    }

    # Require a release if not resetting to defaults; otherwise display an error and exit.
    if (!$TargetReleaseVersion -and !$ResetToDefaults) {
        Write-Host -Object "[Error] You must provide a release to target. You can view the currently supported releases here: https://aka.ms/WindowsTargetVersioninfo"
        Write-Host -Object "[Error] Expected either a release codename (24H2) or a build number (26100) to target."
        exit 1
    }

    # Validate the target release version, ensuring no invalid characters.
    if ($TargetReleaseVersion -and $TargetReleaseVersion -match "[^A-Z0-9]") {
        Write-Host -Object "[Error] A target release version with an invalid character was provided '$TargetReleaseVersion'. Please specify either a release codename (e.g., '24H2') or a build number (e.g., '26100')."
        Write-Host -Object "[Error] You can view the currently supported releases here: https://aka.ms/WindowsTargetVersioninfo"
        exit 1
    }

    # Determine the method to retrieve the operating system information based on PowerShell version.
    try {
        $OS = if ($PSVersionTable.PSVersion.Major -lt 3) {
            Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        }else {
            Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        }
    }
    catch {
        # If the above retrieval fails, display an error message and exit.
        Write-Host -Object "[Error] Unable to retrieve information about the current operating system."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }
    
    # Check if the system is running Windows 10 or Windows 11. If not, display an error message and exit.
    if ($OS.Caption -notmatch "Windows 10" -and $OS.Caption -notmatch "Windows 11") {
        Write-Host -Object "[Error] This device is not currently running Windows 10 or Windows 11. It is currently running '$($OS.Caption)'."
        exit 1
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
    # Check if the script is running with elevated privileges (administrator rights).
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # If the user has requested to reset Windows Update feature lock to defaults, remove the corresponding registry keys.
    if ($ResetToDefaults) {
        Write-Host -Object "Attempting to reset the feature update lock back to the Windows default via the registry.`n"

        # Check if the registry path exists. If it doesn't, show that the keys have been removed and exit.
        $RegistryKeyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (!(Test-Path -Path $RegistryKeyPath -ErrorAction SilentlyContinue)) {
            Write-Host -Object "The registry key '$RegistryKeyPath\TargetReleaseVersionInfo' has already been removed."
            Write-Host -Object "The registry key '$RegistryKeyPath\TargetReleaseVersion' has already been removed."
            Write-Host -Object "The registry key '$RegistryKeyPath\ProductVersion' has already been removed."

            # Announce success and exit.
            Write-Host -Object "`nSuccessfully reset the feature update lock back to the default."
            exit $ExitCode
        }

        # Attempt to retrieve registry properties (if they exist).
        $InfoKey = Get-ItemProperty -Path $RegistryKeyPath -Name "TargetReleaseVersionInfo" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TargetReleaseVersionInfo -ErrorAction SilentlyContinue
        $VersionKey = Get-ItemProperty -Path $RegistryKeyPath -Name "TargetReleaseVersion" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TargetReleaseVersion -ErrorAction SilentlyContinue
        $ProductKey = Get-ItemProperty -Path $RegistryKeyPath -Name "ProductVersion" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProductVersion -ErrorAction SilentlyContinue

        # Remove TargetReleaseVersionInfo if it exists.
        if ($InfoKey) {
            try {
                Write-Host -Object "Removing the registry key '$RegistryKeyPath\TargetReleaseVersionInfo'."
                Remove-ItemProperty -Path $RegistryKeyPath -Name "TargetReleaseVersionInfo" -ErrorAction Stop
                Write-Host -Object "Successfully removed the registry key."
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to remove the registry key '$RegistryKeyPath\TargetReleaseVersionInfo'"
                exit 1
            }
        }
        else {
            Write-Host -Object "The registry key '$RegistryKeyPath\TargetReleaseVersionInfo' has already been removed."
        }

        # Remove TargetReleaseVersion if it exists.
        if ($VersionKey) {
            try {
                Write-Host -Object "Removing the registry key '$RegistryKeyPath\TargetReleaseVersion'."
                Remove-ItemProperty -Path $RegistryKeyPath -Name "TargetReleaseVersion" -ErrorAction Stop
                Write-Host -Object "Successfully removed the registry key."
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to remove the registry key '$RegistryKeyPath\TargetReleaseVersion'"
                exit 1
            }
        }
        else {
            Write-Host -Object "The registry key '$RegistryKeyPath\TargetReleaseVersion' has already been removed."
        }

        # Remove ProductVersion if it exists.
        if ($ProductKey) {
            try {
                Write-Host -Object "Removing the registry key '$RegistryKeyPath\ProductVersion'."
                Remove-ItemProperty -Path $RegistryKeyPath -Name "ProductVersion" -ErrorAction Stop
                Write-Host -Object "Successfully removed the registry key."
            }
            catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to remove the registry key '$RegistryKeyPath\ProductVersion'"
                exit 1
            }
        }
        else {
            Write-Host -Object "The registry key '$RegistryKeyPath\ProductVersion' has already been removed."
        }

        # Announce success and exit.
        Write-Host -Object "`nSuccessfully reset the feature update lock back to the default."
        exit $ExitCode
    }


    # Inform the user about the URL being checked
    Write-Host -Object "Checking https://endoflife.date/windows for the latest Windows build information."
    try {
        # Determine the supported TLS versions and set the appropriate security protocol
        # Prefer Tls13 and Tls12 if both are available, otherwise just Tls12, or warn if unsupported.
        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }else {
            # Warn the user if TLS 1.2 and 1.3 are not supported, which may cause the get request to fail
            Write-Host -Object "[Warning] TLS 1.2 and/or TLS 1.3 are not supported on this system. This operation may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Host -Object "[Warning] PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }
        
        # Invoke a REST call to retrieve JSON data about Windows builds
        $EndOfLifeResponse = Invoke-RestMethod -Method Get -Uri $EndOfLifeURL -ContentType "application/json" -MaximumRedirection 10 -UseBasicParsing -ErrorAction Stop
    
        # Filter the JSON response for Windows builds (cycles that match '11-' or '10-' and end in 'w')
        switch -regex ($OS.Caption) {
            "Windows 11" { $WindowsBuildJSON = $EndOfLifeResponse | Where-Object { $_.Cycle -match '^11-' } }
            "Windows 10" { $WindowsBuildJSON = $EndOfLifeResponse | Where-Object { $_.Cycle -match '^10-' } }
        }

        # Filter the JSON response for Windows builds (Cycles that match the edition of the OS)
        switch -regex ($OS.Caption) {
            "LTS" { $WindowsBuildJSON = $WindowsBuildJSON | Where-Object { $_.Cycle -match "lts$" -or $_.Cycle -match "\d$" } }
            "Enterprise" { $WindowsBuildJSON = $WindowsBuildJSON | Where-Object { $_.Cycle -match "e$" -or $_.Cycle -match "\d$" } }
            default { $WindowsBuildJSON = $WindowsBuildJSON | Where-Object { $_.Cycle -match "w$" -or $_.Cycle -match "\d$" } }
        }
    
        # Throw an error if no Windows builds are found
        if (!$WindowsBuildJSON) {
            throw "No Windows builds found in the response."
        }
    }
    catch {
        # Catch any errors from the REST call or the filtering process
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to retrieve the latest Windows build information from $EndOfLifeURL."
        exit 1
    }
    
    # Inform the user that the response will be parsed
    Write-Host -Object "Parsing the response from https://endoflife.date/windows"
    
    # Create a list to store all relevant Windows build information
    $WindowsBuilds = New-Object System.Collections.Generic.List[Object]
    
    $ErrorActionPreference = "Stop"
    
    # Iterate through each Windows build JSON object
    $WindowsBuildJSON | ForEach-Object {
        try {
            # Extract major, minor, and build numbers from the 'latest' version string
            $Major = $_.latest -replace '^(\d+)\.(\d+)\.(\d+)$', '$1'
            $Minor = $_.latest -replace '^(\d+)\.(\d+)\.(\d+)$', '$2'
            $Build = $_.latest -replace '^(\d+)\.(\d+)\.(\d+)$', '$3'
    
            # Construct a custom PowerShell object for each build
            $WindowBuild = [PSCustomObject]@{
                cycle        = $_.cycle
                releaseLabel = $($_.releaseLabel -replace '^(\d+) ([0-9A-Z]+).*$', '$2')
                releaseDate  = Get-Date $_.releaseDate
                eol          = Get-Date $_.eol
                version      = $_.latest
                major        = $Major
                minor        = $Minor
                build        = $Build
                link         = $_.link
                lts          = $_.lts
                support      = Get-Date $_.support
            }
    
            # Add the newly created object to the Windows builds collection
            $WindowsBuilds.Add($WindowBuild)
        }
        catch {
            # Capture any errors in parsing the date or version properties
            Write-Host -Object "[Warning] $($_.Exception.Message)"
            Write-Host -Object "[Warning] Failed to parse the date for the build $($_.releaseLabel)."
            return
        }
    }
    $ErrorActionPreference = "Continue"
    
    # If no Windows builds were successfully parsed, show an error and exit
    if ($WindowsBuilds.Count -lt 1) {
        Write-Host -Object "[Error] Failed to parse any of the Windows builds."
        exit 1
    }

    # Sort the Windows build objects by release date in descending order
    $WindowsBuilds = $WindowsBuilds | Sort-Object releaseDate -Descending
    
    # Check if the user-specified target release exists in either the releaseLabel or build properties.
    if ($WindowsBuilds.releaseLabel -notcontains $TargetReleaseVersion -and $WindowsBuilds.build -notcontains $TargetReleaseVersion) {
        Write-Host -Object "[Error] '$TargetReleaseVersion' is not a valid release. Please specify either the codename or build for a valid release."
        Write-Host -Object "[Error] For more information: https://aka.ms/WindowsTargetVersioninfo"
        Write-Host -Object "### Valid Releases ###"
        ($WindowsBuilds | Where-Object { $_.build -ge [System.Environment]::OSVersion.Version.Build -and $_.eol -ge (Get-Date) } | Format-Table @{ Label = "Codename"; Expression = { $_.releaseLabel } }, 
        @{ Label = "Build"; Expression = { $_.build } }, 
        @{ Label = "Release Date"; Expression = { $_.releaseDate.ToShortDateString() } } ,
        @{ Label = "End of Life Date"; Expression = { $_.eol.ToShortDateString() } }-AutoSize | Out-String).Trim() | Write-Host
        exit 1
    }

    # If the user has specified a build number, map it to a release codename (releaseLabel).
    if ($TargetReleaseVersion -notmatch "[A-Z]" -and $WindowsBuilds.releaseLabel -notcontains $TargetReleaseVersion) {
        $TargetReleaseVersion = $WindowsBuilds | Where-Object { $_.build -eq $TargetReleaseVersion } | Select-Object -ExpandProperty releaseLabel -ErrorAction SilentlyContinue
    }

    # Retrieve the current Windows version from the registry to compare against the target version.
    Write-Host -Object "Retrieving the system's current Windows version."
    try {
        $CurrentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop | Select-Object -ExpandProperty DisplayVersion -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to retrieve the latest feature update installed."
        exit 1
    }

    # Verify that the user chose a newer release than what is currently installed.
    Write-Host -Object "Verifying a newer release was specified."
    $TargetReleaseBuild = $WindowsBuilds | Where-Object { $_.releaseLabel -eq $TargetReleaseVersion } | Select-Object -ExpandProperty build -ErrorAction SilentlyContinue
    if ($TargetReleaseBuild -lt [System.Environment]::OSVersion.Version.Build) {
        Write-Host -Object "[Error] The system currently has $CurrentVersion installed, which is newer than the targeted release. Please target a newer release."
        Write-Host -Object "[Error] For more information: https://aka.ms/WindowsTargetVersioninfo"
        Write-Host -Object "### Valid Releases ###"
        ($WindowsBuilds | Where-Object { $_.build -ge [System.Environment]::OSVersion.Version.Build -and $_.eol -ge (Get-Date) } | Format-Table @{ Label = "Codename"; Expression = { $_.releaseLabel } }, 
        @{ Label = "Build"; Expression = { $_.build } }, 
        @{ Label = "Release Date"; Expression = { $_.releaseDate.ToShortDateString() } } ,
        @{ Label = "End of Life Date"; Expression = { $_.eol.ToShortDateString() } }-AutoSize | Out-String).Trim() | Write-Host
        exit 1
    }

    # Verify that the user chose a release than what is currently supported.
    Write-Host -Object "Verifying that the specified release is not end-of-life."
    $TargetReleaseSupportDate = $WindowsBuilds | Where-Object { $_.releaseLabel -eq $TargetReleaseVersion } | Select-Object -ExpandProperty eol -ErrorAction SilentlyContinue
    if ($TargetReleaseSupportDate -lt (Get-Date)) {
        Write-Host -Object "[Error] The targeted release '$TargetReleaseVersion' is no longer supported as of $($TargetReleaseSupportDate.ToShortDateString()). Please target a newer release."
        Write-Host -Object "[Error] For more information: https://aka.ms/WindowsTargetVersioninfo"
        Write-Host -Object "### Valid Releases ###"
        ($WindowsBuilds | Where-Object { $_.build -ge [System.Environment]::OSVersion.Version.Build -and $_.eol -ge (Get-Date) } | Format-Table @{ Label = "Codename"; Expression = { $_.releaseLabel } }, 
        @{ Label = "Build"; Expression = { $_.build } }, 
        @{ Label = "Release Date"; Expression = { $_.releaseDate.ToShortDateString() } } ,
        @{ Label = "End of Life Date"; Expression = { $_.eol.ToShortDateString() } }-AutoSize | Out-String).Trim() | Write-Host
        exit 1
    }

    try {
        # Announce setting the feature update lock and define the registry path for the update policies.
        Write-Host -Object "`nAttempting to set the feature update lock via the registry."
        $RegistryKeyPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

        # Set registry values to lock in the chosen Windows release (TargetReleaseVersionInfo).
        Set-RegKey -Path $RegistryKeyPath -Name "TargetReleaseVersionInfo" -Value $TargetReleaseVersion -PropertyType String
        Set-RegKey -Path $RegistryKeyPath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord

        # Based on the OS caption, update the ProductVersion key.
        switch -regex ($OS.Caption) {
            "Windows 11" { Set-RegKey -Path $RegistryKeyPath -Name "ProductVersion" -Value "Windows 11" -PropertyType String }
            "Windows 10" { Set-RegKey -Path $RegistryKeyPath -Name "ProductVersion" -Value "Windows 10" -PropertyType String }
        }

        # Inform the user that the feature update has been successfully locked to the chosen version.
        Write-Host -Object "`nSuccessfully set the target feature update to $TargetReleaseVersion."
        Write-Host -Object "[Warning] Windows Update will target this feature update from now on and will ignore other releases until this script is run again to update it."
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to set the target release."
        exit 1
    }

    exit $ExitCode
}
end {
    
    
    
}
