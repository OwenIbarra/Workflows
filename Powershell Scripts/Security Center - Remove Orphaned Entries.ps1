# Remove a specified Security Center entry if the antivirus is not installed. You can get the antivirus name/Security Center entry in Ninja by navigating to Details > Antivirus.
#Requires -Version 5.1

<#
.SYNOPSIS
    Remove a specified Security Center entry if the antivirus is not installed. You can get the antivirus name/Security Center entry in Ninja by navigating to Details > Antivirus.
.DESCRIPTION
    Remove a specified Security Center entry if the antivirus is not installed. You can get the antivirus name/Security Center entry in Ninja by navigating to Details > Antivirus.
.EXAMPLE
    -AntivirusName "VIPRE Business Agent"
    Checking Add and Remove Programs for 'VIPRE Business Agent'.
    Verifying that 'VIPRE Business Agent' does not exist at path 'C:\Program Files\VIPRE Business Agent\SBAMWSC.EXE'.
    Verifying that 'VIPRE Business Agent' does not exist at path 'C:\Program Files\VIPRE Business Agent\ViprePPLSvc.exe'.
    Removing 'VIPRE Business Agent' from the Security Center.
    Successfully removed 'VIPRE Business Agent' from the Security Center.

PARAMETER: -AntivirusName "ReplaceMeWithTheNameOfTheAntivirusToRemove"
    Specify the name of the Security Center entry you would like to remove.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$AntivirusName
)

begin {
    # If script form variables are used, replace the command line parameters with their value.
    if ($env:antivirusName -and $env:antivirusName -notlike "null") { $AntivirusName = $env:antivirusName }

    function Test-IsServer {
        # Determine the method to retrieve the operating system information based on PowerShell version
        try {
            $OS = if ($PSVersionTable.PSVersion.Major -lt 5) {
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
    
        # Check if the ProductType is "2" or "3", which indicates that the system is a server
        if ($OS.ProductType -eq "2" -or $OS.ProductType -eq "3") {
            return $true
        }
    }

    # If the script is run on a server, display an error message and exit
    if (Test-IsServer) {
        Write-Host -Object "[Error] The Windows Security Center is not present on Windows Server."
        exit 1
    }

    # If $AntivirusName exists, trim any leading or trailing whitespace.
    if ($AntivirusName) {
        $AntivirusName = $AntivirusName.Trim()
    }

    # If $AntivirusName is still not set or empty after the previous checks, display an error and exit the script.
    if (!$AntivirusName) {
        Write-Host -Object "[Error] Please provide a valid antivirus name."
        exit 1
    }

    # Try to retrieve the Security Center entries for antivirus products
    try {
        $SecurityCenterEntries = Get-WmiObject -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction Stop
    }
    catch {
        # If there is an error retrieving the Security Center entries, output an error message and exit the script.
        Write-Host -Object "[Error] Failed to retrieve any antivirus entries from the Security Center."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Check if no Security Center entries were found or if the number of entries is less than 1, then output an error and exit.
    if (!$SecurityCenterEntries -or ($SecurityCenterEntries.displayName | Measure-Object | Select-Object -ExpandProperty Count) -lt 1) {
        Write-Host -Object "[Error] No antivirus entries found in the Security Center."
        exit 1
    }

    # Check if the antivirus name provided does not exist in the Security Center entries.
    if ($SecurityCenterEntries.displayName -notcontains $AntivirusName) {
        Write-Host -Object "[Error] An invalid antivirus name was specified. Please specify one of the following valid antivirus names: " -NoNewline
        Write-Host -Object $SecurityCenterEntries.displayName -Separator ", "
        exit 1
    }

    function Find-InstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString,
            [Parameter()]
            [String]$UserBaseKey
        )
        process {
            # Initialize a list to store found installation keys
            $InstallList = New-Object System.Collections.Generic.List[Object]
    
            # If no custom user base key is provided, search in the standard HKLM paths
            if (!$UserBaseKey) {
                # Search in the 32-bit uninstall registry key and add results to the list
                $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
    
                # Search in the 64-bit uninstall registry key and add results to the list
                $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
            else {
                # If a custom user base key is provided, search in the corresponding Wow6432Node path and add results to the list
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
    
                # Search in the custom user base key for the standard uninstall path and add results to the list
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
    
            # If the UninstallString switch is set, return only the UninstallString property of the found keys
            if ($UninstallString) {
                $InstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $InstallList
            }
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
    # Check if the script is being run with elevated (administrator) privileges.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Inform the user that the script is checking Add and Remove Programs for the specified antivirus.
    Write-Host -Object "Checking Add and Remove Programs for '$AntivirusName'."

    # Call the Find-InstallKey function to check if the antivirus is installed by its display name.
    $IsInstalled = Find-InstallKey -DisplayName $AntivirusName

    # If the antivirus is found to be installed, display an error and exit the script.
    if ($IsInstalled) {
        Write-Host -Object "[Error] '$AntivirusName' is currently installed. Unable to remove the entry from the Security Center."
        exit 1
    }

    # Retrieve the Security Center entries that match the specified antivirus name.
    $EntryToRemove = $SecurityCenterEntries | Where-Object { $_.displayName -like $AntivirusName }

    # Loop through the matched Security Center entries to process each one.
    $EntryToRemove | ForEach-Object {
        # Retrieve the paths for the signed product executable and reporting executable.
        $SignedExe = $_.pathToSignedProductExe
        $SignedReportingExe = $_.pathToSignedReportingExe

        if ($SignedExe) {
            Write-Host -Object "Verifying that '$AntivirusName' does not exist at path '$SignedExe'."
        }

        # If the signed product executable path contains environment variables (denoted by '%' signs), attempt to expand them to their full path using the Environment class.
        if ($SignedExe -and $SignedExe -match '%.*%') {
            try {
                $ErrorActionPreference = "Stop"
                $SignedExe = [Environment]::ExpandEnvironmentVariables($SignedExe)
                $ErrorActionPreference = "Continue"
            }
            catch {
                Write-Host -Object "[Error] Failed to expand environment variable in '$($_.pathToSignedProductExe)'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }

        # If the path for the signed reporting executable exists, print a message indicating the verification of its presence.
        if ($SignedReportingExe) {
            Write-Host -Object "Verifying that '$AntivirusName' does not exist at path '$SignedReportingExe'."
        }
        
        # If the signed reporting executable path contains environment variables, attempt to expand them.
        if ($SignedReportingExe -and $SignedReportingExe -match '%.*%') {
            try {
                $ErrorActionPreference = "Stop"
                $SignedReportingExe = [Environment]::ExpandEnvironmentVariables($SignedReportingExe)
                $ErrorActionPreference = "Continue"
            }
            catch {
                Write-Host -Object "[Error] Failed to expand environment variable in '$($_.pathToSignedReportingExe)'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
        
        # If the signed product executable still exists at the expanded path, output an error and exit the script.
        if ($SignedExe -and (Test-Path -Path $SignedExe -ErrorAction SilentlyContinue)) {
            Write-Host -Object "[Error] '$AntivirusName' is currently installed at '$SignedExe'. Unable to remove the entry."
            exit 1
        }

        # If the signed reporting executable still exists at the expanded path, output an error and exit the script.
        if ($SignedReportingExe -and (Test-Path -Path $SignedReportingExe -ErrorAction SilentlyContinue)) {
            Write-Host -Object "[Error] '$AntivirusName' is currently installed at '$SignedReportingExe'. Unable to remove the entry."
            exit 1
        }
    }

    # After verifying that the antivirus is not installed at the specified paths, proceed to remove the entries from the Security Center.
    Write-Host -Object "Removing '$AntivirusName' from the Security Center"

    # Loop through each entry in $EntryToRemove and attempt to delete it.
    $EntryToRemove | ForEach-Object {
        try {
            $ErrorActionPreference = "Stop"
            $_.Delete()
            $ErrorActionPreference = "Continue"

            Write-Host -Object "Successfully removed '$AntivirusName' from the Security Center."
        }
        catch {
            Write-Host -Object "[Error] Failed to remove '$AntivirusName' from the Security Center."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}
