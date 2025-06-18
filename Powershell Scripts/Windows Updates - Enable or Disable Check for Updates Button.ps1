# Disable or enable the Check for Updates button in Windows Update.
#Requires -Version 5.1

<#
.SYNOPSIS
    Disable or enable the 'Check for Updates' button in Windows Update.
.DESCRIPTION
    Disable or enable the 'Check for Updates' button in Windows Update.

.EXAMPLE
    -Action "Disable"
    
    Attempting to disable the 'Check for Updates' button.
    Set Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisableUXWUAccess to 1
    Successfully disabled the 'Check for Updates' button.

PARAMETER: -Action "Enable"
    Specify whether the 'Check for Updates' button should be accessible for all users of this machine.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action
)

begin {
    # If script form variables are used, replace the command line parameters with their value.
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }

    # Check if the $Action variable is set
    if ($Action) {
        $Action = $Action.Trim()
    }

    # If $Action is null or empty after trimming any leading and trailing whitespace, display an error message and exit
    if (!$Action) {
        Write-Host -Object "[Error] A valid action must be provided."
        exit 1
    }

    # Define a list of valid actions: "Enable" and "Disable"
    $ValidActions = "Enable", "Disable"
    
    # Check if the value of $Action is not in the list of valid actions
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] Invalid action '$Action' specified. Please specify either 'Enable' or 'Disable'."
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

    function Test-IsDomainController {
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
            Write-Host -Object "[Error] Unable to validate whether or not this device is a domain controller."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        # Check if the ProductType is "2", which indicates that the system is a domain controller
        if ($OS.ProductType -eq "2") {
            return $true
        }
    }

    function Test-IsDomainJoined {
        # Check the PowerShell version to determine the appropriate cmdlet to use
        try {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            }
            else {
                return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a part of a domain."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
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
    # Write an empty line to the console (placeholder or for spacing purposes)
    Write-Host -Object ""

    # Check if the script is running with elevated (administrator) privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the current device is either joined to a domain or is a domain controller
    if(Test-IsDomainJoined -or Test-IsDomainController){
        # Display a warning indicating that the device is joined to a domain
        Write-Host -Object "[Warning] This device is currently joined to a domain. This setting can be overridden by a group policy."

        # Display additional information about the group policy that can override the setting
        Write-Host -Object "[Warning] Computer Configuration > Administrative Templates > Windows Components > Windows Update > Remove access to use all Windows Update features."
    }

    # If the action is "Enable" and the specified registry path exists
    if ($Action -eq "Enable" -and (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue)) {
        try {
            # Attempt to retrieve the existing value for "SetDisableUXWUAccess" from the registry
            $ExistingValue = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction Stop | Select-Object -ExpandProperty "SetDisableUXWUAccess" -ErrorAction SilentlyContinue
        }
        catch {
            # Display an error message if retrieval fails and exit the script
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the existing 'Check for Updates' value."
            exit 1
        }
    }

    # Check if the action is "Enable"
    if ($Action -eq "Enable") {
        Write-Host -Object "Attempting to enable the 'Check for Updates' button."

        # If the registry value does not exist or is empty, the button is already enabled
        if (!$ExistingValue) {
            Write-Host -Object "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisableUXWUAccess was already removed."
        }

        # If the registry value exists, attempt to remove it to enable the button
        if ($ExistingValue) {
            try {
                # Remove the "SetDisableUXWUAccess" property from the registry
                Remove-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisableUXWUAccess" -ErrorAction Stop
                Write-Host -Object "Removed the registry key 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\SetDisableUXWUAccess'."
            }
            catch {
                # Display an error message if removal fails and exit the script
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to enable the 'Check for Updates' button."
                exit 1
            }
        }

        # Indicate success and exit the script
        Write-Host -Object "Successfully enabled the 'Check for Updates' button."
        exit $ExitCode
    }


    # Check if the action is "Disable"
    if ($Action -eq "Disable") {
        Write-Host -Object "Attempting to disable the 'Check for Updates' button."

        # Add or update the "SetDisableUXWUAccess" property in the registry to disable the button
        Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisableUXWUAccess" -Value 1 -PropertyType DWord

        # Indicate success
        Write-Host -Object "Successfully disabled the 'Check for Updates' button."
    }


    exit $ExitCode
}
end {
    
    
    
}
