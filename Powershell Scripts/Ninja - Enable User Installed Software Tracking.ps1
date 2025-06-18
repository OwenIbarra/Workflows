# Adds or removes the necessary registry entries to enable Ninja to track software installed under the user context.

<#
.SYNOPSIS
    Adds or removes the necessary registry entries to enable Ninja to track software installed under the user context.
.DESCRIPTION
    Adds or removes the necessary registry entries to enable Ninja to track software installed under the user context.
.EXAMPLE
    (No Parameters)
    Enabling the tracking of software installed in the user context.
    Set Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent\Agent\EnableUserSpecificAppMonitor to 1
    Successfully enabled the tracking of software installed in the user context.

PARAMETER: -Action "ReplaceMeWithDesiredAction"
    Specify whether or not to enable or disable the tracking of software installed under the user context.
    Valid actions include "Enable" and "Disable".

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action = "Enable"
)

begin {
    # If script form variables are used, replace the command line parameters with the form variable value.
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }

    # If $Action has been set, trim any leading or trailing whitespace.
    if ($Action) {
        $Action = $Action.Trim()
    }

    # If $Action is not defined after the previous steps, display an error message and exit with an error code.
    if (!$Action) {
        Write-Host -Object "[Error] You must specify an action (Enable or Disable)."
        exit 1
    }

    # Define a list of valid actions: "Enable" and "Disable".
    $ValidActions = "Enable", "Disable"

    # Check if the value of $Action is not in the list of valid actions.
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] The action '$Action' is invalid. 'Enable' or 'Disable' are the only valid actions."
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
    # Check if the script is being run with elevated (administrator) privileges.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the NinjaRMM registry paths exist.
    # If neither exists, display an error message and exit, as the registry paths are required.
    if (!(Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent\Agent" -ErrorAction SilentlyContinue) -and !(Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\NinjaRMM LLC\NinjaRMMAgent\Agent" -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] The registry path 'HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent\Agent' or 'HKEY_LOCAL_MACHINE\SOFTWARE\NinjaRMM LLC\NinjaRMMAgent\Agent' is expected to exist. You may need to reinstall the agent."
        exit 1
    }

    # Define the registry key name that controls the user-specific app monitoring.
    $AppMonitorRegistryKeyName = "EnableUserSpecificAppMonitor"

    # Define an array of registry paths where the NinjaRMM agent settings could be stored.
    # These paths include both the 64-bit and 32-bit registry paths.
    $NinjaAgentRegistryPaths = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\NinjaRMM LLC\NinjaRMMAgent\Agent", "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent\Agent"

    # Determine the action (Enable or Disable) and output a message accordingly.
    switch ($Action) {
        "Enable" { 
            Write-Host -Object "Enabling the tracking of software installed in the user context." 
        }
        "Disable" {
            Write-Host -Object "Disabling the tracking of software installed in the user context."
        }
    }

    # Iterate over each possible registry path to configure the NinjaRMM agent settings.
    $NinjaAgentRegistryPaths | ForEach-Object {
        # Current registry path in the iteration.
        $NinjaAgentRegistryPath = $_

        # If the current registry path does not exist, skip it and move to the next one.
        if (!(Test-Path -Path $NinjaAgentRegistryPath -ErrorAction SilentlyContinue)) {
            return
        }

        # Retrieve the current value of the "EnableUserSpecificAppMonitor" registry key, if it exists.
        $UserSpecificMonitor = Get-ItemProperty -Path $NinjaAgentRegistryPath -Name $AppMonitorRegistryKeyName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $AppMonitorRegistryKeyName

        # Based on the action (Enable or Disable), perform the respective changes.
        switch ($Action) {
            "Enable" {
                # If the key is already set to "1" (enabled), inform the user and skip the rest.
                if ($UserSpecificMonitor -eq "1") {
                    Write-Host -Object "The user specific monitor is already enabled at path '$NinjaAgentRegistryPath\$AppMonitorRegistryKeyName'."
                    return
                }

                # Set the "EnableUserSpecificAppMonitor" registry key to "1" (enabled).
                Set-RegKey -Path $NinjaAgentRegistryPath -Name $AppMonitorRegistryKeyName -PropertyType "String" -Value "1"
                Write-Host -Object "Successfully enabled the tracking of software installed in the user context."
            }
            "Disable" {
                # If the key is not set or already disabled, inform the user and skip the rest.
                if (!$UserSpecificMonitor) {
                    Write-Host -Object "The user specific monitor is already disabled at path '$NinjaAgentRegistryPath\$AppMonitorRegistryKeyName'."
                    return
                }

                # Attempt to remove the "EnableUserSpecificAppMonitor" registry key.
                try {
                    Remove-ItemProperty -Path $NinjaAgentRegistryPath -Name $AppMonitorRegistryKeyName -ErrorAction Stop
                    Write-Host -Object "$NinjaAgentRegistryPath\$AppMonitorRegistryKeyName was successfully removed."
                }
                catch {
                    # If the removal fails, display an error message and exit with an error code.
                    Write-Host -Object "[Error] Failed to remove '$AppMonitorRegistryKeyName' from '$NinjaAgentRegistryPath'"
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    exit 1
                }
            }
        }
    }

    # Exit the script with the final exit code.
    exit $ExitCode
}
end {
    
    
    
}
