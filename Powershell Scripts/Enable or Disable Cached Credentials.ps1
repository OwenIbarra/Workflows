# Enable or Disable Cached Credentials. This controls if the machine is allowed to login with cached credentials when it cannot contact a domain controller.
#Requires -Version 5.1

<#

.SYNOPSIS
    Enable or Disable Cached Credentials. This controls if the machine is allowed to login with cached credentials when it cannot contact a domain controller.

.DESCRIPTION
    Enable or Disable Cached Credentials. This controls if the machine is allowed to login with cached credentials when it cannot contact a domain controller.

.PARAMETER Enable
    Enable Cached Credentials.

.PARAMETER Disable
    Disable Cached Credentials.

.PARAMETER Count
    Number of previous logins to cache. Default is 10. Minimum is 1. Maximum is 50.

.EXAMPLE
    -Enable
    [Info] Enable Cached Credentials

.EXAMPLE
    -Disable
    [Info] Disable Cached Credentials

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release

#>

param (
    [switch]$Enable,
    [switch]$Disable,
    [int]$Count = 10
)

begin {
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
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
        # Create a WindowsPrincipal object based on the current identity
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    
        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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

    if (Test-IsDomainController) {
        Write-Host "[Error] This device is a domain controller. Cached credentials cannot be set."
        exit 1
    }
    elseif (!(Test-IsElevated)) {
        Write-Host "[Error] This script must be run with elevated privileges to disable cached credentials."
        exit 1
    }

    if (!(Test-IsDomainJoined)) {
        Write-Host "[Error] This device is not part of a domain. Cached credentials are not applicable."
        exit 1
    }

    if ($env:numberOfPreviousLoginsToCache) {
        try {
            $Count = [int]::Parse($env:numberOfPreviousLoginsToCache)
        }
        catch {
            Write-Host "[Error] Invalid value. Please provide a number ranging from 1 to 50."
            exit 1
        }
    }

    if ($env:action -and $env:action -eq "Enable") {
        $Enable = $true
    }
    elseif ($env:action -and $env:action -eq "Disable") {
        $Disable = $true
        $env:numberOfPreviousLoginsToCache = 0
    }
    elseif ($Enable -and $Disable) {
        Write-Host "[Error] Please specify either Enable or Disable."
        exit 1
    }
    else {
        Write-Host "[Error] Please specify either Enable or Disable."
        exit 1
    }

    if ($Disable) {
        $Count = 0
    }
    elseif ($Enable -and $($Count -le 0 -or $Count -gt 50)) {
        Write-Host "[Error] Invalid value. Please provide a number ranging from 1 to 50."
        exit 1
    }
}
process {

    try {
        Set-RegKey -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value $Count

        switch ($Count) {
            0 { Write-Host "[Info] Cached credentials disabled." }
            default { Write-Host "[Info] Cached credentials enabled with $Count previous logins cached." }
        }
    }
    catch {
        switch ($Count) {
            0 { Write-Host "[Error] Unable to disable cached credentials." }
            default { Write-Host "[Error] Unable to enable cached credentials." }
        }

        exit 1
    }
}
end {
    
    
    
}
