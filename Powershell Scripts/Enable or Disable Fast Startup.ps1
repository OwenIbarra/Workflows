# Enable or Disable Windows Fast Boot, also known as Hiberboot or Fast Startup.
<#
.SYNOPSIS
    Enable or Disable Windows Fast Boot, also known as Hiberboot or Fast Startup.
.DESCRIPTION
    Enable or Disable Windows Fast Boot, also known as Hiberboot or Fast Startup.
.OUTPUTS
    None
.NOTES
    Enabling will enable the option to hibernate as it is a requirement for Fast Boot.
    Disabling will disable the Fast Boot option only, leaving hibernation enabled.
    Disabling with the DisableHibernation switch will disable both Fast Boot and Hibernation.

    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Combines both Enable and Disable Fast Boot into a single script
#>
[CmdletBinding()]
param (
    [switch]$Enable,
    [switch]$Disable,
    [string]$DisableHibernation
)
begin {
    # Dropdown strings from Script Variables
    $EnableFastBoot = "Enable Fast Boot and Hibernation"
    $DisableFastBoot = "Disable Fast Boot"
    $DisableFastBootAndHibernation = "Disable Fast Boot and Hibernation"

    switch ($env:action) {
        $EnableFastBoot { $Enable = $true }
        $DisableFastBoot { $Disable = $true }
        $DisableFastBootAndHibernation { $Disable = $true; $DisableHibernation = $true }
        Default {
            if ((-not $Enable -and -not $Disable) -or ($Enable -and $Disable)) {
                Write-Host "[Error] Invalid action specified. Please specify either '$EnableFastBoot', '$DisableFastBoot', or '$DisableFastBootAndHibernation'."
                exit 1
            }
        }
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
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
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    if ($Enable) {
        # Enable Fast Boot
        Write-Host "[Info] Attempting to enable fastboot."
        try {
            $Value = "1"
            $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
            $Name = "HiberbootEnabled"
            Set-RegKey -Path $Path -Name $Name -Value $Value
            Write-Host "[Info] Fastboot enabled."
        }
        catch {
            Write-Host "[Error] Failed to disable Fast Boot."
            exit 1
        }
        # Enable Hibernation
        try {
            $HibernateValue = "1"
            $Path = "HKLM:\System\CurrentControlSet\Control\Power"
            $Name = "HibernateEnabled"
            Set-RegKey -Path $Path -Name $Name -Value $HibernateValue
            Write-Host "[Info] hibernation enabled."
        }
        catch {
            Write-Host "[Error] Failed to enable hibernation."
            exit 1
        }
    }
    elseif ($Disable) {
        # Disable Fast Boot
        try {
            $Value = "0"
            $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
            $Name = "HiberbootEnabled"
            Set-RegKey -Path $Path -Name $Name -Value $Value
            Write-Host "[Info] Fastboot disabled."
        }
        catch {
            Write-Host "[Error] Failed to disable Fast Boot."
            exit 1
        }

        if ($DisableHibernation) {
            # Disable Hibernation
            Write-Host "[Info] Attempting to disable fastboot and hibernation."
            try {
                $HibernateValue = "0"
                $Path = "HKLM:\System\CurrentControlSet\Control\Power"
                $Name = "HibernateEnabled"
                Set-RegKey -Path $Path -Name $Name -Value $HibernateValue
                Write-Host "[Info] hibernation disabled."
            }
            catch {
                Write-Host "[Error] Failed to enable hibernation."
                exit 1
            }
        }
    }
    else {
        Write-Host "[Error] Invalid action specified. Please specify either '$EnableFastBoot', '$DisableFastBoot', or '$DisableFastBootAndHibernation'."
        exit 1
    }
}
end {
    
    
    
}
