# Enables long file paths on Windows.
<#
.SYNOPSIS
    Enables long file paths on Windows.
.DESCRIPTION
    Enables long file paths on Windows.
    This script will enable long file paths on Windows and optionally restart the computer.

PARAMETER:
    (No Parameters)
.EXAMPLE
    (No Parameters)

    [Info] Attempting to enable long file paths on Windows.
    [Info] Successfully enabled long file paths on Windows.

PARAMETER: -Reboot
    Reboots the computer after enabling long file paths.
.EXAMPLE
    -Reboot

    [Info] Attempting to enable long file paths on Windows.
    [Info] Successfully enabled long file paths on Windows.
    [Info] Restarting computer.

.LINK
    https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$Reboot
)

begin {
    if ($env:reboot -and $env:reboot -like "true") { $Reboot = $True }

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
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    try {
        Write-Host "[Info] Attempting to enable long file paths on Windows."
        Set-RegKey -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 -ErrorAction Stop
        Write-Host "[Info] Successfully enabled long file paths on Windows."
    }
    catch {
        Write-Host "[Error] Failed to enable long file paths."
        exit 1
    }

    if ($Reboot) {
        try {
            Write-Host "[Info] Restarting computer."
            Start-Sleep -Seconds 10
            Restart-Computer -Force -Confirm:$false -ErrorAction Stop
        }
        catch {
            Write-Host "[Error] Failed to restart computer."
            exit 1
        }
    }
}
end {
    
    
    
}
