# Removes the HP Support Assistant.
#Requires -Version 5.1

<#
.SYNOPSIS
    Removes the HP Support Assistant.
.DESCRIPTION
    Removes the HP Support Assistant from the system.
.EXAMPLE
    (No Parameters)
    
    [Info] HP Support Assistant is installed.
    [Info] HP Support Assistant is not installed from Microsoft Store.
    [Info] Removing HP Support Assistant from the registry.
    [Info] Removing HP Support Assistant.
    [Info] Successfully removed HP Support Assistant.

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param ()

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $ProgramFiles32bit = if ((Test-Path -Path ${env:ProgramFiles(x86)} -ErrorAction SilentlyContinue)) {
        # 64-bit OS uses ProgramFiles(x86) environment variable.
        ${env:ProgramFiles(x86)}
    }
    elseif ((Test-Path -Path ${env:ProgramFiles} -ErrorAction SilentlyContinue)) {
        # 32-bit OS uses ProgramFiles environment variable.
        $env:ProgramFiles
    }
    else {
        # Program Files directory was not found.
        Write-Host "[Error] Failed to find Program Files directory."
        exit 1
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the HPSupportAssistant.dll file exists
    # "C:\Program Files (x86)" is the only location where HP Support Assistant is installed on 64-bit Windows.
    if ($(Test-Path -Path "$ProgramFiles32bit\HP\HP Support Framework\HPSupportAssistant.dll")) {
        Write-Host "[Info] HP Support Assistant is installed."
    }
    else {
        Write-Host "[Error] HP Support Assistant is not installed."
        exit 1
    }

    # Remove HP Support Assistant from Microsoft Store
    $AppxPackages = Get-AppxPackage -AllUsers | Format-List -Property PackageFullName, PackageUserInformation | Where-Object { $_.PackageFullName -like "*hpsupportassistant*" }
    if ($AppxPackages) {
        Write-Host "[Info] Removing HP Support Assistant from Microsoft Store."
        try {
            $AppxPackages | ForEach-Object {
                Remove-AppxPackage -Online -PackageFullName $_.PackageFullName -AllUsers
            }
            Write-Host "Successfully removed HP Support Assistant from Microsoft Store."
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            Write-Host "[Error] Failed to remove HP Support Assistant from Microsoft Store."
        }
    }
    else {
        Write-Host "[Info] HP Support Assistant is not installed from Microsoft Store."
    }

    try {
        $ProcessSplat32bit = @{
            FilePath     = "$ProgramFiles32bit\HP\HP Support Framework\UninstallHPSA.exe"
            ArgumentList = "/s /v/qn UninstallKeepPreferences=FALSE"
            Wait         = $true
            WindowStyle  = "Hidden"
        }
        if ($(Test-Path -Path $ProcessSplat32bit.FilePath -ErrorAction SilentlyContinue)) {
            try {
                Write-Host "[Info] Removing HP Support Assistant from the registry."
                Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\HP\HPActiveSupport" -Recurse -Force -ErrorAction Stop
            }
            catch {
                Write-Host "$($_.Exception.Message)"
                Write-Host "[Error] Failed to remove registry key: Registry::HKEY_LOCAL_MACHINE\Software\WOW6432Node\HP\HPActiveSupport"
                exit 1
            }
            try {
                Write-Host "[Info] Removing HP Support Assistant."
                Start-Process @ProcessSplat32bit -ErrorAction Stop
                Write-Host "[Info] Successfully removed HP Support Assistant."
            }
            catch {
                Write-Host "$($_.Exception.Message)"
                Write-Host "[Error] Failed to remove HP Support Assistant."
                exit 1
            }
            # Find and stop HP Support Assistant processes
            Write-Host "[Info] Attempting to stop HP Support Assistant processes."
            $Process = Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*HPSupportAssistant*" }
            if ($Process) {
                $Process | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
                Write-Output "[Info] HP Support Assistant process has been stopped."
            }
            else {
                Write-Output "[Warn] HP Support Assistant process not found."
            }
        }
        else {
            Write-Host "[Warn] UninstallHPSA.exe is missing. Skipping."
        }
    }
    catch {
        Write-Host "$($_.Exception.Message)"
        Write-Host "[Error] Failed to remove HP Support Assistant."
        exit 1
    }
}

end {
    
    
    
}
