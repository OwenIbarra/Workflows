# Removes Dell Support Assist from the system.
#Requires -Version 5.1

<#
.SYNOPSIS
    Removes Dell Support Assist from the system.
.DESCRIPTION
    Removes Dell Support Assist from the system.

    Note: Other Dell SupportAssist related applications will not be removed. This script can be modified to account for them if needed.
      See line 43 for more details
.EXAMPLE
    (No Parameters)
    
    [Info] Dell SupportAssist found
    [Info] Removing Dell SupportAssist using msiexec
    [Info] Dell SupportAssist successfully removed
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
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Get UninstallString for Dell SupportAssist from the registry
    $DellSA = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | 
        Where-Object { $_.DisplayName -eq 'Dell SupportAssist' } | 
        # Replace the line above with additions like below
        # Where-Object { $_.DisplayName -eq 'Dell SupportAssist' -or $_.DisplayName -eq 'Dell SupportAssist Remediation' } |
        # Other Dell apps related to SupportAssist:
        # 'Dell SupportAssist OS Recovery'
        # 'Dell SupportAssist'
        # 'DellInc.DellSupportAssistforPCs'
        # 'Dell SupportAssist Remediation'
        # 'SupportAssist Recovery Assistant'
        # 'Dell SupportAssist OS Recovery Plugin for Dell Update'
        # 'Dell SupportAssistAgent'
        # 'Dell Update - SupportAssist Update Plugin'
        # 'Dell SupportAssist Remediation'
        Select-Object -Property DisplayName, UninstallString

    # Check if Dell SupportAssist is installed
    if ($DellSA) {
        Write-Host "[Info] Dell SupportAssist found"
    }
    else {
        Write-Host "[Info] Dell SupportAssist not found"
        exit 1
    }

    $DellSA | ForEach-Object {
        $App = $_
        # Uninstall Dell SupportAssist
        if ($App.UninstallString -match 'msiexec.exe') {
            # Extract the GUID from the UninstallString
            $null = $App.UninstallString -match '{[A-F0-9-]+}'
            $guid = $matches[0]

            Write-Host "[Info] Removing Dell SupportAssist using msiexec"
            try {
                $Process = $(Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $($guid) /qn /norestart" -Wait -PassThru)
                if ($Process.ExitCode -ne 0) {
                    throw $Process.ExitCode
                }
            }
            catch {
                Write-Host "[Error] Error removing Dell SupportAssist. Exit Code: $($Process.ExitCode)"
                exit 1
            }
        }
        elseif ($App.UninstallString -match 'SupportAssistUninstaller.exe') {
            Write-Host "[Info] Removing Dell SupportAssist using SupportAssistUninstaller.exe..."
            try {
                $Process = $(Start-Process -FilePath "$($App.UninstallString)" -ArgumentList "/arp /S /norestart" -Wait -PassThru)
                if ($Process.ExitCode -ne 0) {
                    throw $Process.ExitCode
                }
            }
            catch {
                Write-Host "[Error] Error removing Dell SupportAssist. Exit Code: $($Process.ExitCode)"
                exit 1
            }
        }
        else {
            Write-Host "[Error] Unsupported uninstall method found."
            exit 1
        }
    }

    $SupportAssistClientUI = Get-Process -Name "SupportAssistClientUI" -ErrorAction SilentlyContinue
    if ($SupportAssistClientUI) {
        Write-Host "[Info] SupportAssistClientUI still running and will be stopped"
        try {
            $SupportAssistClientUI | Stop-Process -Force -Confirm:$false -ErrorAction Stop
        }
        catch {
            Write-Host "[Warn] Failed to stop the SupportAssistClientUI process. Reboot to close process."
        }
    }

    Write-Host "[Info] Dell SupportAssist successfully removed"
    exit 0
}
end {
    
    
    
}
