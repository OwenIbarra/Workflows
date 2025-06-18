# Uninstalls TeamViewer.
#Requires -Version 5.1

<#
.SYNOPSIS
    Uninstalls TeamViewer.
.DESCRIPTION
    Uninstalls TeamViewer.

.EXAMPLE
    (No parameters)

    Verifying that TeamViewer is still installed.
    Removing TeamViewer using 'C:\Program Files (x86)\TeamViewer\uninstall.exe /S'.
    Verifying that TeamViewer has been removed.
    TeamViewer has been successfully removed.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial release
#>

[CmdletBinding()]
param ()

begin {

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
                try {
                    $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                } catch {
                    Write-Host -Object "[Warning] Failed to retrieve registry keys at 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    throw $_
                }

                # Search in the 64-bit uninstall registry key and add results to the list
                try {
                    $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                } catch {
                    Write-Host -Object "[Warning] Failed to retrieve registry keys at 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    throw $_
                }
            } else {
                # If a custom user base key is provided, search in the corresponding Wow6432Node path and add results to the list
                try {
                    $Result = Get-ChildItem -Path "$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                } catch {
                    Write-Host -Object "[Warning] Failed to retrieve registry keys at '$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    throw $_
                }

                try {
                    # Search in the custom user base key for the standard uninstall path and add results to the list
                    $Result = Get-ChildItem -Path "$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                } catch {
                    Write-Host -Object "[Warning] Failed to retrieve registry keys at '$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    throw $_
                }
            }

            # If the UninstallString switch is set, return only the UninstallString property of the found keys
            if ($UninstallString) {
                $InstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            } else {
                $InstallList
            }
        }
    }
    function Test-IsElevated {
        [CmdletBinding()]
        param ()

        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Create a WindowsPrincipal object based on the current identity
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)

        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        # 544 is the value for the Built In Administrators role
        # Reference: https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsbuiltinrole
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]'544')
    }

    function Wait-ForTeamViewer {
        [CmdletBinding()]
        param()

        $Start = Get-Date
        $Timeout = [TimeSpan]::FromMinutes(5)

        if (Get-Process -Name "TeamViewer", "TeamViewer_Service", "Un_A", "Un_B" -ErrorAction SilentlyContinue) {
            Write-Host -Object "Waiting for the TeamViewer process to stop."
        }

        while (Get-Process -Name "TeamViewer", "TeamViewer_Service", "Un_A", "Un_B" -ErrorAction SilentlyContinue) {
            if (((Get-Date) - $Start) -ge $Timeout) {
                Write-Host -Object "[Warning] The five minute timeout has been reached."
                break
            }

            Start-Sleep -Milliseconds 100
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Attempt to determine if the current session is running with Administrator privileges.
    try {
        $IsElevated = Test-IsElevated -ErrorAction Stop
    } catch {
        # Output error if unable to determine elevation status
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Unable to determine if the account '$env:Username' is running with Administrator privileges."
        exit 1
    }

    # Exit if not running as administrator
    if (!$IsElevated) {
        Write-Host -Object "[Error] Access Denied: Please run with Administrator privileges."
        exit 1
    }

    # Check if TeamViewer is still installed by searching uninstall registry keys
    Write-Host -Object "Verifying that TeamViewer is still installed."
    try {
        $TeamViewerInstalls = Find-InstallKey -DisplayName "TeamViewer" -UninstallString -ErrorAction Stop
    } catch {
        # Output error if unable to verify installation
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to verify whether TeamViewer is still installed."
        exit 1
    }

    # Check for TeamViewer uninstaller in Program Files (x86)
    if (Test-Path -Path "${env:ProgramFiles(x86)}\TeamViewer\uninstall.exe" -PathType Leaf -ErrorAction SilentlyContinue) {
        $TeamViewerUninstallerFound = $True
    }

    # Check for TeamViewer uninstaller in Program Files
    if (Test-Path -Path "${env:ProgramFiles}\TeamViewer\uninstall.exe" -PathType Leaf -ErrorAction SilentlyContinue) {
        $TeamViewerUninstallerFound = $True
    }

    # Check if TeamViewer is currently running
    $TeamViewerRunning = Get-Process -Name "TeamViewer", "TeamViewer_Service" -ErrorAction SilentlyContinue

    # If neither registry nor uninstaller found, TeamViewer is already removed
    if (!$TeamViewerInstalls -and !$TeamViewerUninstallerFound) {
        if ($TeamViewerRunning) {
            Write-Host -Object "[Alert] The TeamViewer QuickSupport tool was detected. The QuickSupport tool is not installed on the system because it is a portable app."
        }
        Write-Host -Object "[Error] TeamViewer is not installed on this system."
        exit 1
    }

    # If TeamViewer was installed via MSI, uninstall using MsiExec
    if ($TeamViewerInstalls -match "MsiExec\.exe /I") {
        $TeamViewerInstalls | ForEach-Object {
            # Prepare MSI uninstall arguments
            $MsiExecArguments = @(
                ($_ -replace "^MsiExec\.exe " -replace "/I", "/x")
                "/qn"
                "/norestart"
            )

            try {
                Write-Host -Object "Removing TeamViewer using '$env:WINDIR\System32\MsiExec.exe $($MsiExecArguments -join " ")'."
                # Start MSI uninstall process
                $UninstallProcess = Start-Process -FilePath "$env:WINDIR\System32\MsiExec.exe" -ArgumentList $MsiExecArguments -NoNewWindow -Wait -PassThru -ErrorAction Stop
                if ($UninstallProcess.ExitCode -ne 0) {
                    Write-Host -Object "[Warning] The last exit code '$($UninstallProcess.ExitCode)' does not indicate success."
                }
            } catch {
                # Output error if MSI uninstall fails
                Write-Host -Object "[Error] Exit Code: $($UninstallProcess.ExitCode)"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to uninstall TeamViewer."
                $ExitCode = 1
            }

            try {
                # Wait for TeamViewer processes to exit
                Wait-ForTeamViewer -ErrorAction Stop
            } catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to wait for the TeamViewer uninstaller process to complete."
                $ExitCode = 1
            }
        }
    }

    # If TeamViewer was installed with the exe, run the uninstaller
    if ($TeamViewerInstalls -match "uninstall\.exe") {
        $TeamViewerInstalls | ForEach-Object {
            # Extract the uninstall.exe path from the uninstall string
            $UninstallString = $_ -split '"([^"]+)"'
            $FilePath = $UninstallString | Where-Object { $_ -match "uninstall\.exe" }

            # Prepare silent uninstall arguments
            $UninstallArguments = @(
                "/S"
            )

            try {
                Write-Host -Object "Removing TeamViewer using '$FilePath $($UninstallArguments -join " ")'."
                # Start uninstall process
                $UninstallProcess = Start-Process -FilePath $FilePath -ArgumentList $UninstallArguments -NoNewWindow -Wait -PassThru -ErrorAction Stop
                if ($UninstallProcess.ExitCode -ne 0) {
                    Write-Host -Object "[Warning] The last exit code '$($UninstallProcess.ExitCode)' does not indicate success."
                }
            } catch {
                # Output error if uninstall.exe fails
                Write-Host -Object "[Error] Exit Code: $($UninstallProcess.ExitCode)"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to uninstall TeamViewer."
                $ExitCode = 1
            }

            try {
                # Wait for TeamViewer processes to exit
                Wait-ForTeamViewer -ErrorAction Stop
            } catch {
                Write-Host -Object "[Error] $($_.Exception.Message)"
                Write-Host -Object "[Error] Failed to wait for the TeamViewer uninstaller process to complete."
                $ExitCode = 1
            }
        }
    }

    # Fallback: If uninstall.exe exists in Program Files (x86), run it directly
    if (Test-Path -Path "${env:ProgramFiles(x86)}\TeamViewer\uninstall.exe" -PathType Leaf -ErrorAction SilentlyContinue) {
        try {
            Write-Host -Object "Removing TeamViewer using '${env:ProgramFiles(x86)}\TeamViewer\uninstall.exe /S'."
            $UninstallProcess = Start-Process -FilePath "${env:ProgramFiles(x86)}\TeamViewer\uninstall.exe" -ArgumentList "/S" -NoNewWindow -PassThru -ErrorAction Stop
            if ($UninstallProcess.ExitCode -ne 0) {
                Write-Host -Object "[Warning] The last exit code '$($UninstallProcess.ExitCode)' does not indicate success."
            }
        } catch {
            # Output error if uninstall.exe fails
            Write-Host -Object "[Error] Exit Code: $($UninstallProcess.ExitCode)"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to uninstall TeamViewer."
            $ExitCode = 1
        }

        try {
            # Wait for TeamViewer processes to exit
            Wait-ForTeamViewer -ErrorAction Stop
        } catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to wait for the TeamViewer uninstaller process to complete."
            $ExitCode = 1
        }
    }

    # Fallback: If uninstall.exe exists in Program Files, run it directly
    if (Test-Path -Path "${env:ProgramFiles}\TeamViewer\uninstall.exe" -PathType Leaf -ErrorAction SilentlyContinue) {
        try {
            Write-Host -Object "Removing TeamViewer using '${env:ProgramFiles}\TeamViewer\uninstall.exe /S'."
            $UninstallProcess = Start-Process -FilePath "${env:ProgramFiles}\TeamViewer\uninstall.exe" -ArgumentList "/S" -NoNewWindow -PassThru -ErrorAction Stop
            if ($($UninstallProcess.ExitCode) -ne 0) {
                Write-Host -Object "[Warning] The last exit code '$($UninstallProcess.ExitCode)' does not indicate success."
            }
        } catch {
            # Output error if uninstall.exe fails
            Write-Host -Object "[Error] Exit Code: $($UninstallProcess.ExitCode)"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to uninstall TeamViewer."
            $ExitCode = 1
        }

        try {
            # Wait for TeamViewer processes to exit
            Wait-ForTeamViewer -ErrorAction Stop
        } catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to wait for the TeamViewer uninstaller process to complete."
            $ExitCode = 1
        }
    }

    # Final verification that TeamViewer has been removed
    Write-Host -Object "Verifying that TeamViewer has been removed."
    try {
        $TeamViewerInstalls = Find-InstallKey -DisplayName "TeamViewer" -UninstallString -ErrorAction Stop
    } catch {
        # Output error if unable to verify removal
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to verify whether TeamViewer is still installed."
        exit 1
    }

    # Check again for uninstall.exe in both Program Files locations
    if (Test-Path -Path "${env:ProgramFiles(x86)}\TeamViewer\uninstall.exe" -PathType Leaf -ErrorAction SilentlyContinue) {
        $TeamViewerUninstallerFoundAgain = $True
    }

    if (Test-Path -Path "${env:ProgramFiles}\TeamViewer\uninstall.exe" -PathType Leaf -ErrorAction SilentlyContinue) {
        $TeamViewerUninstallerFoundAgain = $True
    }

    # If neither registry nor uninstaller found, removal was successful
    if (!$TeamViewerInstalls -and !$TeamViewerUninstallerFoundAgain) {
        Write-Host -Object "TeamViewer has been successfully removed."
    } else {
        Write-Host -Object "[Error] TeamViewer is still installed."
        exit 1
    }

    exit $ExitCode
}
end {
    
    
    
}
