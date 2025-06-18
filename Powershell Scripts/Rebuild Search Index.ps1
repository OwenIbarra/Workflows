# Deletes the existing Windows Search Index and forces Windows to rebuild it.
#Requires -Version 5.1

<#
.SYNOPSIS
    Deletes the existing Windows Search Index and forces Windows to rebuild it.
.DESCRIPTION
    Deletes the existing Windows Search Index and forces Windows to rebuild it.
.EXAMPLE
    (No Parameters)
  
    Stopping Windows Search Service.
    Attempt 1
    Successfully stopped Search Index service.

    Removing Windows search index files.
    Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search\SetupCompletedSuccessfully changed from 1 to 0

    Starting Windows Search Service
    Attempt 1
    Successfully started Search Index service.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param ()

begin {
    $Attempts = 4

    # Check if Windows Search Service exists
    if (-not (Get-Service -Name "wsearch" -ErrorAction SilentlyContinue)) {
        Write-Host "[Error] Windows Search Service does not exist. Nothing to rebuild."
        exit 1
    }

    # Check if Windows Search Service is disabled
    $StartType = Get-Service -Name "wsearch" | Select-Object -ExpandProperty StartType
    if ($StartType -eq "Disabled") {
        Write-Host "[Error] Windows Search Service is disabled. Nothing to rebuild."
        exit 1
    }

    # Function to set registry key values
    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
        if (-not $(Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            New-Item -Path $Path -Force | Out-Null
        }
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "[Error] Unable to Set registry key for $Name. Please see the error below!"
                Write-Host "[Error] $($_.Message)"
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "[Error] Unable to Set registry key for $Name. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    # Function to check if the script is running with elevated privileges
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Initialize ExitCode
    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if running with elevated privileges
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Stop the Windows Search Service
    Write-Host "Stopping Windows Search Service."
    $i = 1
    do {
        try {
            Write-Host "Attempt $i"
            Get-Service -Name "wsearch" | Stop-Service -ErrorAction Stop
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
        }

        Start-Sleep -Seconds 1
        $Status = Get-Service -Name "wsearch" | Select-Object -ExpandProperty Status
        $i++
    }while ($Status -ne "Stopped" -and $i -lt $Attempts)

    # Check if the service stopped successfully
    if ($Status -ne "Stopped") {
        Write-Host "[Error] Search Index service failed to stop!"
        Get-Service -Name "wsearch" | Format-Table | Out-String | Write-Host
        exit 1
    }
    else {
        Write-Host "Successfully stopped Search Index service."
    }
    
    # Remove existing search index files
    Write-Host "`nRemoving Windows search index files."
    Get-ChildItem -Path "$env:ProgramData\Microsoft\Search\Data\Applications\Windows" -File -Filter "*.db" | Remove-Item -Force
    Get-ChildItem -Path "$env:ProgramData\Microsoft\Search\Data\Applications\Windows" -File -Filter "*.edb" | Remove-Item -Force

    # Set the registry key to indicate setup is incomplete
    Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Search" -Name "SetupCompletedSuccessfully" -Value 0

    # Start the Windows Search Service
    Write-Host "`nStarting Windows Search Service"
    $i = 1
    do {
        Start-Sleep -Seconds 1

        try {
            Write-Host "Attempt $i"
            Get-Service -Name "wsearch" | Start-Service -ErrorAction Stop
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
        }

        $i++
        $Status = Get-Service -Name "wsearch" | Select-Object -ExpandProperty Status
    }while ($Status -ne "Running" -and $i -lt $Attempts)

    # Check if the service started successfully
    if ($Status -ne "Running") {
        Write-Host "[Error] Search Index service failed to start!"
        Get-Service -Name "wsearch" | Format-Table | Out-String | Write-Host
        exit 1
    }
    else {
        Write-Host "Successfully started Search Index service."
    }

    exit $ExitCode
}
end {
    
    
    
}
