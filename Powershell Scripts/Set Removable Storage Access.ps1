# Disable or Enable Write, Read, and Execute access to Removable Storage devices.
#Requires -Version 2.0

<#
.SYNOPSIS
    Disable or Enable Write, Read, and Execute access to Removable Storage devices.
.DESCRIPTION
    Disable or Enable Write, Read, and Execute access to Floppy, CD/DVD, Tape, WPD, and/or USB.
    Disable actions are does first, then allow actions are done after.
.EXAMPLE
     -Device DVD -DenyRead -DenyWrite -DenyExecute
    Disable Write, Read, and Execute access to CD/DVD drive.
.EXAMPLE
     -Device DVD -AllowRead -AllowWrite -AllowExecute
    Allow Write, Read, and Execute access to CD/DVD drive.
.EXAMPLE
     -Device DVD -DenyWrite -DenyExecute -AllowRead
    Disable Write, Read, and Execute access to CD/DVD drive, but Allow Read.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    Local Group Policy updates like this requires the computer to rebooted.
    Release Notes: Updated Calculated Name
.COMPONENT
    DataIOSecurity
#>

[CmdletBinding()]
param (
    # Supported devices Floppy, DVD, Tape, WPD, USB
    [String[]]
    $Device,
    [switch]
    $DenyRead = [System.Convert]::ToBoolean($env:DenyRead),
    [switch]
    $DenyWrite = [System.Convert]::ToBoolean($env:DenyWrite),
    [switch]
    $DenyExecute = [System.Convert]::ToBoolean($env:DenyExecute),
    [switch]
    $AllowRead = [System.Convert]::ToBoolean($env:AllowRead),
    [switch]
    $AllowWrite = [System.Convert]::ToBoolean($env:AllowWrite),
    [switch]
    $AllowExecute = [System.Convert]::ToBoolean($env:AllowExecute),
    [switch]
    $ForceReboot = [System.Convert]::ToBoolean($env:ForceReboot)
)

begin {
    function Test-StringEmpty {
        param([string]$Text)
        # Returns true if string is empty, null, or whitespace
        process { [string]::IsNullOrEmpty($Text) -or [string]::IsNullOrWhiteSpace($Text) }
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $RegSettings = @(
        [PSCustomObject]@{
            Name        = "Floppy"
            BasePath    = "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56311-b6bf-11d0-94f2-00a0c91efb8b}"
            DenyExecute = "Deny_Execute"
            DenyWrite   = "Deny_Write"
            DenyRead    = "Deny_Read"
        },
        [PSCustomObject]@{
            Name        = "DVD"
            BasePath    = "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}"
            DenyExecute = "Deny_Execute"
            DenyWrite   = "Deny_Write"
            DenyRead    = "Deny_Read"
        },
        [PSCustomObject]@{
            Name        = "Tape"
            BasePath    = "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630b-b6bf-11d0-94f2-00a0c91efb8b}"
            DenyExecute = "Deny_Execute"
            DenyWrite   = "Deny_Write"
            DenyRead    = "Deny_Read"
        },
        [PSCustomObject]@{
            Name      = "WPD"
            BasePath  = "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}"
            DenyWrite = "Deny_Write"
            DenyRead  = "Deny_Read"
        },
        [PSCustomObject]@{
            Name      = "WPD"
            BasePath  = "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}"
            DenyWrite = "Deny_Write"
            DenyRead  = "Deny_Read"
        },
        [PSCustomObject]@{
            Name        = "USB"
            BasePath    = "HKLM:\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"
            DenyExecute = "Deny_Execute"
            DenyWrite   = "Deny_Write"
            DenyRead    = "Deny_Read"
        }
    )
    $Device = if ($(Test-StringEmpty -Text $env:Device)) { $Device }else { $env:Device }

    if ($(Test-StringEmpty -Text $Device)) {
        Write-Error "Device is required."
        exit 1
    }
    if ((-not $DenyRead -and -not $DenyWrite -and -not $DenyExecute) -and (-not $AllowRead -and -not $AllowWrite -and -not $AllowExecute)) {
        Write-Error "At least one Deny or Allow is required."
        exit 1
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Split any string that has a comma and validate types of devices
    $Device = $Device | ForEach-Object {
        $_ -split ',' | ForEach-Object {
            "$_".Trim()
        }
    } | Where-Object { $_ -in "Floppy", "DVD", "Tape", "WPD", "USB" }

    try {
        $Device | ForEach-Object {
            $CurDevice = $_
            # Loop through each item in $RegSettings and work on the current device($Device)
            $RegSettings | Where-Object { $_.Name -in $CurDevice } | ForEach-Object {
                $CurRegSetting = $_
                $Path = $CurRegSetting.BasePath

                # Build Deny list
                $Deny = [System.Collections.ArrayList]::new() # Older PowerShell compatible Lists
                if ($DenyRead) { $Deny.Add("Read") | Out-Null }
                if ($DenyWrite) { $Deny.Add("Write") | Out-Null }
                if ($DenyExecute) { $Deny.Add("Execute") | Out-Null }
                # Build Allow list
                $Allow = [System.Collections.ArrayList]::new() # Older PowerShell compatible Lists
                if ($AllowRead) { $Allow.Add("Read") | Out-Null }
                if ($AllowWrite) { $Allow.Add("Write") | Out-Null }
                if ($AllowExecute) { $Allow.Add("Execute") | Out-Null }

                # Loop though each $Deny item passed
                $Deny | ForEach-Object {
                    $CurDeny = $_
                    # Only act on what we have, like WPD where we only have Deny_Write and Deny_Read
                    # $CurRegSetting."Deny$CurDeny" is a method of access a property
                    if ($CurRegSetting."Deny$CurDeny") {
                        $CurDenyType = $CurRegSetting."Deny$CurDeny"
                        # Check if we need to create the path
                        if (-not (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
                            New-Item -Path ($Path | Split-Path -Parent) -Name ($Path | Split-Path -Leaf) -Force -Confirm:$false | Out-Null
                            Write-Host "Creating path: $($Path)"
                        }
                        # Check if the property already exists and update it or create the property
                        if ((Get-ItemProperty -Path $Path -Name $CurDenyType -ErrorAction SilentlyContinue)."$CurDenyType") {
                            Set-ItemProperty -Path $Path -Name $CurDenyType -Value 1 -Force -Confirm:$false | Out-Null
                            Write-Host "Setting $($Path)/$CurDenyType to 1"
                        }
                        else {
                            New-ItemProperty -Path $Path -Name $CurDenyType -Value 1 -PropertyType "DWORD" -Force -Confirm:$false | Out-Null
                            Write-Host "Creating and Setting $($Path)/$CurDenyType to 1"
                        }
                        Write-Host "Deny $CurDeny for $CurDevice set to $((Get-ItemProperty -Path $Path -Name $CurDenyType -ErrorAction SilentlyContinue)."$CurDenyType")"
                    }
                    else {
                        # Skipping this as we don't have Deny_Execute for WPD
                        Write-Host "Skipping $($CurRegSetting."Deny$CurDeny")"
                    }
                }
                # Loop though each $Allow item passed
                $Allow | ForEach-Object {
                    $CurAllow = $_
                    # Only act on what we have, like WPD where we only have Deny_Write and Deny_Read
                    # $CurRegSetting."Deny$CurAllow" is a method to access a property
                    if ($CurRegSetting."Deny$CurAllow") {
                        $CurAllowType = $CurRegSetting."Deny$CurAllow"
                        # Check if the property already exists and update it or create the property
                        if ((Get-ItemProperty -Path $Path -Name $CurAllowType -ErrorAction SilentlyContinue)."$CurAllowType") {
                            Set-ItemProperty -Path $Path -Name $CurAllowType -Value 0 -Force -Confirm:$false | Out-Null
                            Write-Host "Setting $($Path)/$CurAllowType to 0"
                        }
                        Write-Host "Allow access for $CurDevice"
                    }
                    else {
                        # Skipping this as we don't have Deny_Execute for WPD
                        Write-Host "Skipping $($CurRegSetting."Deny$CurAllow")"
                    }
                }
            }
        }
        

        Write-Host "Running: gpupdate.exe /force"
        gpupdate.exe /force
        Write-Host "Completed Running: gpupdate.exe /force"
        Write-Host "Computer will need to be rebooted for changes to take effect."

        if ($ForceReboot) {
            shutdown.exe -r -t 60
        }
        else {
            Write-Host "Computer will need to be rebooted to see changes."
        }
        exit 0
    }
    catch {
        Write-Error $_
        exit 1
    }
}
end {
    
    
    
}

