# Logs off user(s) specified.

<#
.SYNOPSIS
    Logs off user(s) specified.
.DESCRIPTION
    Logs off user(s) specified.
.EXAMPLE
    -Users "Administrator"

    Logs off Administrator user.
.EXAMPLE
    -Users "Administrator, Guest"

    Logs off Administrator and Guest users.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012
    Release Notes: Updated checkbox script variables.
.COMPONENT
    ManageUsers
#>

[CmdletBinding(SupportsShouldProcess = $True)]
param (
    # User name(s) to log off
    [Parameter()]
    [String]$Users,
    [Parameter()]
    [switch]$LogOffAllUsers
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Get-QueryUser {
        # Run the quser.exe command to get the list of currently logged-in users
        try {
            $ErrorActionPreference = "Stop"
            $QuserOutput = quser.exe
            $ErrorActionPreference = "Continue"
        }
        catch {
            throw $_
        }
    
        $i = 0
        $QuserOutput | Where-Object { ![string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
            # Skip the first line (header) and process only the data lines
            if ($i -ne 0) {
                # Extract the relevant columns using fixed width positions
                [PSCustomObject]@{
                    Username    = ($_.Substring(0, 21).Trim() -replace '^>')
                    SessionName = $_.Substring(21, 21).Trim()
                    ID          = $_.Substring(40, 5).Trim()
                    State       = $_.Substring(45, 10).Trim()
                    IdleTime    = $_.Substring(55, 10).Trim()
                    LogonTime   = $_.Substring(65).Trim()
                }
            }
    
            $i++
        }
    }

    if ($env:usersToLogoff -and $env:usersToLogoff -notlike "null") {
        $Users = $env:usersToLogoff
    }
    if ($env:logOffAllUsers -like "true") {
        $LogOffAllUsers = $true
    }

    $UserList = New-Object System.Collections.Generic.List[string]

    if ($LogOffAllUsers) {
        # If the Log Off All Users was used, get all users logged on
        $Users = (Get-QueryUser).Username | ForEach-Object { $UserList.Add($_.Trim()) }
    }
    else {
        # If no users are specified, exit with an error
        if (-not ($Users)) { Write-Host "[Error] A username is required!"; Exit 1 }

        $Users -split ',' | ForEach-Object { $UserList.Add($_.Trim()) }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Get a list of users logged on from query.exe, format it for powershell to process
    $QueryResults = Get-QueryUser

    $UsersNotFound = New-Object System.Collections.Generic.List[string]
    $ToLogOut = New-Object System.Collections.Generic.List[object]
    $FailedToLogout = New-Object System.Collections.Generic.List[object]

    foreach ($User in $UserList) {
        $UserFound = $QueryResults | Where-Object { $_.Username -eq "$User" }

        if (-not $UserFound) { $UsersNotFound.Add($User) }
        if ($UserFound) { $ToLogOut.Add($UserFound) }
    }

    $ToLogOut | ForEach-Object {
        Write-Host "[Info] Logging out $($_.Username) on Session $($_.Id)!"

        $Process = Start-Process logoff.exe -ArgumentList "$($_.Id)" -Wait -PassThru -NoNewWindow 
        Write-Host "[Info] Exit Code: $($Process.ExitCode)"

        if ($Process.ExitCode -like 0) { 
            Write-Host "[Info] Successfully logged out $($_.Username) on Session $($_.Id)." 
        }
        else {
            Write-Host "[Error] Failed to logout $($_.Username) on Session $($_.Id)."
            $FailedToLogout.Add($_.Username)
        }
    }

    if (-not ($QueryResults)) {
        $Users | ForEach-Object { Write-Host "[Error] $_ was not signed in." }
        exit 2
    }

    if ($UsersNotFound) {
        $UsersNotFound | ForEach-Object { Write-Host "[Error] $_ was not signed in." }
        exit 2
    }

    if ($FailedToLogout) {
        Write-Host "[Error] One or more users failed to logout!"
        exit 1
    }

    exit 0
}
end {
    
    
    
}


