# This will return user session start and stop events.
#Requires -Version 5.1

<#
.SYNOPSIS
    This will return user session start and stop events.
.DESCRIPTION
    This will return user session start and stop events. Excluding system accounts.
    
    If this doesn't return any results, run the following to be sure that Windows is capturing login events:
        auditpol.exe /get /subcategory:"Logon"
    It should output:
        System audit policy
        Category/Subcategory                      Setting
        Logon/Logoff
          Logon                                   Success and Failure
    If the last line for Logon doesn't look the same as above then run the following:
        auditpol.exe /set /subcategory:"Logon" /success:enable /failure:enable
    Now the system will start logging logins.
.EXAMPLE
    No params needed
    Returns all login events for all users.
.EXAMPLE
     -UserName "Fred"
    Returns all user login events of the user Fred.
.EXAMPLE
     -Days 7
    Returns the last 7 days of login events for all users.
.EXAMPLE
     -Days 7 -UserName "Fred"
    Returns the last 7 days of login events for the user Fred.
.EXAMPLE
    PS C:\> Get-User-Login-History.ps1 -Days 7 -UserName "Fred"
    Returns the last 7 days of login events for the user Fred.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
.OUTPUTS
    Time                  Event        User  ID
    ----                  -----        ----  --
    10/7/2021 3:51:48 PM  SessionStop  User1 4634
    10/7/2021 3:51:48 PM  SessionStart User1 4624
.COMPONENT
    ManageUsers
#>

[CmdletBinding()]
param (
    # Specify one user
    [Parameter()]
    [String]$UserName,
    # How far back in days you want to search, this is in 24 hour increments from the time it executes
    [Parameter()]
    [int]$Days
)

begin {
    if ($env:userToReportOn -and $env:userToReportOn -notlike "null") { $UserName = $env:userToReportOn }
    if ($env:inTheLastXDays -and $env:inTheLastXDays -notlike "null") { $Days = $env:inTheLastXDays }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        { Write-Output $true }
        else
        { Write-Output $false }
    }

    # System accounts that we don't want
    $SystemUsers = @(
        "SYSTEM"
        "NETWORK SERVICE"
        "LOCAL SERVICE"
    )
    # Filter for only getting session start and stop events from Security event log
    $FilterHashtable = @{
        LogName = "Security";
        id      = 4634, 4624, 4625
    }
    # If Days was specified then add this parameter
    if ($Days) {
        $FilterHashtable.Add("StartTime", (Get-Date).AddDays(-$Days))
    }
    # Creating a hash table for parameter splatting
    $Splat = @{
        FilterHashtable = $FilterHashtable
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    # Get windows events, filter out everything but logins and logouts(Session starts and ends)
    Get-WinEvent @Splat | ForEach-Object {
        # UserName in the two event types are in different places in the Properties array
        if ($_.Id -eq 4634) {
            # Events with ID 4634 the user name is the second item in the array. Arrays start at 0 in PowerShell.
            $User = $_.Properties[1].Value
        }
        else {
            # Events with ID 4624 and 4625 the user name is the fifth item in the array. Arrays start at 0 in PowerShell.
            $User = $_.Properties[5].Value
        }

        # Filter out system accounts and computer logins(Active Directory related)
        # DWM-0  = Desktop Window Manager
        # UMFD-0 = User Mode Framework Driver
        if ($SystemUsers -notcontains $User -and $User -notlike "DWM-*" -and $User -notlike "UMFD-*" -and $User -notlike "*$") {
            # If the UserName parameter was specified then only return that user's events
            if ($UserName -and $UserName -like $User) {
                # Write out to StandardOutput
                [PSCustomObject]@{
                    Time  = $_.TimeCreated
                    Event = if ($_.Id -eq 4634) { "SessionStop" } elseif ($_.ID -eq 4625) { "FailedLogin" } else { "SessionStart" }
                    User  = $User
                    ID    = $_.ID
                }
            } # If the UserName parameter was not specified return all users events
            elseif (-not $UserName) {
                # Write out to StandardOutput
                [PSCustomObject]@{
                    Time  = $_.TimeCreated
                    Event = if ($_.Id -eq 4634) { "SessionStop" } elseif ($_.ID -eq 4625) { "FailedLogin" } else { "SessionStart" }
                    User  = $User
                    ID    = $_.ID
                }
            }
        }
        # Null $User just in case the next loop iteration doesn't set it, we can then see that the user name is missing
        $User = $null
    }
}
end {
    
    
    
}


