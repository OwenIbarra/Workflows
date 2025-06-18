# This script will see if any accounts on a local machine or on a domain controller are locked out.
You can optionally export this information into a custom field.

Does NOT check Azure AD Accounts.

<#
.SYNOPSIS
    This script will see if any accounts on a local machine or on a domain controller are locked out. 
    You can optionally export this information into a custom field.

    Does NOT check Azure AD Accounts.
.DESCRIPTION
    This script will see if any accounts on a local machine or on a domain controller are locked out. 
    You can optionally export this information into a custom field.

    Does NOT check Azure AD Accounts.
    
.EXAMPLE
    (No Parameters but ran on a DC)
    SamAccountName LastLogonDate        PasswordExpired Enabled
    -------------- -------------        --------------- -------
    user           4/20/2023 1:09:23 PM           False    True

.EXAMPLE
    (No Parameters but ran on a Workstation)
    Name  Domain LocalAccount Disabled
    ----  ------ ------------ --------
    user  TEST          False    False

PARAMETER: -ExportTXT "ReplaceMeWithAnyMultiLineCustomField"
    Name of a multi-line customfield you'd like to export the results to.
.EXAMPLE
    -ExportTXT "ReplaceMeWithAnyMultiLineCustomField"
    Name  Domain LocalAccount Disabled
    ----  ------ ------------ --------
    user  TEST          False    False

PARAMETER: -ExportCSV "ReplaceMeWithAnyMultiLineCustomField"
    Name of a multi-line customfield you'd like to export the results to.
.EXAMPLE
    -ExportCSV "ReplaceMeWithAnyMultiLineCustomField"
    Name  Domain LocalAccount Disabled
    ----  ------ ------------ --------
    user  TEST          False    False

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2008
    Release Notes: Renamed script, added Script Variable support, added support for showing results of only 1 or more specific users.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Users,
    [Parameter()]
    [String]$ExportCSV,
    [Parameter()]
    [String]$ExportTXT
)

begin {
    if ($env:usersToCheck -and $env:usersToCheck -notlike "null") { $Users = $env:usersToCheck }
    if ($env:exportCsvResultsToThisCustomField -and $env:exportCsvResultsToThisCustomField -notlike "null") { $ExportCSV = $env:exportCsvResultsToThisCustomField }
    if ($env:exportTextResultsToThisCustomField -and $env:exportTextResultsToThisCustomField -notlike "null") { $ExportTXT = $env:exportTextResultsToThisCustomField }

    if ($Users) {
        $UsersToCheck = $Users.split(',') | ForEach-Object { $_.Trim() }
        Write-Warning "Only the following users will be checked: $UsersToCheck"
    }
    function Test-IsDomainController {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        }
        else {
            $OS = Get-WmiObject -Class Win32_OperatingSystem
        }

        if ($OS.ProductType -eq "2") {
            return $True
        }
    }

    function Test-IsAzureJoined {
        $dsreg = dsregcmd.exe /status | Select-String "AzureAdJoined : YES"
        if ($dsreg) {
            return $True
        }
    }

    if ([System.Environment]::OSVersion.Version.Major -ge 10) {
        if (Test-IsAzureJoined) { Write-Warning "This device is Azure AD Joined, this script currently cannot detect if Azure AD Users are locked out!" }
    }
}
process {

    # For Domain Controllers find the locked out account using Search-ADAccount
    if (Test-IsDomainController) {
        Import-Module ActiveDirectory
        $LockedOutUsers = Search-ADAccount -LockedOut | Select-Object SamAccountName, LastLogonDate, PasswordExpired, Enabled
    }
    else {
        $LockedOutUsers = if ($PSVersionTable.PSVersion.Major -ge 5) {
            Get-CimInstance -ClassName Win32_Useraccount | Where-Object { $_.Lockout -eq $True } | Select-Object Name, Domain, LocalAccount, Disabled 
        }
        else {
            Get-WmiObject -Class Win32_Useraccount | Where-Object { $_.Lockout -eq $True } | Select-Object Name, Domain, LocalAccount, Disabled
        }
    }

    if ($Users) {
        $LockedOutUsers = $LockedOutUsers | Where-Object { $UsersToCheck -contains $_.Name -or $UsersToCheck -contains $_.SamAccountName } 
    }

    if ($LockedOutUsers) {
        # Output any locked out users into the activity log
        Write-Warning "Locked out users were found!"
        $LockedOutUsers | Format-Table | Out-String | Write-Host

        # Export the list in CSV format into a custom field
        if ($ExportCSV) {
            Ninja-Property-Set $ExportCSV ($LockedOutUsers | ConvertTo-Csv -NoTypeInformation)
        }

        # Export the usernames into a custom field
        if ($ExportTXT) {
            if ($LockedOutUsers.Name) {
                Ninja-Property-Set $ExportTXT ($LockedOutUsers.Name | Out-String)
            }

            if ($LockedOutUsers.SamAccountName) {
                Ninja-Property-Set $ExportTXT ($LockedOutUsers.SamAccountName | Out-String)
            }
        }
        Exit 1
    }

    Write-Host "No locked out users detected. Please note this does NOT check Azure AD Accounts."
    Exit 0
}
end {
    
    
    
}

