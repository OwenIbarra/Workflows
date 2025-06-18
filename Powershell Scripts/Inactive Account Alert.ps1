# Alerts when there is an inactive / unused account that has not logged in or has not had their password set in the specified number of days.

<#
.SYNOPSIS
    Alerts when there is an inactive / unused account that has not logged in or has not had their password set in the specified number of days.
.DESCRIPTION
    Alerts when there is an inactive / unused account that has not logged in or has not had their password set in the specified number of days.
.EXAMPLE
    -IncludeDisabled
    
    Action completed: Run Monitor Account Last Logon Result: FAILURE Output: Action: Run Monitor Account Last Logon, Result: Failed
    WARNING: Inactive accounts detected!

    Username       PasswordLastSet       LastLogon              Enabled
    --------       ---------------       ---------              -------
    Administrator  4/12/2023 9:05:18 AM  11/28/2023 10:31:06 AM    True
    Guest                                12/31/1600 4:00:00 PM    False
    DefaultAccount                       12/31/1600 4:00:00 PM    False
    kbohlander     11/29/2023 1:49:51 PM 12/5/2023 1:09:43 PM      True
    tuser1         12/1/2023 5:59:58 PM  12/4/2023 9:34:32 AM      True
    krbtgt         11/27/2023 3:40:20 PM 12/31/1600 4:00:00 PM    False
    tuser2         12/4/2023 3:40:27 PM  12/31/1600 4:00:00 PM     True
.EXAMPLE
    -Days 60
    
    Action completed: Run Monitor Account Last Logon Result: FAILURE Output: Action: Run Monitor Account Last Logon, Result: Failed
    WARNING: Inactive accounts detected!

    Username       PasswordLastSet       LastLogon              Enabled
    --------       ---------------       ---------              -------
    Administrator  4/12/2023 9:05:18 AM  11/28/2023 10:31:06 AM    True
    kbohlander     11/29/2023 1:49:51 PM 12/5/2023 1:09:43 PM      True
    tuser1         12/1/2023 5:59:58 PM  12/4/2023 9:34:32 AM      True
    tuser2         12/4/2023 3:40:27 PM  12/31/1600 4:00:00 PM     True
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    Exit code 1: Found users that haven't logged in over X days and are enabled.
    Exit code 2: Calling "net.exe user" or "Get-LocalUser" failed.
    Release Notes: Updated checkbox script variables.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$Days = 90,
    [Parameter()]
    [switch]$IncludeDisabled = [System.Convert]::ToBoolean($env:includeDisabled)
)

begin {
    # Use script variables if available.
    if ($env:days -and $env:days -notlike "null") {
        $Days = $env:Days
    }

    # Change negative days to the expected positive days
    if ($Days -lt 0) {
        $Days = 0 - $Days
    }

    # Date where an account is considered inactive.
    $InactivityCutOff = (Get-Date).AddDays(-$Days)

    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    function Test-IsDomainController {
        $OS = if ($PSVersionTable.PSVersion.Major -lt 5) {
            Get-WmiObject -Class Win32_OperatingSystem
        }
        else {
            Get-CimInstance -ClassName Win32_OperatingSystem
        }

        if ($OS.ProductType -eq "2") {
            return $true
        }
    }

    # We'll want to warn that we're unable to check the actual Azure AD account 
    # (it requires O365 credentials and a powershell module both of which are not supported by this script).
    function Test-IsAzureJoined {
        try {
            $dsreg = dsregcmd.exe /status | Select-String "AzureAdJoined : YES"
        }
        catch {
            return $False
        }
        if ($dsreg) { return $True }
    }

    # For Non-Domain Controllers we'll check net user for the information we need.
    function Get-NetAccountInfo {
        [CmdletBinding()]
        param(
            [Parameter()]
            [string]$User,
            [Parameter()]
            [switch]$Domain
        )
        process {
            # Get user info from net.exe user
            $netuser = if ($Domain) { net.exe user $user /Domain }else { net.exe user $user }

            $success = $netuser | Select-String 'The command completed successfully.'
            if (-not $success) {
                throw "Failed to retrieve account info for user $user!"
            }

            #Pre-formatted Object
            $Object = New-Object psobject -Property @{
                Username        = $User
                Name            = "$(($netuser | Select-String 'Full Name') -split '  ' | Select-Object -Last 1)".Trim()
                Enabled         = "$(($netuser | Select-String 'Account active') -split '  ' | Select-Object -Last 1)".Trim()
                LastLogon       = "$(($netuser | Select-String 'Last logon') -split '  ' | Select-Object -Last 1)".Trim()
                PasswordLastSet = "$(($netuser | Select-String 'Password last set') -split '  ' | Select-Object -Last 1)".Trim()
            }

            # Formatted object using PowerShell datatypes (for easier parsing later).
            New-Object psobject -Property @{
                Username        = $Object.Username
                Name            = $Object.Name
                Enabled         = if ($Object.Enabled -eq "Yes") { $True }elseif ($Object.Enabled -eq "No") { $False }else { $Object.Enabled }
                LastLogon       = try { Get-Date $Object.LastLogon }catch { $Object.LastLogon };
                PasswordLastSet = try { Get-Date $Object.PasswordLastSet }catch { $Object.PasswordLastSet }
            }
        }
    }
}
process {

    # If it's an azure joined machine we should warn that we're not checking any of the Azure AD Accounts.
    if (Test-IsAzureJoined) {
        Write-Warning -Message "This script is unable to check Azure AD accounts however this script will check the local accounts on this machine."
    }

    $Report = New-Object System.Collections.Generic.List[object]

    # Warn if ad accounts are not able to be checked.
    if (-not (Test-IsDomainController) -and (Test-IsDomainJoined) -and -not (Test-ComputerSecureChannel)) {
        Write-Warning "Domain is not reachable! We'll be unable to check active directory accounts!"
    }

    # There are two ways this script will check for an inactive account one of which uses the Active Directory PowerShell module which is only availalbe on Domain Controllers / machines with RSAT installed.
    if (-not (Test-IsDomainController)) {

        # Compile a list of users to check.
        $Users = if ($PSVersionTable.PSVersion.Major -lt 5) {
            Get-WmiObject -Class "win32_UserAccount"        
        }
        else {
            Get-CimInstance -Class "win32_UserAccount"
        }

        # Grab the account info using net user (which is slightly different if it's a domain account or not).
        $Accounts = foreach ($User in $Users) {
            if ($User.Domain -ne $env:COMPUTERNAME ) {
                Get-NetAccountInfo -User $User.Name -Domain
            }
            else {
                Get-NetAccountInfo -User $User.Name
            }
        }
    }
    else {
        # Older OS's need to have the module manually imported.
        try {
            Import-Module ActiveDirectory
        }
        catch {
            Write-Error -Message "[Error] Failed to import PowerShell Active Directory Module. Is RSAT installed?" -Category DeviceError -Exception (New-Object System.Exception)
        }

        # Compile a list of users with the relevant attributes
        $Users = Get-AdUser -Filter * -Properties SamAccountName, DisplayName, PasswordLastSet, lastLogonTimestamp, lastLogon, Enabled
        
        # Convert that into a more parseable object
        $Accounts = foreach ($User in $Users) {
            $LastLogon = [datetime]::FromFileTime($User.lastLogon)
            $LastLogonTimeStamp = [datetime]::FromFileTime($User.LastLogonTimestamp)
            New-Object psobject -Property @{
                Username        = $User.SamAccountName
                Name            = $User.DisplayName
                Enabled         = $User.Enabled
                LastLogon       = if ($LastLogon -gt $LastLogonTimeStamp) { $LastLogon }else { $LastLogonTimeStamp }
                PasswordLastSet = $User.PasswordLastSet
            }
        }
    }

    # Compile a list of accounts that could be considered inactive
    $InactiveAccounts = $Accounts | Where-Object { ($_.LastLogon -eq "Never" -or $_.LastLogon -lt $InactivityCutOff) -and $_.PasswordLastSet -lt $InactivityCutOff }

    # Filter out disabled accounts if we're asked to.
    if ($IncludeDisabled) {
        $InactiveAccounts | ForEach-Object { $Report.Add($_) }
    }
    else {
        $InactiveAccounts | Where-Object { $_.Enabled -notlike $False } | ForEach-Object { $Report.Add($_) }
    }

    # If no inactive accounts exit
    if (-not $Report) {
        Write-Host "No inactive accounts detected!"
        exit 0
    }

    Write-Warning "Inactive accounts detected!"
    $Report | Format-Table -AutoSize -Property Username, PasswordLastSet, LastLogon, Enabled | Out-String | Write-Host
    exit 1
}
end {
    
    
    
}


