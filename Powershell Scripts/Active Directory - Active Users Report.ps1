# Generates a report for the number of active users in active directory that have logged in the specified time frame.
#Requires -Version 5.1

<#
.SYNOPSIS
    Generates a report for the number of active users in active directory that have logged in the specified time frame.
.DESCRIPTION
    Generates a report for the number of active users in active directory that have logged in the specified time frame.

.EXAMPLE
    (No Parameters)
    
    Number of active users: 2
    Total users (including active and inactive): 5
    Percent Active: 40%

    SamAccountName UserPrincipalName   mail           LastLogonDate      
    -------------- -----------------   ----           -------------      
    kbohlander     kbohlander@test.lan                6/5/2023 8:58:20 AM
    tuser          tuser@test.lan      tuser@test.com 6/6/2023 8:30:23 AM

PARAMETER: -NumberOfDays "ReplaceWithAnumber"
    How long ago in days to report on.
.EXAMPLE
    -NumberOfDays "1" (If today was 6/7/2023)
    
    Number of active users: 2
    Total users (including active and inactive): 5
    Percent Active: 40%

    SamAccountName UserPrincipalName   mail           LastLogonDate      
    -------------- -----------------   ----           -------------      
    tuser          tuser@test.lan      tuser@test.com 6/6/2023 8:30:23 AM

PARAMETER: -ExcludeDisabledUsers
    Excludes the user from the report if they're currently disabled.

PARAMETER: -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    Name of a multiline custom field to save the results to.
.EXAMPLE
    -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    
    Number of active users: 2
    Total users (including active and inactive): 5
    Percent Active: 40%

    SamAccountName UserPrincipalName   mail           LastLogonDate      
    -------------- -----------------   ----           -------------      
    kbohlander     kbohlander@test.lan                6/5/2023 8:58:20 AM
    tuser          tuser@test.lan      tuser@test.com 6/6/2023 8:30:23 AM
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$NumberOfDays = 30,
    [Parameter()]
    [String]$CustomFieldName,
    [Parameter()]
    [Switch]$ExcludeDisabledUsers = [System.Convert]::ToBoolean($env:excludeDisabledUsersFromReport)
)

begin {
    # Tests for administrative rights which is required to get the last logon date.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Tests if the device the script is running on is a dmona controller.
    function Test-IsDomainController {
        return $(Get-CimInstance -ClassName Win32_OperatingSystem).ProductType -eq 2
    }

    # This function is to make it easier to set Ninja Custom Fields.

    # Todays date
    $Today = Get-Date

    if ($env:numberOfDaysToReportOn -and $env:numberOfDaysToReportOn -notlike "null") { $NumberOfDays = $env:numberOfDaysToReportOn }
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomFieldName = $env:customFieldName }
}
process {
    # Erroring out when ran without administrator rights
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Erroring out when ran on a non-domain controller
    if (-not (Test-IsDomainController)) {
        Write-Error -Message "The script needs to be run on a domain controller!"
        exit 1
    }

    # If disabled users are to be excluded we're going to fetch different properties and Filter out disabled users
    if ($ExcludeDisabledUsers) {
        $Users = Get-ADUser -Filter * -Properties SamAccountName, UserPrincipalName, mail, LastLogonDate, Enabled | 
            Where-Object { $_.Enabled -eq $True }
        $ActiveUsers = Get-ADUser -Filter { LastLogonDate -ge 0 } -Properties SamAccountName, UserPrincipalName, mail, LastLogonDate, Enabled |
            Where-Object { (New-TimeSpan $_.LastLogonDate $Today).Days -le $NumberOfDays -and $_.Enabled -eq $True } |
            Select-Object SamAccountName, UserPrincipalName, mail, LastLogonDate
    }
    else {
        $Users = Get-ADUser -Filter * -Properties SamAccountName, UserPrincipalName, mail, LastLogonDate
        $ActiveUsers = Get-ADUser -Filter { LastLogonDate -ge 0 } -Properties SamAccountName, UserPrincipalName, mail, LastLogonDate |
            Where-Object { (New-TimeSpan $_.LastLogonDate $Today).Days -le $NumberOfDays } |
            Select-Object SamAccountName, UserPrincipalName, mail, LastLogonDate
    }

    # Creating a generic list to start assembling the report
    $Report = New-Object System.Collections.Generic.List[string]

    # Actual report assembly each section will be print on its own line
    $Report.Add("Active users: $(($ActiveUsers | Measure-Object).Count)")
    $Report.Add("Total users: $(($Users | Measure-Object).Count)")
    $Report.Add("Percent Active: $(if((($Users | Measure-Object).Count) -gt 0){[Math]::Round(($ActiveUsers | Measure-Object).Count / (($Users | Measure-Object).Count) * 100, 2)}else{0})%")

    # Set's up table to use in the report
    $Report.Add($($ActiveUsers | Format-Table | Out-String))

    if ($ActiveUsers) {
        # Exports report to activity log
        $Report | Write-Host

        if ($CustomFieldName) {
            # Saves report to custom field.
            try {
            }
            catch {
                # If we ran into some sort of error we'll output it here.
                Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
                exit 1
            }
        }
    }
    else {
        Write-Error "[Error] No active users found!"
        exit 1
    }
}
end {

}

