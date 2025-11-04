# Gets the last login time for all computers in Active Directory.
#Requires -Version 5.1

<#
.SYNOPSIS
    Gets the last login time for all computers in Active Directory.
.DESCRIPTION
    Gets the last login time for all computers in Active Directory.
    The last login time is retrieved from the LastLogonTimeStamp property of the computer object.
    If the user name cannot be retrieved from an offline computer, the script will return Unknown.
    If the computer name cannot be retrieved, the script will return Unknown.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##

PARAMETER: -WysiwygCustomField "myWysiwygCustomField"
    Saves results to a WYSIWYG Custom Field.
.EXAMPLE
    -WysiwygCustomField "myWysiwygCustomField"
    ## EXAMPLE OUTPUT WITH WysiwygCustomField ##
    [Info] Found 10 computers.
    [Info] Attempting to set Custom Field 'myWysiwygCustomField'.
    [Info] Successfully set Custom Field 'myWysiwygCustomField'!

PARAMETER: -QueryForLastUserLogon "true"
    When checked, the script will query for the last user logon time for each computer.
    Note that this will take longer to run and will try to connect to each computer in the domain.
.EXAMPLE
    -QueryForLastUserLogon "true"
    ## EXAMPLE OUTPUT WITH QueryForLastUserLogon ##
    [Warn] Remote computer WIN-1234567891 is not available.
    [Info] Found 2 computers.

    Computer                  Last Logon Date   Last Login in Days   User
    --------                  ---------------   ------------------   ----
    WIN-1234567891            2024-04-01 12:00   0                   Unknown
    WIN-1234567890            2024-04-01 12:00   0                   Fred
    WIN-9876543210            2023-04-01 12:00   32                  Bob

.NOTES
    Minimum OS Architecture Supported: Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$WysiwygCustomField,
    [Parameter()]
    [Switch]$QueryForLastUserLogon
)

begin {
    # CIM timeout
    $CIMTimeout = 10

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

}
process {
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Get Script Variables and override parameters with them
    if ($env:wysiwygCustomField -and $env:wysiwygCustomField -notlike "null") {
        $WysiwygCustomField = $env:wysiwygCustomField
    }
    if ($env:queryForLastUserLogon -and $env:queryForLastUserLogon -notlike "null") {
        if ($env:queryForLastUserLogon -eq "true") {
            $QueryForLastUserLogon = $true
        }
        else {
            $QueryForLastUserLogon = $false
        }
    }

    # Check that Active Directory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "[Error] Active Directory module is not available. Please install it and try again."
        exit 1
    }

    # Get the computer system from the CIM
    $ComputerSystem = $(Get-CimInstance -ClassName Win32_ComputerSystem)

    # Check if this script is running on a domain joined computer
    if ($ComputerSystem.PartOfDomain -eq $false) {
        Write-Host "[Error] This script must be run on a domain joined computer."
        exit 1
    }

    # Check if this script is running on a domain controller
    switch ($ComputerSystem.DomainRole) {
        0 { Write-Host "[Info] Running script on a Standalone Workstation." }
        1 { Write-Host "[Info] Running script on a Member Workstation." }
        2 { Write-Host "[Info] Running script on a Standalone Server." }
        3 { Write-Host "[Info] Running script on a Member Server." }
        4 { Write-Host "[Info] Running script on a Backup Domain Controller." }
        5 { Write-Host "[Info] Running script on a Primary Domain Controller." }
    }

    # Get the SearchBase for the domain
    $Domain = "DC=$($ComputerSystem.Domain -split "\." -join ",DC=")"

    # Get Computers from Active Directory
    try {
        $Computers = Get-ADComputer -Filter { (Enabled -eq $true) } -Properties Name, LastLogonTimeStamp -SearchBase "$Domain" -ErrorAction Stop
    }
    catch {
        Write-Host "[Error] Failed to get computers. Make sure this is running on a domain controller."
        exit 1
    }

    $IsFirstError = $true

    $LastLogonInfo = foreach ($Computer in $Computers) {
        try {
            # Get the LastLogonTimeStamp for the computer from Active Directory
            $PCInfo = Get-ADComputer -Identity $Computer.Name -Properties LastLogonTimeStamp -ErrorAction Stop | Select-Object -Property @(
                @{Name = "Computer"; Expression = { $_.Name } },
                @{Name = "LastLogon"; Expression = { [DateTime]::FromFileTime($_.LastLogonTimeStamp) } }
            )
        }
        catch {
            # This should only happen if the script is not running as the system user on a domain controller or not as a domain admin
            Write-Debug "[Debug] $($_.Exception.Message)"
            Write-Host "[Warn] Failed to get details for $($Computer.Name) from Active Directory. Skipping."
            continue
        }
        try {
            if ($QueryForLastUserLogon) {
                # Get the User Principal Name from the computer
                $LastUserLogonInfo = Get-CimInstance -ClassName Win32_UserProfile -ComputerName $Computer.name -OperationTimeoutSec $CIMTimeout -ErrorAction Stop | Where-Object { $_.LocalPath -like "*Users*" } | Sort-Object -Property LastUseTime | Select-Object -Last 1
                $SecIdentifier = New-Object System.Security.Principal.SecurityIdentifier($LastUserLogonInfo.SID) -ErrorAction Stop
                $UserName = $SecIdentifier.Translate([System.Security.Principal.NTAccount])
            }
        }
        catch {
            if ($null -eq $UserName) {
                if ($IsFirstError) {
                    # Only show on the first error
                    Write-Debug "[Debug] $($_.Exception.Message)"
                    Write-Host "[Error] Failed to connect to 1 or more computers via Get-CimInstance."
                    $IsFirstError = $false
                }
                Write-Host "[Warn] Remote computer $($Computer.Name) is not available or could not be queried."
            }
        }

        if ($null -eq $UserName) {
            $UserName = [PSCustomObject]@{
                value = "Unknown"
            }
        }
        if ($null -eq $PCInfo.LastLogon) {
            $PCInfo = [PSCustomObject]@{
                Computer  = $Computer.Name
                LastLogon = "Unknown"
            }
            Write-Host "[Warn] Failed to get LastLogonTimeStamp for $($Computer.Name)."
        }

        # Get the number of days since the last login
        $LastLoginDays = try {
            0 - $(Get-Date -Date $PCInfo.LastLogon).Subtract($(Get-Date)).Days
        }
        catch {
            # Return unknown if the date is invalid or does not exist
            "Unknown"
        }

        # Output the results
        if ($QueryForLastUserLogon) {
            [PSCustomObject]@{
                'Computer'           = $PCInfo.Computer
                'Last Logon Date'    = $PCInfo.LastLogon
                'Last Login in Days' = $LastLoginDays
                'User'               = $UserName.value
            }
        }
        else {
            [PSCustomObject]@{
                'Computer'           = $PCInfo.Computer
                'Last Logon Date'    = $PCInfo.LastLogon
                'Last Login in Days' = $LastLoginDays
            }
        }

        $PCInfo = $null
        $LastUserLogonInfo = $null
        $SecIdentifier = $null
        $UserName = $null
    }

    # Output the number of computers found
    if ($LastLogonInfo -and $LastLogonInfo.Count -gt 0) {
        Write-Host "[Info] Found $($LastLogonInfo.Count) computers."
    }
    else {
        Write-Host "[Error] No computers were found."
        $ExitCode = 1
    }

    function Write-LastLoginInfo {
        param ()
        $LastLogonInfo | Format-Table -AutoSize | Out-String -Width 4000 | Write-Host
    }

    # Save the results to a custom field
    if ($WysiwygCustomField) {
        Write-Host ""
        Write-Host "Note: Custom field '$WysiwygCustomField' was specified but NinjaOne integration has been removed."
        Write-Host "All output has been displayed above."
    }
    else {
        Write-LastLoginInfo
    }

    exit $ExitCode
}
end {

}
