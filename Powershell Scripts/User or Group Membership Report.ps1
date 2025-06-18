# This will output the user or group membership for the specified group or user.

<#
.SYNOPSIS
    This will output the user or group membership for the specified group or user.
.DESCRIPTION
    This will output the user or group membership for the specified group or user.

PARAMETER: -Usernames "ReplaceMe","ReplaceMe2" (Quotations are not necessary if using script variables)
    Grabs the group membership for each user you specified.
.EXAMPLE
    -Usernames "Administrator" (Windows 10 - Domain Joined)
    
    A Domain Joined Computer was detected. Attempting to search Active Directory...
    WARNING: The Active Directory Powershell Module was not found please install RSAT for better results.
    Searching Active Directory using the ADSI Searcher...
    Searching local groups...
    #### User Membership ####

    Group                       Group Type Member       
    -----                       ---------- ------       
    Administrators              Domain     Administrator
    Administrators              Local      Administrator
    Domain Admins               Domain     Administrator
    Domain Users                Domain     Administrator
    Enterprise Admins           Domain     Administrator
    Group Policy Creator Owners Domain     Administrator
    Schema Admins               Domain     Administrator

PARAMETER: -Groups "ReplaceMe","ReplaceMe2" (Quotations are not necessary if using script variables)
    Grabs the user membership for each group you specified.
.EXAMPLE
    -Groups "Domain Admins" (Server 2008 - Domain Controller)

    A Domain Joined Computer was detected. Attempting to search Active Directory...
    Searching Active Directory using the Active Directory Powershell Module...
    Searching local groups...
    #### Group Membership ####

    Member        Group Type Group        
    ------        ---------- -----        
    Administrator Domain     Domain Admins
    kbohlander    Domain     Domain Admins

PARAMETER: -LastLoggedInUser
    Checks the last logged in user.

PARAMETER: -AzureAD
    Adds 'AzureAD\' prefix to usernames

PARAMETER: -CustomField "ReplaceMeWithAMultilineCustomField"
    Outputs the results to a multiline customfield of your choice.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2008
    Release Notes: Updated Calculated Name
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String[]]$Usernames,
    [Parameter()]
    [String[]]$Groups,
    [Parameter()]
    [Switch]$AzureAD = [System.Convert]::ToBoolean($env:azureadAccounts),
    [Parameter()]
    [Switch]$LastLoggedInUser = [System.Convert]::ToBoolean($env:getLastLoggedInUserMembership),
    [Parameter()]
    [String]$CustomField
)

begin {
    # If script variables are used replace the parameters
    if ($env:usernames -and $env:usernames -notlike "null") {
        $Usernames = $env:usernames -split ',' | ForEach-Object { $_.trim() }
    }

    if ($env:groups -and $env:groups -notlike "null") {
        $Groups = $env:groups -split ',' | ForEach-Object { $_.trim() }
    }

    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }

    # Microsoft always adds AzureAD\ as a prefix to AzureAD Accounts. 
    if($Usernames -and $AzureAD){
        Write-Warning "Adding AzureAD\ prefix to all usernames in the list."
        $AzureAccounts = $Usernames | ForEach-Object {
            "AzureAD\$_"
        }
        $Usernames = $AzureAccounts
    }

    # We'll check the last login registry key and replace the extra info we don't want / need
    if($LastLoggedInUser){
        $Regkey = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI").LastLoggedOnSAMUser
        if($Regkey){
            if($Regkey -notlike "AzureAD\*"){
                $LastLogon = $Regkey -replace ".*\\"
            }else{
                $LastLogon = $Regkey
            }

            Write-Host "Adding $LastLogon to the list!"
            $Usernames += $LastLogon
        }else{
            Write-Warning "No user has previously signed in (you may need to reboot). Skipping!"
        }
    }

    # Error out if we're missing information
    if (-not ($Usernames) -and -not ($Groups)) {
        Write-Error "You must specify at least 1 group or 1 user to get the membership for."
        Exit 1
    }

    # Check if domain joined.
    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    # When executed as System net localgroup gives an error. This will grab and filter the groups using a wmi query.
    function Get-AllLocalGroups {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Get-CimInstance -Class Win32_Group | Where-Object { $_.LocalAccount -eq $True } | Select-Object -ExpandProperty Name
        }
        else {
            Get-WmiObject -Class Win32_Group | Where-Object { $_.LocalAccount -eq $True } | Select-Object -ExpandProperty Name
        }
    }
}
process {

    if ($Usernames) {
        $UserResults = New-Object System.Collections.Generic.List[Object]
        if (Test-IsDomainJoined) {
            # The active directory powershell module is prefered but not required
            Write-Host "A Domain Joined Computer was detected. Attempting to search Active Directory..."
            if ((Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue)) {
                Import-Module -Name ActiveDirectory
                Write-Host "Searching Active Directory using the Active Directory Powershell Module..."
                foreach ($User in $Usernames) {
                    Get-ADGroup -Filter * | ForEach-Object {
                        if (Get-ADGroupMember $_ | Where-Object { $_.SamAccountName -like $User }) {
                            $UserResults.Add(
                                (
                                    New-Object psobject -Property @{
                                        Member       = $User
                                        Group        = ($_ | Select-Object -ExpandProperty SamAccountName)
                                        "Group Type" = "Domain"
                                    }
                                )
                            )
                        }
                    }
                }
            }
            else {
                Write-Warning "The Active Directory Powershell Module was not found switching to ADSI Searcher..."
                if (Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
                    Write-Host "Searching Active Directory using the ADSI Searcher..."
                    # If for some reason this script is ran without the active directory powershell module we'll do two adsi searches to get the membership info
                    foreach ($User in $Usernames) {
                        $search = [adsisearcher]"samaccountname=$User"
                        # The memberof search won't include the primary group so we'll have to search separately for that
                        $primarygroup = $search.FindOne().Properties.primarygroupid
                        $primaryGroupSearch = [adsisearcher]"objectclass=group"
                        # When adding a property it always outputs the number of properties currently added.
                        $primaryGroupSearch.PropertiesToLoad.Add("SamAccountName") | Out-Null
                        $primaryGroupSearch.PropertiesToLoad.Add("PrimaryGroupToken") | Out-Null
                        $primaryGroupSearch.FindAll() | ForEach-Object {
                            if ($_.Properties.primarygrouptoken -like $primarygroup) {
                                $UserResults.Add(
                                    (
                                        New-Object psobject -Property @{
                                            Member       = $User
                                            Group        = ($_.Properties.samaccountname | Out-String).Trim()
                                            "Group Type" = "Domain"
                                        }
                                    )
                                )
                            }
                        }
                        $search.FindOne().Properties.memberof | ForEach-Object {
                            $namesearch = [adsisearcher]"distinguishedname=$_"
                            $namesearch.PropertiesToLoad.Add("SamAccountName") | Out-Null
                            $UserResults.Add(
                                (
                                    New-Object psobject -Property @{
                                        Member       = $User
                                        Group        = ($namesearch.FindOne().Properties.samaccountname | Out-String).Trim()
                                        "Group Type" = "Domain"
                                    }
                                )
                            )
                        }
                    }
                }
                else {
                    Write-Warning "A Secure connection to the domain could not be established. Unable to get Active Directory memberships."
                }
            }
        }

        # Grabs the localgroup info using net localgroup
        Write-Host "Searching local groups..."
        $netlocalgroup = Get-AllLocalGroups
        $netlocalgroup | ForEach-Object {
            foreach ($User in $Usernames) {
                if ((net.exe localgroup $_) -replace 'The command completed successfully.' | Select-Object -Skip 6 | Where-Object { $_ -and $_ -like "*$User" }) {
                    $UserResults.Add(
                        (
                            New-Object psobject -Property @{
                                Member       = $User
                                Group        = $_
                                "Group Type" = "Local"
                            }
                        )
                    )
                }
            }
        }

        if ($UserResults) {
            Write-Host "User Membership info found!"
            Write-Host "#### User Membership ####"
            $UserResults | Sort-Object -Property Group | Format-Table -Property Group, "Group Type", Member -AutoSize | Out-String | Write-Host
        }
    }

    # All of this ia pretty similar to grabing the user membership except its searching for the group membership instead of the user
    if ($Groups) {
        $GroupResults = New-Object System.Collections.Generic.List[Object]
        if (Test-IsDomainJoined) {
            Write-Host "A Domain Joined Computer was detected. Attempting to search Active Directory..."
            if ((Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue)) {
                Import-Module -Name ActiveDirectory
                Write-Host "Searching Active Directory using the Active Directory Powershell Module..."
                Get-ADGroup -Filter * | Where-Object { $Groups -contains $_.SamAccountName } | ForEach-Object {
                    $Group = $_.SamAccountName
                    Get-ADGroupMember $_ | ForEach-Object {
                        $GroupResults.Add(
                            (
                                New-Object psobject -Property @{
                                    Member       = $_.SamAccountName
                                    Group        = $Group
                                    "Group Type" = "Domain"
                                }
                            )
                        )
                    }
                }
            }
            else {
                Write-Warning "The Active Directory Powershell Module was not found switching to ADSI Searcher..."
                if (Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
                    Write-Host "Searching Active Directory using the ADSI Searcher..."
                    foreach ($Group in $Groups) {
                        $search = [adsisearcher]"samaccountname=$Group"
                        $search.FindOne().Properties.member | ForEach-Object {
                            $namesearch = [adsisearcher]"distinguishedname=$_"
                            $namesearch.PropertiesToLoad.Add("SamAccountName") | Out-Null
                            $GroupResults.Add(
                                (
                                    New-Object psobject -Property @{
                                        Member       = ($namesearch.FindOne().Properties.samaccountname | Out-String).trim()
                                        Group        = $Group
                                        "Group Type" = "Domain"
                                    }
                                )
                            )
                        }
                    }
                }
                else {
                    Write-Warning "A Secure connection to the domain could not be established. Unable to get Active Directory memberships."
                }
            }
        }

        Write-Host "Searching local groups..."
        $netlocalgroup = Get-AllLocalGroups
        foreach ($Group in $Groups) {
            $netlocalgroup | Where-Object { $_ -eq $Group } | ForEach-Object {
                ((net.exe localgroup $_) -replace 'The command completed successfully.' | Select-Object -Skip 6) | Where-Object { $_ } | ForEach-Object {
                    $GroupResults.Add(
                        (
                            New-Object psobject -Property @{
                                Member       = $_
                                Group        = $Group
                                "Group Type" = "Local"
                            }
                        )
                    )
                }
            }
        }

        if ($GroupResults) {
            Write-Host "Group Membership info found!"
            Write-Host "#### Group Membership ####"
            $GroupResults | Sort-Object -Property Member | Format-Table -Property Member, "Group Type", Group -AutoSize | Out-String | Write-Host
        }
    }

    # If we're outputing to a custom field we'll need to combine our results
    if ($CustomField) {
        $CombinedResults = New-Object System.Collections.Generic.List[Object]

        if ($UserResults) {
            $CombinedResults.Add("### User Results ###")
            $CombinedResults.Add(
                ($UserResults | Sort-Object -Property Group | Format-List -Property Group, "Group Type", Member | Out-String)
            )
            $CombinedResults.Add("")
        }

        if ($GroupResults) {
            $CombinedResults.Add("### Group Results ###")
            $CombinedResults.Add(
                ($GroupResults | Sort-Object -Property Member | Format-List -Property Member, "Group Type", Group | Out-String)
            )
        }

        if ($PSVersionTable.PSVersion.Major -gt 2) {
            Ninja-Property-Set -Name $CustomField -Value ($CombinedResults | Out-String)
        }
        else {
            Write-Warning "Powershell 1 and 2 cannot set custom fields. https://ninjarmm.zendesk.com/hc/en-us/articles/4405408656013"
        }
    }

    # Check if we should error out or not
    if ($GroupResults -or $UserResults) {
        exit 0
    }
    else {
        Write-Error "Failed to find User or Group Membership. Does the user or group exist?"
        exit 1
    }
}
end {
    
    
    
}

