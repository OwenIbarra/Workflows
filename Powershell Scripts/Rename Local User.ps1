# Renames a local account.
#Requires -Version 2.0

<#
.SYNOPSIS
    Renames a local account.
.DESCRIPTION
    Renames a local account.
.EXAMPLE
    -CurrentName "jsmith" -NewName "JohnSmith"
    
    WARNING: This script does not support making changes to domain accounts.
    Successfully renamed jsmith to JohnSmith!

PARAMETER: -CurrentName "ReplaceMeWithTheCurrentUsername"
    Enter the existing username of the local account you wish to rename. This must be the current, valid username for the account.

PARAMETER: -NewName "ReplaceMeWithANewUsername"
    Enter the new username for the local account. This will be the account's username after the script is executed.

PARAMETER: -DisplayName "Replace Me With New Display Name"
    Enter the new display name for the local account.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012
    Release Notes: Added script variables, input validation, updated help block, and added warnings for domain and azure joined machines.
.COMPONENT
    LocalBuiltInAccountManagement
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CurrentName,
    [Parameter()]
    [String]$NewName,
    [Parameter()]
    [String]$NewDisplayName
)

begin {
    # Retrieve script form variables and replace the parameters with them, handling 'null' values.
    if ($env:currentUsername -and $env:currentUsername -notlike "null") { $CurrentName = $env:currentUsername }
    if ($env:newUsername -and $env:newUsername -notlike "null") { $NewName = $env:newUsername }
    if ($env:newDisplayName -and $env:newDisplayName -notlike "null") { $NewDisplayName = $env:newDisplayName }

    # Check if the new username has been entered, otherwise exit with an error.
    if (-not $NewName) {
        Write-Host -Object "[Error] Please enter the new username for the desired user."
        exit 1
    }

    # Check if the current username has been provided, otherwise exit with an error.
    if (-not $CurrentName) {
        Write-Host -Object "[Error] Please enter the current username that you wish to change."
        exit 1
    }

    # Check the new username for illegal characters and exit with an error if found.
    if ($NewName -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|,|"|@') {
        Write-Host -Object ("[Error] $NewName contains one of the following invalid characters." + ' " [ ] : ; | = + * ? < > / \ , @')
        exit 1
    }

    # Check the current username for illegal characters and exit with an error if found.
    if ($CurrentName -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|,|"|@') {
        Write-Host -Object ("[Error] $CurrentName contains one of the following invalid characters." + ' " [ ] : ; | = + * ? < > / \ , @')
        exit 1
    }

    # Ensure that the new username does not contain any spaces.
    if ($NewName -match '\s') {
        Write-Host -Object "[Error] '$NewName' contains a space. Usernames cannot contain spaces."
        exit 1
    }

    # Ensure the new username does not exceed 20 characters in length.
    $UserNameCharacters = $NewName | Measure-Object -Character | Select-Object -ExpandProperty Characters
    if ($UserNameCharacters -gt 20) {
        Write-Host -Object "[Error] '$NewName' is too long. The username must be 20 characters or fewer."
        exit 1
    }

    # Function to retrieve local group members using the net command.
    function Get-NetLocalGroup {
        param(
            [Parameter()]
            [String]$Group = "Users"
        )
        Invoke-Command -ScriptBlock { net.exe localgroup $Group } | Where-Object { $_ -AND $_ -notmatch "command completed successfully" } | Select-Object -Skip 4
    }

    # Function to check if the script is running with elevated permissions (as Administrator).
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Function to check if the machine is a Domain Controller.
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

    # Function to check if the machine is joined to a domain.
    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    # Function to check if the machine is Azure AD joined.
    function Test-IsAzureJoined {
        if ([environment]::OSVersion.Version.Major -ge 10) {
            $dsreg = dsregcmd.exe /status | Select-String "AzureAdJoined : YES"
        }
    
        if ($dsreg) { return $True }else { return $False }
    }

    # Initialize exit code.
    $ExitCode = 0
}

process {
    # Check if the script is running with elevated (Administrator) privileges.
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }
    
    # Warn if the machine is joined to a domain, as the script does not support domain accounts.
    if (Test-IsDomainJoined) {
        Write-Warning -Message "This script does not support making changes to domain accounts."
    }
    
    # Exit if the machine is a domain controller, as the script does not support domain accounts.
    if (Test-IsDomainController) {
        Write-Host -Object "[Error] This script does not support making changes to domain accounts. Please do not run this on a domain controller."
        exit 1
    }

    # Warn if the machine is Azure AD joined, as the script does not support Azure AD accounts.
    if (Test-IsAzureJoined) {
        Write-Warning -Message "This script does not support making changes to Microsoft Entra / Azure AD accounts."
    }

    # Check if the new username already exists among local accounts and exit if it does.
    if ((Get-NetLocalGroup) -contains $NewName) {
        Write-Host -Object "[Error] A local account for the user $NewName already exists!"
        exit 1
    }

    # Check if the current username exists among local accounts and exit if it does not.
    if ((Get-NetLocalGroup) -notcontains $CurrentName) {
        Write-Host -Object "[Error] A local account for the user $CurrentName does not exist!"
        exit 1
    }

    # Attempt to rename the user account.
    try {
        # Use WMI for PowerShell versions less than 5, otherwise use the Rename-LocalUser cmdlet.
        if ($PSversionTable.PSVersion.Major -lt 5) {
            (Get-WmiObject Win32_UserAccount -Filter "name='$CurrentName'").Rename("$NewName")
        }
        else {
            Rename-LocalUser -Name $CurrentName -NewName $NewName -ErrorAction Stop
        }
    }
    catch {
        # Catch and display any errors encountered during the renaming process.
        Write-Host -Object "[Error] $($_.Exception.Message)."
        exit 1
    }

    # Verify if the rename operation was successful.
    if ((Get-NetLocalGroup) -contains $NewName -and (Get-NetLocalGroup) -notcontains $CurrentName) {
        Write-Host -Object "Successfully renamed $CurrentName to $NewName!"
    }
    else {
        Write-Host -Object "[Error] Failed to update $CurrentName to $NewName!"
        exit 1
    }

    # Update the display name
    if($NewDisplayName){
        Invoke-Command -ScriptBlock { net.exe user $NewName /fullname:"$NewDisplayName" } | Where-Object { $_ -AND $_ -notmatch "command completed successfully" }
    }

    # Check if updating display name was successful
    $CurrentDisplayName = Invoke-Command -ScriptBlock { net.exe user $NewName } | Where-Object { $_ -AND $_ -match "Full Name" -and $_ -match $([regex]::Escape($NewDisplayName)) }
    if($NewDisplayName -and $CurrentDisplayName){
        Write-Host -Object "Successfully updated display name to $NewDisplayName!"
    }elseif($NewDisplayName){
        Write-Host -Object "[Error] Failed to update display name!"
        exit 1
    }

    # Exit script with the defined exit code.
    exit $ExitCode
}

end {
    
    
    
}


