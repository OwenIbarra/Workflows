# Renames domain-joined or non-domain-joined computers. For domain-joined computers, this operation requires either the username of a Domain Admin and the name of a secure field containing their password, or it must be executed with Domain Admin privileges.
#Requires -Version 4

<#
.SYNOPSIS
    Renames domain-joined or non-domain-joined computers. For domain-joined computers, this operation requires either the username of a Domain Admin and the name of a secure field containing their password, or it must be executed with Domain Admin privileges.
.DESCRIPTION
    Renames domain-joined or non-domain-joined computers. For domain-joined computers, this operation requires either the username of a Domain Admin and the name of a secure field containing their password, or it must be executed with Domain Admin privileges.
.EXAMPLE
    -NewName "ReplaceWithNewName"

    WARNING: The changes will take effect after you restart the computer KYLE-WIN10-TEST.

    HasSucceeded OldComputerName           NewComputerName          
    ------------ ---------------           ---------------          
    True         KYLE-WIN10-TEST           ReplaceWithNewName               



    WARNING: This script takes effect after a reboot. Use -Reboot to have this script reboot for you.

PARAMETER: -DomainUser "UsernameForDomainAdmin" -DomainPasswordCustomField "SecureCustomField"
    Domain Joined machines require a domain admins creds when not ran as a Domain Admin (System is not a Domain Admin).

PARAMETER: -Reboot
    Reboots the computer 5 minutes after the script is ran.
.EXAMPLE
    -NewName "ReplaceWithNewName" -Reboot

    This is a domain joined machine. Testing for secure domain connection...
    WARNING: The changes will take effect after you restart the computer KYLE-WIN10-TEST.

    HasSucceeded OldComputerName           NewComputerName          
    ------------ ---------------           ---------------          
    True         KYLE-WIN10-TEST           ReplaceWithNewName               

    WARNING: Reboot specified scheduling reboot for 06/13/2023 12:09:53...

.OUTPUTS
    None
.NOTES
    OS: Win 10+, Server 2012+
    Release Notes: Removed Password Variable, Switched to write-host instead of write-error
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$NewName,
    [Parameter()]
    [String]$DomainUser,
    [Parameter()]
    [String]$DomainPasswordCustomField,
    [Parameter()]
    [Switch]$Reboot = [System.Convert]::ToBoolean($env:reboot)
)

begin {
    # If script forms are used overwrite the params with those values.
    if ($env:newComputerName -and $env:newComputerName -notlike "null") { $NewName = $env:newComputerName }
    if ($env:domainAdminUsername -and $env:domainAdminUsername -notlike "null") { $DomainUser = $env:domainAdminUsername }
    if ($env:domainAdminPasswordCustomField -and $env:domainAdminPasswordCustomField -notlike "null") { $DomainPasswordCustomField = $env:domainAdminPasswordCustomField }

    function Get-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [String]$Name
        )
  
        # We'll redirect error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
        $NinjaPropertyValue = Ninja-Property-Get -Name $Name 2>&1
  
        # If we received some sort of error it should have an exception property and we'll exit the function with that error information.
        if ($NinjaPropertyValue.Exception) { throw $NinjaPropertyValue }
  
        if (-not $NinjaPropertyValue) {
            throw [System.NullReferenceException]::New("The Custom Field '$Name' is empty!")
        }
  
        $NinjaPropertyValue
    }

    # If Domain Password Custom Field provided, retrieve the password, convert it to a secure a string and save it to a variable.
    if ($DomainPasswordCustomField) {
        try {
            Write-Host -Object "Attempting to retrieve password from secure field '$DomainPasswordCustomField'..."
            $DomainPassword = Get-NinjaProperty -Name $DomainPasswordCustomField -ErrorAction Stop | ConvertTo-SecureString -AsPlainText -Force
            Write-Host -Object "Successfully retrieved password from '$DomainPasswordCustomField'."
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Converts the username and password into a powershell credential object
    if ($DomainUser -and $DomainPassword) {
        $Credential = New-Object System.Management.Automation.PsCredential("$DomainUser", $DomainPassword)
    }

    # Checks if script is running as an elevated user
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Check if machine is domain joined
    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    # Check if script is running as System
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    # Check if script is running as a domain admin
    function Test-IsDomainAdmin {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole("Domain Admins")
    }

    # Check if running on a domain controller
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

    # Double check that this script has something to do.
    if ($NewName -eq $env:computername) {
        Write-Host -Object "[Error] New name is the same as the current hostname."
        exit 1
    }

    # Error out if not provided with a new name
    if (-not $Newname) {
        Write-Host -Object "[Error] Please specify a new name!"
        exit 1
    }
}
process {
    # If not running as the system user script needs to be running as an elevated user.
    if (-not (Test-IsElevated) -and -not (Test-IsSystem)) {
        Write-Host -Object "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Warn end-users if theyre giving the computer too long of a name.
    if ($NewName.Length -gt 15) {
        Write-Warning -Message "The New Computer Name $NewName exceeds 15 characters! In some instances you may only see the first 15 characters."
    }

    # Preparing Splat
    $ArgumentList = @{
        "ComputerName" = $env:computername
        "Force"        = $True
        "NewName"      = $NewName
        "PassThru"     = $True
    }

    # If it's domain joined we'll have to check a couple things to make sure this is possible
    if (Test-IsDomainJoined) {
        Write-Host -Object "This is a domain joined machine. Testing for secure domain connection..."

        # We're not going to allow renaming domain controllers
        if (Test-IsDomainController) {
            Write-Host -Object "[Error] This is a domain controller. Please rename manually."
            exit 1
        }

        # The domain controller will need to be reachable for the rename to apply
        if (-not (Test-ComputerSecureChannel)) {
            Write-Host -Object "[Error] A secure connection to the domain controller cannot be established! Please ensure the domain is reachable and there are no machines with identical names!"
            exit 1
        }

        # Domain joined machines require a domain admin to change the name
        if (-not $Credential -and -not (Test-IsDomainAdmin)) {
            Write-Host -Object "[Error] The Domain User and Domain Password is missing. The username and password for a domain admin is required for a domain joined machine!"
            exit 1
        }

        # Adding credentials to the splat
        if ($Credential) {
            $ArgumentList["DomainCredential"] = $Credential
        }
    }

    # Saving the results to check later
    $Result = Rename-Computer @ArgumentList

    # Letting the end-user know the result
    $Result | Format-Table -AutoSize | Out-String | Write-Host

    # Error out on failure
    if (-not $Result.HasSucceeded) {
        Write-Host -Object "[Error] Failed to rename computer!"
        exit 1
    }

    # If a reboot was specified schedule it for 5 minutes from now.
    if ($Reboot) {
        Write-Warning -Message "Reboot specified scheduling reboot for $((Get-Date).AddMinutes(5))..."
        Start-Process "shutdown.exe" -ArgumentList "/r /t 300" -NoNewWindow -Wait
    }
    else {
        Write-Warning -Message "This script takes effect after a reboot. Use the reboot checkbox to have this script reboot for you."
    }
    exit 0
}
end {
    
    
    
}

