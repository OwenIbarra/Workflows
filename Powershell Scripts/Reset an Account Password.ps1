# Resets a users password. Please run on a domain controller to reset an active directory account; otherwise, it will reset a local account.
#Requires -Version 5.1

<#
.SYNOPSIS
    Resets a user's password. Please run on a domain controller to reset an active directory account; otherwise, it will reset a local account.
.DESCRIPTION
    Resets a user's password. Please run on a domain controller to reset an active directory account; otherwise, it will reset a local account.
.EXAMPLE
    -Username "Fred" -PasswordCustomField "secure"

    WARNING: This system is not a domain controller but is domain-joined. Resetting domain accounts is only supported on Domain Controllers.
    WARNING: Assuming you're trying to reset a local account on a domain-joined machine.
    
    Attempting to set Custom Field 'secure'.
    Successfully set Custom Field 'secure'!

    Successfully reset password for 'Fred'.

PARAMETER: -Username "NameOfAccountYouWouldLikeToReset"
    Username of the user you would like to reset the password for.

PARAMETER: -PasswordCustomField "NameOfSecureFieldToStorePassword"
    Name of a secure Custom Field to store the randomly generated password to.

PARAMETER: -PasswordLength "20"
    Desired length for the randomly generated password.

PARAMETER: -PasswordExpireOption "User Must Change Password"
    Specifies the password expiration policy. Options include "User Must Change Password" to require a password change at next login, "Password Never Expires" to keep the password from expiring, and "Neither" for standard password expiration.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated Calculated Name, removed checkbox for domain accounts, switched to generating password and storing it into a custom field. 
.COMPONENT
    ManageUsers
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Username,
    [Parameter()]
    [String]$PasswordCustomField,
    [Parameter()]
    [long]$PasswordLength,
    [Parameter()]
    [String]$PasswordExpireOption
)
    
begin {
    # Replace preset parameters with script variables.
    if ($env:resetUsername -and $env:resetUsername -notlike "null") { $Username = $env:resetUsername }
    if ($env:customFieldToStorePassword -and $env:customFieldToStorePassword -notlike "null") { $PasswordCustomField = $env:customFieldToStorePassword }
    if ($env:passwordLength -and $env:passwordLength -notlike "null") { $PasswordLength = $env:passwordLength }
    if ($env:passwordExpireOptions -and $env:passwordExpireOptions -notlike "null") { $PasswordExpireOption = $env:passwordExpireOptions }

    # Check if the username variable is empty. If it is, output an error message and exit with status code 1.
    if (!$Username) {
        Write-Host -Object "[Error] The username of the user you would like to reset is required."
        exit 1
    }

    # Ensure username does not contain illegal characters.
    if ($Username -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|,|"|@') {
        Write-Host -Object ("[Error] $Username contains one of the following invalid characters." + ' " [ ] : ; | = + * ? < > / \ , @')
        exit 1
    }

    # Ensure the username does not contain spaces.
    if ($Username -match '\s') {
        Write-Host -Object "[Error] '$Username' contains a space."
        exit 1
    }

    # Ensure the username is not longer than 20 characters.
    $UsernameCharacters = $Username | Measure-Object -Character | Select-Object -ExpandProperty Characters
    if ($UsernameCharacters -gt 20) {
        Write-Host -Object "[Error] '$Username' is too long. The username needs to be less than or equal to 20 characters."
        exit 1
    }

    # Verify that a password length has been specified, exit if not.
    if (!$PasswordLength) {
        Write-Host -Object "[Error] You must specify a password length."
        exit 1
    }

    # Ensure the specified password length is between 8 and 199 characters, exit if outside this range.
    if ($PasswordLength -lt 8 -or $PasswordLength -ge 200) {
        Write-Host -Object "[Error] Password length must be at least 8 and less than 200. '$PasswordLength' is invalid."
        exit 1
    }

    # Check for the presence of a custom field to store the password, exit if it is missing.
    if (!$PasswordCustomField) {
        Write-Host -Object "[Error] A custom field to store the password is required!"
        exit 1
    }

    # Ensure the custom field does not contain spaces, exit if it does.
    if ($PasswordCustomField -match '\s') {
        Write-Host -Object "[Error] The script requires the name of the custom field not the label."
        Write-Host -Object "https://ninjarmm.zendesk.com/hc/en-us/articles/360060920631-Custom-Fields-Configuration-Device-Role-Fields"
        exit 1
    }

    # Validate that the password expiration option provided is one of the allowed values, exit if it is not.
    $ValidExpireOption = "User Must Change Password", "Password Never Expires", "Neither"
    if ($PasswordExpireOption -and $ValidExpireOption -notcontains $PasswordExpireOption) {
        Write-Host -Object "[Error] Invalid password expire option given. Must be either 'User Must Change Password' or 'Password Never Expires' or 'Neither'"
        exit 1
    }

    
    # Microsoft default password policy
    $PasswordPolicy = [PSCustomObject]@{
        MinimumLength = 0
        Complexity    = 1
    }

    # Export the security policy to a file and wait for the process to complete.
    $Arguments = @(
        "/export"
        "/cfg"
        "$env:TEMP\secconfig.cfg"
    )
    $SecurityExport = Start-Process -FilePath "secedit.exe" -ArgumentList $Arguments -PassThru -Wait -WindowStyle Hidden

    # Check if the export was successful; if not, assume default Microsoft policy.
    if ($SecurityExport.ExitCode -ne 0) {
        Write-Host -Object "[Error] Failed to retrieve password complexity policy. Assuming Microsoft Default policy is in effect."
    }
    else {
        $SecurityPolicy = Get-Content -Path "$env:TEMP\secconfig.cfg"

        $PasswordLengthField = $SecurityPolicy | Select-String "MinimumPasswordLength"
        $PasswordPolicy.MinimumLength = ($PasswordLengthField -split "=").Trim()[1]
    }

    # Remove the exported security policy file if it exists.
    if (Test-Path -Path "$env:TEMP\secconfig.cfg" -ErrorAction SilentlyContinue) {
        Remove-Item -Path "$env:TEMP\secconfig.cfg"
    }

    # Check if the requested password length meets the minimum requirements of the security policy, exit if it does not.
    if ($PasswordLength -lt $PasswordPolicy.MinimumLength) {
        Write-Host "[Error] The minimum password length of $($PasswordPolicy.MinimumLength) is greater than the password length you requested to generate ($PasswordLength)."
        exit 1
    }

    # Check if script is running with local administrator rights.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { 
            Write-Output $True 
        }
        else { 
            Write-Output $False 
        }
    }

    # Generate a cryptographically secure password.
    function New-SecurePassword {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)]
            [int]$Length = 16,
            [Parameter(Mandatory = $false)]
            [switch]$IncludeSpecialCharacters
        )
        # .NET class for generating cryptographically secure random numbers
        $cryptoProvider = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $baseChars = "abcdefghjknpqrstuvwxyzABCDEFGHIJKMNPQRSTUVWXYZ0123456789"
        $SpecialCharacters = '!@#$%&-'
        $passwordChars = $baseChars + $(if ($IncludeSpecialCharacters) { $SpecialCharacters } else { '' })
        $password = for ($i = 0; $i -lt $Length; $i++) {
            $byte = [byte[]]::new(1)
            $cryptoProvider.GetBytes($byte)
            $charIndex = $byte[0] % $passwordChars.Length
            $passwordChars[$charIndex]
        }
        
        return $password -join ''
    }

    # Check if the script is currently running on a Domain Controller.
    function Test-IsDomainController {
        $OS = if ($PSVersionTable.PSVersion.Major -lt 5) {
            Get-WmiObject -Class Win32_OperatingSystem
        }
        else {
            Get-CimInstance -ClassName Win32_OperatingSystem
        }
    
        if ($OS.ProductType -eq "2") {
            return $True
        }
    }

    # Check if the script is running on a Domain-Joined computer.
    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    # Check if the script is running on an Entra-Joined computer.
    function Test-IsAzureJoined {
        if ([environment]::OSVersion.Version.Major -ge 10) {
            $dsreg = dsregcmd.exe /status | Select-String "AzureAdJoined : YES"
        }
    
        if ($dsreg) { 
            return $True 
        }
        else { 
            return $False 
        }
    }

    # Function to set a Ninja custom field.
    function Set-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            $Value,
            [Parameter()]
            [String]$DocumentName
        )

        $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded; the value is greater than or equal to 200,000 characters.")
        }
    
        # If requested to set the field value for a Ninja document, we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
    
        # This is a list of valid fields that can be set. If no type is specified, it is assumed that the input does not need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
    
        # The field below requires additional information to be set.
        $NeedsOptions = "Dropdown"
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                # Redirect error output to the success stream to make it easier to handle errors if nothing is found or if something else goes wrong.
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
    
        # If an error is received with an exception property, the function will exit with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
    
        # The below types require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # Although it's highly likely we were given a value like "True" or a boolean datatype, it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, the given value will be matched with a GUID.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
    
                if (-not $Selection) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                }
    
                $NinjaValue = $Selection
            }
            default {
                # All the other types shouldn't require additional work on the input.
                $NinjaValue = $Value
            }
        }
    
        # We'll need to set the field differently depending on if its a field in a Ninja Document or not.
        if ($DocumentName) {
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
    
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}   
process {
    # Check if the script is running with elevated (Administrator) privileges; exit with an error if not.
    if (!(Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the script is running on a Domain Controller and set the $IsDomainUser flag to true if it is.
    if (Test-IsDomainController) {
        $IsDomainUser = $True
    }

    # Check if the script is running on a system joined to Azure AD (Microsoft Entra) and output warnings that the script does not support operations on Entra accounts.
    if (Test-IsAzureJoined) {
        Write-Warning "This script does not support resetting Microsoft Entra accounts." 
        Write-Warning "Assuming you want to reset a local or domain account on an Entra-joined machine."
        Write-Host ""
    }

    # Check if the system is domain-joined but not a domain controller, and output warnings that domain account resets are only supported on domain controllers.
    if (!(Test-IsDomainController) -and (Test-IsDomainJoined)) {
        Write-Warning "This system is not a domain controller but is domain-joined. Resetting domain accounts is only supported on Domain Controllers."
        Write-Warning "Assuming you're trying to reset a local account on a domain-joined machine."
        Write-Host ""
    }

    # Attempt to import the ActiveDirectory module if the script detected a domain environment earlier.
    if ($IsDomainUser) {
        try {
            # Try to import the ActiveDirectory module
            Import-Module -Name ActiveDirectory -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] Failed to import the ActiveDirectory PowerShell module. Please ensure it is installed on this system."
            exit 1
        }
    }

    # Attempt to generate a secure password that meets specified complexity requirements, retrying up to 1000 times.
    $i = 0
    do {
        $Password = New-SecurePassword -Length $PasswordLength -IncludeSpecialCharacters
        $i++
    }while ($i -lt 1000 -and !($Password -match '[@!#$%&\-]+' -and $Password -match '[A-Z]+' -and $Password -match '[a-z]+' -and $Password -match '[0-9]+'))

    # Output an error if unable to generate a password after 1000 attempts.
    if ($i -eq 1000) {
        Write-Host "[Error] Unable to generate a secure password after 1000 tries."
        exit 1
    }

    # Retrieve user account information based on whether the script is running in a domain environment or locally.
    if ($IsDomainUser) {
        $UserToReset = Get-ADUser -Identity $Username -ErrorAction SilentlyContinue
    }
    else {
        $UserToReset = Get-LocalUser -Name $Username -ErrorAction SilentlyContinue
    }

    # Exit with an error if no user account was found for the specified username.
    if (!$UserToReset) {
        Write-Host "[Error] Cannot reset the password to an account that does not exist!"
        exit 1
    }

    # Check if multiple accounts matched the username; if so, provide detailed information and exit.
    if ($UserToReset.Count -gt 1) {
        Write-Host "[Error] Multiple accounts matched that username. Please be more specific."
        $UserToReset | Format-Table | Out-String | Write-Host
        exit 1
    }

    # Attempt to set a custom field with the newly generated password, handling any errors that occur.
    try {
        Write-Host "Attempting to set Custom Field '$PasswordCustomField'."
        Set-NinjaProperty -Name $PasswordCustomField -Value $Password
        Write-Host "Successfully set Custom Field '$PasswordCustomField'!`n"
    }
    catch {
        Write-Host "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Convert plaintext password to a secure string.
    $Password = $Password | ConvertTo-SecureString -AsPlainText -Force

    try {
        # If operating within a domain environment, use domain user operations.
        if ($IsDomainUser) {
            # Reset the user's password.
            $UserToReset | Set-ADAccountPassword -NewPassword $Password -Reset -ErrorAction Stop

            # Set password expiration option according to the option selected.
            if ($PasswordExpireOption -eq "Password Never Expires") {
                $UserToReset | Set-ADUser -PasswordNeverExpires:$True
            }
            else {
                $UserToReset | Set-ADUser -PasswordNeverExpires:$False
            }

            # If user must change password at next logon, set that option.
            if ($PasswordExpireOption -eq "User Must Change Password") {
                $UserToReset = Get-ADUser -Identity $Username -ErrorAction SilentlyContinue
                $UserToReset | Set-ADUser -ChangePasswordAtLogon:$True
            }

            # Confirm password reset operation success.
            Write-Host "Successfully reset password for '$Username'."
        }
        else {
            $Arguments = @{
                Password = $Password
            }

            # Set password policies for local users based on the specified expiration option.
            if ($PasswordExpireOption -eq "Password Never Expires") {
                $Arguments["PasswordNeverExpires"] = $true
            }
            else {
                $Arguments["PasswordNeverExpires"] = $false
            }

            # Reset the local user's password.
            $UserToReset | Set-LocalUser @Arguments -Confirm:$false -ErrorAction Stop

            # If user must change password at next logon, execute the command.
            if ($PasswordExpireOption -eq "User Must Change Password") {
                Invoke-Command -ScriptBlock { net.exe user "$Username" /logonpasswordchg:yes } | Where-Object { $_ -AND $_ -notmatch "command completed successfully" }
            }

            # Confirm password reset operation success.
            Write-Host "Successfully reset password for '$Username'."
        }
    }
    catch {
        # Output errors if the try block fails.
        Write-Host "[Error] Failed to reset the password for $Username."
        Write-Host "[Error] $($_.Exception.Message)"
        exit 1
    }

    exit $ExitCode
}
end {
    
    
    
}
