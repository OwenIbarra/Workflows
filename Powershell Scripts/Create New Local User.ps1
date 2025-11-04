# Create a local user account with options to enable and disable at specific dates, and add to local admin group. Saves randomly generated password to a custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Create a local user account with options to enable and disable at specific dates, and add to local admin group. Saves randomly generated password to a custom field.
.DESCRIPTION
    Create a local user account with options to enable and disable at specific dates, and add to local admin group. Saves randomly generated password to a custom field.

.EXAMPLE
    -UserNameToAdd "JohnTSmith" -Name "John T Smith"
    ## EXAMPLE OUTPUT ##
    User JohnTSmith has been created successfully.
    User JohnTSmith was added to the local Users group.

PARAMETER: -UserNameToAdd "JohnTSmith" -Name "John T Smith"
    Creates user with the name JohnTSmith and display name of John T Smith.

PARAMETER: -UserNameToAdd "JohnTSmith" -Name "John T Smith" -DateAndTimeToEnable "Monday, January 1, 2020 1:00:00 PM"
    Create user with the name JohnTSmith and display name of John T Smith.
    The user will start out disabled.
    A scheduled task will be created to enable the user after "Monday, January 1, 2020 1:00:00 PM".
.EXAMPLE
    -UserNameToAdd "JohnTSmith" -Name "John T Smith" -DateAndTimeToEnable "Monday, January 1, 2020 1:00:00 PM"
    ## EXAMPLE OUTPUT ##
    User JohnTSmith has been created successfully.
    User JohnTSmith was added to the local Users group.
    Created Scheduled Task: Enable User JohnTSmith
    User JohnTSmith will be able to login after Monday, January 1, 2020 1:00:00 PM.

PARAMETER: -UserNameToAdd "JohnTSmith" -Name "John T Smith" -DisableAfterDays 10
    Create user with the name JohnTSmith and display name of John T Smith.
    The user will be disabled after 10 days after the user's creation.
.EXAMPLE
    -UserNameToAdd "JohnTSmith" -Name "John T Smith" -DisableAfterDays 10
    ## EXAMPLE OUTPUT ##
    User JohnTSmith has been created successfully.
    User JohnTSmith was added to the local Users group.

PARAMETER: -UserNameToAdd "JohnTSmith" -Name "John T Smith" -AddToLocalAdminGroup
    Create user with the name JohnTSmith and display name of John T Smith.
    User will be added as a member of the local Administrators group.
.EXAMPLE
    -UserNameToAdd "JohnTSmith" -Name "John T Smith" -AddToLocalAdminGroup
    ## EXAMPLE OUTPUT ##
    User JohnTSmith has been created successfully.
    User JohnTSmith was added to the local Users group.
    User JohnTSmith was added to the local Administrators group.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Update Calculated Name, reduced nesting, added more validation of parameters, fixed bug with adding to local admin group, made changes to scheduled task, improved password generation.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Username,
    [Parameter()]
    [String]$DisplayName,
    [Parameter()]
    [Int]$PasswordLength = 20,
    [Parameter()]
    [DateTime]$EnableDate,
    [Parameter()]
    $DisableAfterDays,
    [Parameter()]
    [String]$CustomField,
    [Parameter()]
    [String]$PasswordExpireOption = "User Must Change Password",
    [Parameter()]
    [Switch]$AddToLocalAdminGroup = [System.Convert]::ToBoolean($env:addToLocalAdminGroup)
)

begin {
    # Retrieve script form variables and replace the parameters with them, handling 'null' values.
    if ($env:usernameToAdd -and $env:usernameToAdd -notlike "null") { $Username = $env:usernameToAdd }
    if ($env:displayName -and $env:displayName -notlike "null") { $DisplayName = $env:displayName }
    if ($env:customFieldToStorePassword -and $env:customFieldToStorePassword -notlike "null") { $CustomField = $env:customFieldToStorePassword }
    if ($env:passwordLength -and $env:passwordLength -notlike "null") { $PasswordLength = $env:passwordLength }
    if ($env:dateAndTimeToEnable -and $env:dateAndTimeToEnable -notlike "null") { $EnableDate = $env:dateAndTimeToEnable }
    if ($env:disableAfterDays -and $env:disableAfterDays -notlike "null") { [int]$DisableAfterDays = $env:disableAfterDays }
    if ($env:passwordExpireOptions -and $env:passwordExpireOptions -notlike "null" ) {
        if ($env:passwordExpireOptions -eq "Neither") { 
            $PasswordExpireOption = $null
        }
        else { 
            $PasswordExpireOption = $env:passwordExpireOptions 
        } 
    }

    # Validate input parameters for user creation, checking for absence, invalid characters, length, and options.

    if (!$Username) {
        Write-Host -Object "[Error] Please enter in a username!"
        exit 1
    }

    if (!$CustomField) {
        Write-Host -Object "[Error] A Custom Field to store the password is required!"
        exit 1
    }

    # Ensure username does not contain illegal characters.
    if ($Username -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|,|"|@') {
        Write-Host -Object ("[Error] $Username contains one of the following invalid characters." + ' " [ ] : ; | = + * ? < > / \ , @')
        exit 1
    }

    # Ensure the username does not contain spaces.
    if ($Username -match '\s') {
        Write-Host -Object ("[Error] '$Username' contains a space.")
        exit 1
    }

    # Ensure the username is not longer than 20 characters.
    $UserNameCharacters = $Username | Measure-Object -Character | Select-Object -ExpandProperty Characters
    if ($UserNameCharacters -gt 20) {
        Write-Host -Object "[Error] '$Username' is too long. The username needs to be less than or equal to 20 characters."
        exit 1
    }

    # Validate password length, must be 8 or more.
    if (!$PasswordLength -or $PasswordLength -lt 8) {
        Write-Host -Object "[Error] Password length must be greater than or equal to 8!"
        exit 1
    }

    # Validate disable after days, cannot be negative.
    if ($DisableAfterDays -and $DisableAfterDays -lt 0) {
        Write-Host -Object "[Error] Disable After Days cannot be less than 0."
        exit 1
    }

    # Validate password expiration options.
    $ValidExpireOption = "User Must Change Password", "Password Never Expires"
    if ($PasswordExpireOption -and $ValidExpireOption -notcontains $PasswordExpireOption) {
        Write-Host -Object "[Error] Invalid password expire option given. Must be either 'User Must Change Password' or 'Password Never Expires'"
        exit 1
    }

    # Default Password Policy
    $PasswordPolicy = [PSCustomObject]@{
        MinimumLength = 0
        Complexity    = 1
    }

    # Export the security policy
    $Arguments = @(
        "/export"
        "/cfg"
        "$env:TEMP\secconfig.cfg"
    )
    $SecurityExport = Start-Process -FilePath "secedit.exe" -ArgumentList $Arguments -PassThru -Wait -WindowStyle Hidden

    # If export was successful parse through the security policy for the minimum password length required.
    if ($SecurityExport.ExitCode -ne 0) {
        Write-Host -Object "[Error] Failed to retrieve password complexity policy. Assuming Microsoft Default policy is in effect."
    }
    else {
        $SecurityPolicy = Get-Content -Path "$env:TEMP\secconfig.cfg"

        $PasswordLengthField = $SecurityPolicy | Select-String "MinimumPasswordLength"
        $PasswordPolicy.MinimumLength = ($PasswordLengthField -split "=").Trim()[1]
    }

    # Remove the export if it exists
    if (Test-Path -Path "$env:TEMP\secconfig.cfg" -ErrorAction SilentlyContinue) {
        Remove-Item -Path "$env:TEMP\secconfig.cfg"
    }

    # Error out if the password length does not meet the minimum requirements.
    if ($PasswordLength -lt $PasswordPolicy.MinimumLength) {
        Write-Host "[Error] The minimum password length of $($PasswordPolicy.MinimumLength) is greater than the password length you requested to generate ($PasswordLength)."
        exit 1
    }

    # Check if script is running with elevated permissions.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Function to retrieve a local group name via its sid.
    function Get-LocalGroupName {
        param(
            [Parameter(Mandatory = $True)]
            [String]$Sid
        )

        if ($PSVersionTable.PSVersion.Major -lt 5) {
            (Get-WmiObject -Class Win32_Group -Filter "LocalAccount=True and SID='$Sid'").Name
        }
        else {
            (Get-CimInstance -Class Win32_Group -Filter "LocalAccount=True and SID='$Sid'").Name
        }
    }

    # Function to retrieve local groups using net command.
    function Get-NetLocalGroup {
        param(
            [Parameter()]
            [String]$Group = "Users"
        )
        Invoke-Command -ScriptBlock { net.exe localgroup "$Group" } | Where-Object { $_ -AND $_ -notmatch "command completed successfully" } | Select-Object -Skip 4
    }

    # Function to add to a local group using the net command.
    function Add-NetLocalGroupMember {
        param(
            [Parameter(Mandatory = $True)]
            [String]$User,
            [Parameter(Mandatory = $True)]
            [String]$Group
        )

        Invoke-Command -ScriptBlock { net.exe localgroup "$Group" "$Username" /add } | Where-Object { $_ -AND $_ -notmatch "command completed successfully" }
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

    $ExitCode = 0
}
process {
    # Check if the script is running with elevated (Administrator) privileges
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # The Users and Administrators group can have a different name depending on the language set.
    $UsersGroup = Get-LocalGroupName -Sid "S-1-5-32-545"
    $AdministratorsGroup = Get-LocalGroupName -Sid "S-1-5-32-544"
    
    # Check if the user already exists in the local group
    if ((Get-NetLocalGroup -Group $UsersGroup) -contains $Username) {
        Write-Host "[Error] User $Username already exists!"
        exit 1
    }

    # Generate a password according to the complexity policy
    $i = 0
    do {
        $Password = New-SecurePassword -Length $PasswordLength -IncludeSpecialCharacters
        $i++
    }while ($i -lt 1000 -and !($Password -match '[@!#$%&\-]+' -and $Password -match '[A-Z]+' -and $Password -match '[a-z]+' -and $Password -match '[0-9]+'))

    if ($i -eq 1000) {
        Write-Host "[Error] Unable to generate a secure password after 1000 tries."
        exit 1
    }

    try {
        # Attempt to set the custom field with the generated password
        Write-Host "Attempting to set password in Custom Field '$CustomField'."
        # Confirmation of successful custom field update
        Write-Host "Successfully set password in Custom Field '$CustomField'!"
    }
    catch {
        # Error handling for custom field update failure
        Write-Host "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Prepare parameters for creating a new local user account
    $UserSplat = @{
        Name        = $Username
        Password    = (ConvertTo-SecureString -String $Password -AsPlainText -Force)
        Description = "User account created on $(Get-Date)"
    }
    
    # If a display name is provided, add it to the user account parameters
    if ($DisplayName) {
        $UserSplat["FullName"] = $DisplayName
    }

    # If a future enable date is provided, create the user in a disabled state; else warn if date is in the past
    if ($EnableDate -and $EnableDate -gt (Get-Date)) {
        $UserSplat['Disabled'] = $true
        $ScheduleEnable = $True
    }
    elseif ($EnableDate) {
        Write-Warning -Message "This script is set to enable the account after a date in the past!"
        Write-Warning -Message "Date to enable: $EnableDate"
    }

    # If the user is to be disabled immediately, set the disabled flag
    if ($DisableAfterDays -eq 0) {
        $UserSplat['Disabled'] = $true
    }

    # If the password is set to never expire, add this to the user account parameters
    if ($PasswordExpireOption -eq "Password Never Expires") {
        $UserSplat['PasswordNeverExpires'] = $True
    }

    # If an account expiration period is provided, calculate the expiration date based on the enable date
    if ($DisableAfterDays -and $DisableAfterDays -gt 0) {
        if (-not $EnableDate) { $EnableDate = Get-Date }
        $UserSplat['AccountExpires'] = $(Get-Date $EnableDate).AddDays($DisableAfterDays)
    }

    # Attempt to create the new local user account with the specified parameters
    try {
        New-LocalUser @UserSplat -ErrorAction Stop
        Add-NetLocalGroupMember -User $Username -Group $UsersGroup
    }
    catch {
        Write-Host "[Error] $($_.Exception.Message)"
        exit 1
    }

    # If specified, force the user to change their password at the next logon
    if ($PasswordExpireOption -eq "User Must Change Password") {
        Invoke-Command -ScriptBlock { net.exe user "$Username" /logonpasswordchg:yes } | Where-Object { $_ -AND $_ -notmatch "command completed successfully" }
    }

    # If the user needs to be added to the local Administrators group, attempt to add them
    if ($AddToLocalAdminGroup) {
        Add-NetLocalGroupMember -User $Username -Group $AdministratorsGroup
        # Verify that the user was added to the Administrators group
        $LocalAdmins = Get-NetLocalGroup -Group $AdministratorsGroup
        $LocalAdmins | ForEach-Object {
            if ($_ -match [regex]::Escape($Username)) {
                $IsLocalAdmin = $True
            }
        }
        # If the user wasn't added to the Administrators group, print an error
        if (-not $IsLocalAdmin) {
            Write-Host -Object "[Error] Failed to add $Username to the '$AdministratorsGroup' group."
            $ExitCode = 1
        }
    }

    # Check if enabling the user is scheduled.
    if ($ScheduleEnable) {
        # Set up properties for the scheduled task (splatting method for cleaner code).
        $TaskSplat = @{
            Description = "Ninja Automation Enable User $Username"
            Action      = New-ScheduledTaskAction -Execute "net.exe" -Argument "user `"$Username`" /active:yes"
            Trigger     = New-ScheduledTaskTrigger -Once -At $EnableDate
            Principal   = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
            Settings    = New-ScheduledTaskSettingsSet -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries -WakeToRun -StartWhenAvailable
        }

        # Attempt to create and register the scheduled task
        try {
            # Create and register the scheduled task to enable the user
            New-ScheduledTask @TaskSplat | Register-ScheduledTask -User "System" -TaskName "Enable User $Username $(Get-Date -Date $EnableDate -Format yyyyMMdd)" | Out-Null
            
            # Verify task creation
            if ($(Get-ScheduledTask -TaskName "Enable User $Username $(Get-Date -Date $EnableDate -Format yyyyMMdd)" )) {
                Write-Host "Created Scheduled Task: Enable User $Username"
            }
            else {
                # Task creation verification failed
                Write-Host "[Error] Failed to find scheduled task with the name 'Enable User $Username'"
                $ExitCode = 1
            }
        }
        catch {
            # Error handling for task registration failure
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }

        # Inform the user of the enable date
        Write-Host "User $Username will be able to login after $EnableDate."
    }
    elseif ($DisableAfterDays -ne 0) {
        # No enable date was specified, user can login immediately
        Write-Host "No Enable Date is Set, $Username is able to login now."
    }

    if ($DisableAfterDays -eq 0) {
        Write-Host "Account $Username was successfully created, account is currently disabled as requested!"
    }

    # Exit the script with the final status code
    exit $ExitCode
}
end {

}
