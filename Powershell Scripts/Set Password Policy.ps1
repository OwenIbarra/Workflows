# Sets the password policy for the local machine or Active Directory.
#Requires -Version 5.1

<#
.SYNOPSIS
    Sets the password policy for the local machine or Active Directory.
.DESCRIPTION
    Sets the password policy for the local machine or Active Directory.

PARAMETER: -Length "ReplaceMeWithYourDesiredPasswordLength"
    Sets the minimum password length. Accepts a number from 0 to 128.

.EXAMPLE
    -Length 128
    
    Setting the minimum password length to 128.

PARAMETER: -MinAge "ReplaceMeWithYourDesiredMinimumPasswordAge"
    Sets the minimum password age. Accepts a number from 0 to 998. Must be less than Maximum password age.

.EXAMPLE
    -MinAge 30
    
    Setting the minimum password age to 30 days.

PARAMETER: -History "ReplaceMeWithYourDesiredPasswordHistory"
    Sets the password history. Accepts a number from 1 to 999.

.EXAMPLE
    -History 24
    
    Setting the password history to 24.

PARAMETER: -LoginAttemptLockTime "ReplaceMeWithYourDesiredLockoutDuration"
    Sets the lockout duration. Accepts a number from 1 to 99999.

.EXAMPLE
    -LoginAttemptLockTime 15
    
    Setting the lockout duration to 15 minutes.

PARAMETER: -ResetLockoutTime "ReplaceMeWithYourDesiredResetLockoutCount"
    Sets the reset lockout count. Accepts a number from 1 to 99999.

.EXAMPLE
    -ResetLockoutTime 15
    
    Setting the reset lockout count to 15 days.

PARAMETER: -MaxLoginAttempts "ReplaceMeWithYourDesiredLockoutThreshold"
    Sets the lockout threshold. Accepts a number from 1 to 999.

.EXAMPLE
    -MaxLoginAttempts 10
    
    Setting the lockout threshold to 10 days.

PARAMETER: -MaxAge "ReplaceMeWithYourDesiredMaximumPasswordAge"
    Sets the maximum password age. Accepts a number from 0 to 999. Must be greater than Minimum password age.

.EXAMPLE
    -MaxAge 30
    
    Setting the maximum password age to 30 days.

PARAMETER: -ComplexityEnabled
    Enables password complexity.

.EXAMPLE
    -ComplexityEnabled $True
    
    Enabling password complexity.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Combined minimum password requirements script and password complexity script.

.LINK
    https://support.microsoft.com/en-us/topic/minimum-password-length-auditing-and-enforcement-on-certain-versions-of-windows-5ef7fecf-3325-f56b-cc10-4fd565aacc59
#>

[CmdletBinding()]
param (
    [Parameter()]
    $Length,
    [Parameter()]
    $MinAge,
    [Parameter()]
    $MaxAge,
    [Parameter()]
    $History,
    [Parameter()]
    $LoginAttemptLockTime,
    [Parameter()]
    $ResetLockoutTime,
    [Parameter()]
    $MaxLoginAttempts,
    [Parameter()]
    # Boolean
    $ComplexityEnabled,
    [Parameter()]
    [Switch]
    $ResetPolicy
)

begin {

    # Default local machine password policy settings
    $DefaultLocalPolicy = @{
        minimumPasswordLength = 7
        minimumPasswordAge    = 1
        maximumPasswordAge    = 42
        passwordHistory       = 24
        loginAttemptLockTime  = 15
        maxLoginAttempts      = 10
        resetLockoutTime      = 15
        complexity            = 1
    }

    # Default domain password policy settings
    # See https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy for more information
    $DefaultDomainPolicy = @{
        MinPasswordLength    = 14
        MinPasswordAge       = 1
        MaxPasswordAge       = 60
        PasswordHistoryCount = 24
        LockoutDuration      = 30
        LockoutThreshold     = 10
        ResetLockoutCount    = 30
        ComplexityEnabled    = "Enable"
    }

    if ($env:resetPolicy -like "true") {
        $ResetPolicy = $true
    }

    # We'll do different actions depending on if its a domain controller or not
    function Test-IsDomainController {
        # Determine the method to retrieve the operating system information based on PowerShell version
        try {
            $OS = if ($PSVersionTable.PSVersion.Major -lt 5) {
                Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            }
            else {
                Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a domain controller."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        # Check if the ProductType is "2", which indicates that the system is a domain controller
        if ($OS.ProductType -eq "2") {
            return $true
        }
    }

    Function Set-LocalPasswordPolicy {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $false)][int]$PasswordComplexity,
            [Parameter(Mandatory = $false)][int]$MinimumPasswordLength,
            [Parameter(Mandatory = $false)][int]$MinimumPasswordAge,
            [Parameter(Mandatory = $false)][int]$MaximumPasswordAge,
            [Parameter(Mandatory = $false)][int]$PasswordHistorySize,
            [Parameter(Mandatory = $false)][int]$LockoutBadCount,
            [Parameter(Mandatory = $false)][int]$ResetLockoutCount,
            [Parameter(Mandatory = $false)][int]$LockoutDuration
        )
        begin {
            # Create a temporary file to store the local security policy
            $outfile = "$env:TEMP\secpol-$(New-Guid).cfg"

            # Setup our local security policy template
            $Header = "[Unicode]`nUnicode=yes`n[System Access]"
            $Content = ""
            $Footer = "[Version]`nsignature=`"`$CHICAGO`$`"`nRevision=1"
        }
        process {
            # If parameters are specified, update the local security policy file
            if ($PSBoundParameters.ContainsKey("PasswordComplexity")) {
                $Content += "PasswordComplexity = $PasswordComplexity`n"
            }
            if ($PSBoundParameters.ContainsKey("MinimumPasswordLength")) {
                $Content += "MinimumPasswordLength = $MinimumPasswordLength`n"
            }
            if ($PSBoundParameters.ContainsKey("MinimumPasswordAge")) {
                $Content += "MinimumPasswordAge = $MinimumPasswordAge`n"
            }
            if ($PSBoundParameters.ContainsKey("MaximumPasswordAge")) {
                $Content += "MaximumPasswordAge = $MaximumPasswordAge`n"
            }
            if ($PSBoundParameters.ContainsKey("PasswordHistorySize")) {
                $Content += "PasswordHistorySize = $PasswordHistorySize`n"
            }
            if ($PSBoundParameters.ContainsKey("LockoutBadCount")) {
                $Content += "LockoutBadCount = $LockoutBadCount`n"
            }
            if ($PSBoundParameters.ContainsKey("ResetLockoutCount")) {
                $Content += "ResetLockoutCount = $ResetLockoutCount`n"
            }
            if ($PSBoundParameters.ContainsKey("LockoutDuration")) {
                $Content += "LockoutDuration = $LockoutDuration`n"
            }

            # Return if no changes were requested
            if ($Content -like "") {
                Write-Host "[Info] No changes to the local security policy were requested."
                return
            }

            $Header + "`n" + $Content + "`n" + $Footer | Out-File $outfile -Force -Encoding unicode
            $ModifyPolicy = Start-Process -FilePath "C:\Windows\System32\SecEdit.exe" -ArgumentList "/configure /db c:\windows\security\local.sdb /cfg $outfile /areas SECURITYPOLICY" -Wait -NoNewWindow -PassThru -RedirectStandardOutput EmptyOutput

            if ($ModifyPolicy.ExitCode -ne 0) {
                Write-Host "[Error] SecEdit.exe failed to set the local security policy."

                # When the policy fails to set, we should output the file to the console for debugging purposes.
                if ($Debug) {
                    Get-Content $outfile | Write-Host
                }

                # Remove the local security policy file
                Remove-Item $outfile -Force -ErrorAction SilentlyContinue | Out-Null
                throw "Failed to set local security policy"
            }
            else {
                Write-Host "[Info] Successfully set password policy."
            }

            # Remove the local security policy file
            Remove-Item $outfile -Force | Out-Null
        }
        end {
            return
        }
    }

    # These actions require elevation
    function Test-IsElevated {
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        # Create a WindowsPrincipal object based on the current identity
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)

        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Test if the machine is joined to a domain
    function Test-IsDomainJoined {
        # Check the PowerShell version to determine the appropriate cmdlet to use
        try {
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            }
            else {
                return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a part of a domain."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Check if we are trying to set individual password policy settings and reset the policy at the same time.
    if (
        (
            ($Length -or $env:minimumPasswordLength -notlike "null") -or
            ($MinAge -or $env:minimumPasswordAge -notlike "null") -or
            ($MaxAge -or $env:maximumPasswordAge -notlike "null") -or
            ($History -or $env:passwordHistory -notlike "null") -or
            ($LoginAttemptLockTime -or $env:loginAttemptLockTime -notlike "null") -or
            ($MaxLoginAttempts -or $env:maxLoginAttempts -notlike "null") -or
            ($ResetLockoutTime -or $env:resetLockoutTime -notlike "null")
        ) -and ($ResetPolicy) -and -not ($env:complexity -like "Do Not Change")
    ) {
        Write-Host "[Error] You cannot set individual password policy settings and reset the policy at the same time."
        exit 1
    }
    elseif (($ResetPolicy) -and ($env:complexity -like "Do Not Change")) {
        if (Test-IsDomainController) {
            try {
                Import-Module ActiveDirectory
            }
            catch {
                Write-Host "[Error] Failed to import PowerShell Active Directory Module. Is RSAT installed?"
            }
            try {
                Write-Host "[Info] Attempting to reset Default Domain Password Policy"
                Set-ADDefaultDomainPasswordPolicy @DefaultDomainPolicy -ErrorAction Stop
                Write-Host "[Info] Successfully reset Default Domain Password Policy"
            }
            catch {
                Write-Host "[Error] Failed to reset Default Domain Password Policy"
                exit 1
            }
            exit 0
        }
        else {
            Write-Host "[Info] Selecting default local machine security policy"
            # Reset the policy to the default settings
            $Splat = @{
                PasswordComplexity    = $DefaultLocalPolicy.complexity
                MinimumPasswordLength = $DefaultLocalPolicy.minimumPasswordLength
                MinimumPasswordAge    = $DefaultLocalPolicy.minimumPasswordAge
                MaximumPasswordAge    = $DefaultLocalPolicy.maximumPasswordAge
                PasswordHistorySize   = $DefaultLocalPolicy.passwordHistory
                LockoutBadCount       = $DefaultLocalPolicy.maxLoginAttempts
                ResetLockoutCount     = $DefaultLocalPolicy.resetLockoutTime
                LockoutDuration       = $DefaultLocalPolicy.loginAttemptLockTime
            }
            try {
                Write-Host "[Info] Attempting to reset local security policy"
                Set-LocalPasswordPolicy @Splat
                Write-Host "[Info] Successfully reset local security policy"
            }
            catch {
                Write-Host "[Error] Failed to reset local security policy."
                exit 1
            }
            exit 0
        }
    }
    else {

        # If Dynamic script variables are used, use them.
        if ($env:minimumPasswordLength -and $env:minimumPasswordLength -notlike "null") {
            [int]$Length = $env:minimumPasswordLength
        }

        if ($env:minimumPasswordAge -and $env:minimumPasswordAge -notlike "null") {
            [int]$MinAge = $env:minimumPasswordAge
        }

        if ($env:maximumPasswordAge -and $env:maximumPasswordAge -notlike "null") {
            [int]$MaxAge = $env:maximumPasswordAge
        }

        if ($env:passwordHistory -and $env:passwordHistory -notlike "null") {
            [int]$History = $env:passwordHistory
        }

        if ($env:loginAttemptLockTime -and $env:loginAttemptLockTime -notlike "null") {
            [int]$LoginAttemptLockTime = $env:loginAttemptLockTime
        }

        if ($env:maxLoginAttempts -and $env:maxLoginAttempts -notlike "null") {
            [int]$MaxLoginAttempts = $env:maxLoginAttempts
        }

        if ($env:resetLockoutTime -and $env:resetLockoutTime -notlike "null") {
            [int]$ResetLockoutTime = $env:resetLockoutTime
        }

        # If the complexity is not set, set it to $null
        if (-not $PSBoundParameters.ContainsKey("ComplexityEnabled")) {
            $ComplexityEnabled = $null
        }

        # If Script Variable is used, set it accordingly
        if ($env:complexity -like "Enable") {
            $ComplexityEnabled = $True
        }
        elseif ($env:complexity -like "Disable") {
            $ComplexityEnabled = $False
        }

        # Verify we weren't given bad parameters

        # Check types
        if ($null -ne $Length -and $Length -notmatch "^\d+$") {
            Write-Host "[Error] Minimum password length must be a number."
            exit 1
        }
        if ($null -ne $MinAge -and $MinAge -notmatch "^\d+$") {
            Write-Host "[Error] Minimum password age must be a number."
            exit 1
        }
        if ($null -ne $MaxAge -and $MaxAge -notmatch "^\d+$") {
            Write-Host "[Error] Maximum password age must be a number."
            exit 1
        }
        if ($null -ne $History -and $History -notmatch "^\d+$") {
            Write-Host "[Error] Password history must be a number."
            exit 1
        }
        if ($null -ne $LoginAttemptLockTime -and $LoginAttemptLockTime -notmatch "^\d+$") {
            Write-Host "[Error] Lockout duration must be a number."
            exit 1
        }
        if ($null -ne $MaxLoginAttempts -and $MaxLoginAttempts -notmatch "^\d+$") {
            Write-Host "[Error] Lockout threshold must be a number."
            exit 1
        }
        if ($null -ne $ResetLockoutTime -and $ResetLockoutTime -notmatch "^\d+$") {
            Write-Host "[Error] Reset lockout time must be a number."
            exit 1
        }


        # Check Ranges
        if ($null -ne $Length -and ($Length -lt 8 -or $Length -gt 128)) {
            Write-Host "[Error] Minimum password length must be between 8 and 128."
            exit 1
        }

        if (($null -ne $MinAge -and $null -ne $MaxAge) -and $MinAge -gt $MaxAge) {
            Write-Host "[Error] Minimum password age must be less than maximum password age!"
            exit 1
        }

        if ($null -ne $MinAge -and ($MinAge -lt 0 -or $MinAge -gt 998)) {
            Write-Host "[Error] Minimum password age must be between 0 and 998."
            exit 1
        }

        if ($null -ne $MaxAge -and ($MaxAge -lt 0 -or $MaxAge -gt 999)) {
            Write-Host "[Error] Maximum password age must be between 0 and 999."
            exit 1
        }

        if ($null -ne $History -and ($History -lt 1 -or $History -gt 999)) {
            Write-Host "[Error] Password history must be between 1 and 999."
            exit 1
        }

        if (
            (
                $null -ne $LoginAttemptLockTime -and $null -like $LoginAttemptLockTime
            ) -or (
                $null -like $LoginAttemptLockTime -and $null -ne $LoginAttemptLockTime
            )
        ) {
            Write-Host "[Error] Login Attempt Lock Time and Reset Lockout Time must be set together."
        }

        if ($null -ne $LoginAttemptLockTime -and ($LoginAttemptLockTime -lt 1 -or $LoginAttemptLockTime -gt 99999)) {
            Write-Host "[Error] Lockout duration must be between 1 and 99999."
            exit 1
        }

        if ($null -ne $ResetLockoutTime -and ($ResetLockoutTime -lt 1 -or $ResetLockoutTime -gt 99999)) {
            Write-Host "[Error] Reset lockout time must be between 1 and 99999."
            exit 1
        }

        if ($null -ne $MaxLoginAttempts -and ($MaxLoginAttempts -lt 1 -or $MaxLoginAttempts -gt 999)) {
            Write-Host "[Error] Lockout threshold must be between 1 and 999."
            exit 1
        }

        if (
            (
                $null -like $MaxLoginAttempts -and $null -ne $ResetLockoutTime -and $null -like $LoginAttemptLockTime
            ) -or (
                $null -ne $MaxLoginAttempts -and $null -like $ResetLockoutTime -and $null -ne $LoginAttemptLockTime
            ) -or (
                $null -ne $MaxLoginAttempts -and $null -ne $ResetLockoutTime -and $null -like $LoginAttemptLockTime
            )
        ) {
            Write-Host "[Error] Lockout threshold, reset lockout time, and lockout duration must be set together."
            exit 1
        }

        if ($null -ne $LoginAttemptLockTime -and $null -ne $ResetLockoutTime -and $LoginAttemptLockTime -lt $ResetLockoutTime) {
            Write-Host "[Error] Login Attempt Lock Time must be greater than or equal to reset lockout time."
            exit 1
        }
    }

}
process {
    # Check if we are running as an administrator, exit if we aren't
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # The Domain policy can overwrite what is set; we should warn about that.
    if ((Test-IsDomainJoined -and -not (Test-IsDomainController))) {
        Write-Host "[Error] This can not be run on a domain-joined machine. Either run this on a Domain Controller or on a machine that is not joined to a domain."
        exit 1
    }

    if (Test-IsDomainController) {
        try {
            Import-Module ActiveDirectory
        }
        catch {
            Write-Host "[Error] Failed to import PowerShell Active Directory Module. Is RSAT installed?"
        }

        # Active Directory
    
        # Check if we are running on a Domain Controller, exit if we aren't
        if (-not (Test-IsDomainController)) {
            Write-Host "[Error] This needs to run on a Domain Controller."
            exit 1
        }

        # Checking the current policy to see if these settings are already set
        $CurrentPolicy = Get-ADDefaultDomainPasswordPolicy
        $Arguments = try {
            @{
                Identity = (Get-CimInstance -Class Win32_ComputerSystem -ErrorAction Stop).Domain
            } | Write-Output
        }
        catch {
            Write-Host "[Error] Failed to get the domain name."
            exit 1
        }

        # Check if we have bad arguments based on the current policy
        if ($null -ne $MinAge -and ($MinAge -gt $CurrentPolicy.MaxPasswordAge.Days -and -not ($null -ne $MaxAge))) {
            Write-Host "[Info] Current Maximum Age: $($CurrentPolicy.MaxPasswordAge.Days)"
            Write-Host "[Error] Minimum age must be less than maximum age!"
            exit 1
        }
        if ($null -ne $MaxAge -and ($MaxAge -lt $CurrentPolicy.MinPasswordAge.Days -and -not ($null -ne $MinAge))) {
            Write-Host "[Info] Current Minimum Age: $($CurrentPolicy.MinPasswordAge.Days)"
            Write-Host "[Error] Minimum age must be less than maximum age!"
            exit 1
        }
        if ($null -ne $MinAge -and ($MinAge -lt 0 -or $MinAge -gt 998)) {
            Write-Host "[Info] Current Minimum Age: $($CurrentPolicy.MinPasswordAge.Days)"
            Write-Host "[Error] Minimum age must be between 0 and 998."
            exit 1
        }
        if ($null -ne $MaxAge -and ($MaxAge -lt 0 -or $MaxAge -gt 999)) {
            Write-Host "[Info] Current Maximum Age: $($CurrentPolicy.MaxPasswordAge.Days)"
            Write-Host "[Error] Maximum age must be between 0 and 999."
            exit 1
        }
        if ($null -ne $History -and ($History -lt 1 -or $History -gt 999)) {
            Write-Host "[Info] Current Password History: $($CurrentPolicy.PasswordHistoryCount)"
            Write-Host "[Error] Password history must be between 1 and 999."
            exit 1
        }
        if ($null -ne $LoginAttemptLockTime -and ($LoginAttemptLockTime -lt 1 -or $LoginAttemptLockTime -gt 99999)) {
            Write-Host "[Info] Current Lockout Duration: $($CurrentPolicy.LoginAttemptLockTime)"
            Write-Host "[Error] Lockout duration must be between 1 and 99999."
            exit 1
        }
        if ($null -ne $MaxLoginAttempts -and ($MaxLoginAttempts -lt 1 -or $MaxLoginAttempts -gt 999)) {
            Write-Host "[Info] Current Lockout Threshold: $($CurrentPolicy.LockoutThreshold)"
            Write-Host "[Error] Lockout threshold must be between 1 and 999."
            exit 1
        }
        if ($null -ne $ResetLockoutTime -and ($ResetLockoutTime -lt 1 -or $ResetLockoutTime -gt 99999)) {
            Write-Host "[Info] Current Reset Lockout Count: $($CurrentPolicy.ResetLockoutCount)"
            Write-Host "[Error] Reset lockout time must be between 1 and 99999."
            exit 1
        }
        if ($null -ne $LoginAttemptLockTime -and $null -ne $ResetLockoutTime -and $LoginAttemptLockTime -lt $ResetLockoutTime) {
            Write-Host "[Info] Current Lockout Duration: $($CurrentPolicy.LoginAttemptLockTime)"
            Write-Host "[Error] Login Attempt Lock Time must be greater than or equal to reset lockout time."
            exit 1
        }

        # We may be able to skip setting these if they are already apart of the policy
        if ($null -ne $MinAge -and $MinAge -like $CurrentPolicy.MinPasswordAge.Days) {
            Write-Host "[Info] The current policy already has a minimum password age of $($CurrentPolicy.MinPasswordAge.Days). Skipping..."
        }
        elseif ($null -ne $MinAge) {
            Write-Host "[Info] Changing security policy from a minimum password age of $($CurrentPolicy.MinPasswordAge.Days) to $MinAge."
            $Arguments["MinPasswordAge"] = "$MinAge.0:0:0.0"
        }

        if ($null -ne $MaxAge -and $MaxAge -like $CurrentPolicy.MaxPasswordAge.Days) {
            Write-Host "[Info] The current policy already has a maximum password age of $($CurrentPolicy.MaxPasswordAge.Days). Skipping..."
        }
        elseif ($null -ne $MaxAge) {
            Write-Host "[Info] Changing security policy from a maximum password age of $($CurrentPolicy.MaxPasswordAge.Days) to $MaxAge."
            $Arguments["MaxPasswordAge"] = "$MaxAge.0:0:0.0"
        }

        if ($null -ne $Length -and $Length -like $CurrentPolicy.MinPasswordLength) {
            Write-Host "[Info] The current policy already has a minimum password length of $($CurrentPolicy.MinPasswordLength). Skipping..."
        }
        elseif ($null -ne $Length) {
            Write-Host "[Info] Changing security policy from a minimum password length of $($CurrentPolicy.MinPasswordLength) to $Length."
            $Arguments["MinPasswordLength"] = $Length
        }

        if ($null -ne $History -and $History -like $CurrentPolicy.PasswordHistoryCount) {
            Write-Host "[Info] The current policy already has a password history of $($CurrentPolicy.PasswordHistoryCount). Skipping..."
        }
        elseif ($null -ne $History) {
            Write-Host "[Info] Changing security policy from a password history of $($CurrentPolicy.PasswordHistoryCount) to $History."
            $Arguments["PasswordHistoryCount"] = $History
        }

        if ($null -ne $ComplexityEnabled -and $ComplexityEnabled -like $CurrentPolicy.ComplexityEnabled) {
            Write-Host "[Info] The current policy already has password complexity set to $($CurrentPolicy.ComplexityEnabled). Skipping..."
        }
        elseif ($null -ne $ComplexityEnabled) {
            Write-Host "[Info] Changing security policy from password complexity $($CurrentPolicy.ComplexityEnabled) to $ComplexityEnabled."
            $Arguments["ComplexityEnabled"] = $ComplexityEnabled
        }
        elseif ($null -like $ComplexityEnabled) {
            Write-Host "[Info] Password complexity is not being changed."
        }

        if ($null -ne $LoginAttemptLockTime -and $LoginAttemptLockTime -like $CurrentPolicy.LoginAttemptLockTime) {
            Write-Host "[Info] The current policy already has a lockout duration of $($CurrentPolicy.LoginAttemptLockTime). Skipping..."
        }
        elseif ($null -ne $LoginAttemptLockTime) {
            Write-Host "[Info] Changing security policy from a lockout duration of $($CurrentPolicy.LoginAttemptLockTime) to $LoginAttemptLockTime."
            $Arguments["LockoutDuration"] = $LoginAttemptLockTime
        }

        if ($null -ne $MaxLoginAttempts -and $MaxLoginAttempts -like $CurrentPolicy.LockoutThreshold) {
            Write-Host "[Info] The current policy already has a lockout threshold of $($CurrentPolicy.LockoutThreshold). Skipping..."
        }
        elseif ($null -ne $MaxLoginAttempts) {
            Write-Host "[Info] Changing security policy from a lockout threshold of $($CurrentPolicy.LockoutThreshold) to $MaxLoginAttempts."
            $Arguments["LockoutThreshold"] = $MaxLoginAttempts
        }

        if ($null -ne $ResetLockoutTime -and $ResetLockoutTime -like $CurrentPolicy.ResetLockoutCount) {
            Write-Host "[Info] The current policy already has a reset lockout count of $($CurrentPolicy.ResetLockoutCount). Skipping..."
        }
        elseif ($null -ne $ResetLockoutTime) {
            Write-Host "[Info] Changing security policy from a reset lockout count of $($CurrentPolicy.ResetLockoutCount) to $ResetLockoutTime."
            $Arguments["ResetLockoutCount"] = $ResetLockoutTime
        }

        # Actually set the policy based on the options requested and what has not already been set.
        if ($Arguments.Count -gt 1) {
            try {
                Write-Host "[Info] Attempting to set Default Domain Password Policy"
                Set-ADDefaultDomainPasswordPolicy @Arguments -ErrorAction Stop
                Write-Host "[Info] Successfully set Default Domain Password Policy"
            }
            catch {
                Write-Host "[Error] Failed to set Default Domain Password Policy"
                exit 1
            }
        }
        else {
            Write-Host "[Info] Current policy is identical to what was requested to be set."
        }
    }
    else {
        # Exporting the current policy so that we can modify it later.
        Write-Host "[Info] Reading local machine security policy"
        $Path = "$PSScriptRoot\Set-Password-Complexity-secpol.cfg"
        $ExportPolicy = Start-Process -FilePath "C:\Windows\System32\SecEdit.exe" -ArgumentList "/export /cfg $Path" -Wait -NoNewWindow -PassThru -RedirectStandardOutput EmptyOutput 

        # If we failed to export the policy we should error out.
        if ($ExportPolicy.ExitCode -ne 0) {
            Write-Host "[Info] Exit Code: $($ExportPolicy.ExitCode)"
            Write-Host "[Error] Unable to edit security policy."
            exit 1
        }

        $SecPolContent = Get-Content $Path

        # If $SecPolContent contains a line that matches the string "?[Unicode]" replace it with "[Unicode]"
        if ($SecPolContent -like "?[Unicode]") {
            # Remove the question marks from the beginning of the line

            # RegEx: \?+?\[Unicode\]
            # \? - Matches the character "?" literally
            # +? - Matches between one and unlimited times, as few times as possible, expanding as needed
            # \[Unicode\] - Matches the character "[", followed by "Unicode", followed by the character "]"

            $SecPolContent = $SecPolContent -replace "\?+?\[Unicode\]", "[Unicode]"
        }

        # Get the current policy settings
        $CurrentLength = ($SecPolContent | Where-Object { $_ -like "MinimumPasswordLength*" }) -replace 'MinimumPasswordLength\s*=\s*'
        $CurrentMinAge = ($SecPolContent | Where-Object { $_ -like "MinimumPasswordAge*" }) -replace 'MinimumPasswordAge\s*=\s*'
        $CurrentMaxAge = ($SecPolContent | Where-Object { $_ -like "MaximumPasswordAge*" }) -replace 'MaximumPasswordAge\s*=\s*'
        $CurrentHistory = ($SecPolContent | Where-Object { $_ -like "PasswordHistorySize*" }) -replace 'PasswordHistorySize\s*=\s*'
        $CurrentPasswordComplexity = ($SecPolContent | Where-Object { $_ -like "PasswordComplexity*" }) -replace 'PasswordComplexity\s*=\s*'
        $CurrentLoginAttemptLockTime = ($SecPolContent | Where-Object { $_ -like "LockoutDuration*" }) -replace 'LockoutDuration\s*=\s*'
        $CurrentMaxLoginAttempts = ($SecPolContent | Where-Object { $_ -like "LockoutBadCount*" }) -replace 'LockoutBadCount\s*=\s*'
        $CurrentResetLockoutTime = ($SecPolContent | Where-Object { $_ -like "ResetLockoutCount*" }) -replace 'ResetLockoutCount\s*=\s*'

        # Checking to see if we have bad arguments based on the current policy
        if ($null -ne $MinAge -and ($MinAge -gt "$CurrentMaxAge" -and -not ($null -ne $MaxAge))) {
            Write-Host "[Info] Current Maximum Age: $CurrentMaxAge"
            Write-Host "[Error] Minimum age must be less than maximum age!"
            # Remove our temp local policy config file
            Remove-Item $Path -Force
            exit 1
        }

        if ($null -ne $MaxAge -and ($MaxAge -lt "$CurrentMinAge" -and -not ($null -ne $MinAge))) {
            Write-Host "[Info] Current Minimum Age: $CurrentMinAge"
            Write-Host "[Error] Minimum age must be less than maximum age!"
            # Remove our temp local policy config file
            Remove-Item $Path -Force
            exit 1
        }

        if ($null -ne $History -and ($History -lt "$CurrentHistory" -and -not ($null -ne $History))) {
            Write-Host "[Info] Current Password History: $CurrentHistory"
            Write-Host "[Error] Password history must be greater than or equal to the current password history!"
            # Remove our temp local policy config file
            Remove-Item $Path -Force
            exit 1
        }

        $SplatPolicy = @{}

        # We may be able to skip setting these if they are already a part of the policy
        if ($null -ne $MinAge -and $MinAge -like "$CurrentMinAge") {
            Write-Host "[Info] The current policy already has a minimum password age of $CurrentMinAge. Skipping..."
            $SplatPolicy["MinimumPasswordAge"] = $CurrentMinAge
        }
        elseif ($null -ne $MinAge) {
            Write-Host "[Info] Changing security policy from a minimum password age of $CurrentMinAge to $MinAge."
            $SplatPolicy["MinimumPasswordAge"] = $MinAge
            $ModifiedPolicy = $True
        }

        if ($null -ne $MaxAge -and $MaxAge -like "$CurrentMaxAge") {
            Write-Host "[Info] The current policy already has a maximum password age of $CurrentMaxAge. Skipping..."
            $SplatPolicy["MaximumPasswordAge"] = $CurrentMaxAge
        }
        elseif ($null -ne $MaxAge) {
            Write-Host "[Info] Changing security policy from a maximum password age of $CurrentMaxAge to $MaxAge."
            $SplatPolicy["MaximumPasswordAge"] = $MaxAge
            $ModifiedPolicy = $True
        }

        if ($null -ne $Length -and $Length -like "$CurrentLength") {
            Write-Host "[Info] The current policy already has a minimum password length of $CurrentLength. Skipping..."
            $SplatPolicy["MinimumPasswordLength"] = $CurrentLength
        }
        elseif ($null -ne $Length) {
            Write-Host "[Info] Changing security policy from a minimum password length of $CurrentLength to $Length."
            $SplatPolicy["MinimumPasswordLength"] = $Length
            $ModifiedPolicy = $True
        }

        if ($null -ne $History -and $History -like "$CurrentHistory") {
            Write-Host "[Info] The current policy already has a password history of $CurrentHistory. Skipping..."
            $SplatPolicy["PasswordHistorySize"] = $CurrentHistory
        }
        elseif ($null -ne $History) {
            Write-Host "[Info] Changing security policy from a password history of $CurrentHistory to $History."
            $SplatPolicy["PasswordHistorySize"] = $History
            $ModifiedPolicy = $True
        }

        if (
            $null -ne $ComplexityEnabled -and
            (
                $($ComplexityEnabled -eq $True -and $CurrentPasswordComplexity -like "1") -or
                $($ComplexityEnabled -eq $False -and $CurrentPasswordComplexity -like "0")
            )
        ) {
            Write-Host "[Info] The current policy already has password complexity set to $CurrentPasswordComplexity. Skipping..."
        }
        elseif (
            $null -ne $ComplexityEnabled -and
            (
                $($ComplexityEnabled -eq $True -and $CurrentPasswordComplexity -like "0") -or
                $($ComplexityEnabled -eq $False -and $CurrentPasswordComplexity -like "1")
            )
        ) {
            Write-Host "[Info] Changing security policy from password complexity $CurrentPasswordComplexity to $(if($ComplexityEnabled){"1"}else{"0"})."
            $SplatPolicy["PasswordComplexity"] = $(if ($ComplexityEnabled) { "1" }else { "0" })
            $ModifiedPolicy = $True
        }

        if ($null -ne $LoginAttemptLockTime -and $LoginAttemptLockTime -like "$CurrentLoginAttemptLockTime") {
            Write-Host "[Info] The current policy already has a lockout duration of $CurrentLoginAttemptLockTime. Skipping..."
            $SplatPolicy["LockoutDuration"] = $CurrentLoginAttemptLockTime
        }
        elseif ($null -ne $LoginAttemptLockTime) {
            Write-Host "[Info] Changing security policy from a lockout duration of $CurrentLoginAttemptLockTime to $LoginAttemptLockTime."
            $SplatPolicy["LockoutDuration"] = $LoginAttemptLockTime
            $ModifiedPolicy = $True
        }

        if ($null -ne $MaxLoginAttempts -and $MaxLoginAttempts -like "$CurrentMaxLoginAttempts") {
            Write-Host "[Info] The current policy already has a lockout threshold of $CurrentMaxLoginAttempts. Skipping..."
            $SplatPolicy["LockoutBadCount"] = $CurrentMaxLoginAttempts
        }
        elseif ($null -ne $MaxLoginAttempts) {
            Write-Host "[Info] Changing security policy from a lockout threshold of $CurrentMaxLoginAttempts to $MaxLoginAttempts."
            $SplatPolicy["LockoutBadCount"] = $MaxLoginAttempts
            $ModifiedPolicy = $True
        }

        if ($null -ne $ResetLockoutTime -and $ResetLockoutTime -like "$CurrentResetLockoutTime") {
            Write-Host "[Info] The current policy already has a reset lockout count of $CurrentResetLockoutTime. Skipping..."
            $SplatPolicy["ResetLockoutCount"] = $CurrentResetLockoutTime
        }
        elseif ($null -ne $ResetLockoutTime) {
            Write-Host "[Info] Changing security policy from a reset lockout count of $CurrentResetLockoutTime to $ResetLockoutTime."
            $SplatPolicy["ResetLockoutCount"] = $ResetLockoutTime
            $ModifiedPolicy = $True
        }

        # Actually set the policy based on the options requested and what has not already been set.
        if ($ModifiedPolicy) {
            try {
                Set-LocalPasswordPolicy @SplatPolicy -ErrorAction Stop -Debug:$Debug
            }
            catch {
                Write-Host "[Error] Failed to set local security policy."
                exit 1
            }
        }
        else {
            # Remove our temp local policy config file
            Remove-Item $Path -Force

            Write-Host "[Info] Current policy is identical to what was requested to be set."
        }
    }
}
end {
    
    
    
}


