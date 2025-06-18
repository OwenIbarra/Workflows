# List all local accounts on the machine and optionally save the results to a WYSIWYG custom field.
#Requires -Version 4

<#
.SYNOPSIS
    List all local accounts on the machine and optionally save the results to a WYSIWYG custom field.
.DESCRIPTION
    List all local accounts on the machine and optionally save the results to a WYSIWYG custom field.
.EXAMPLE
    (No Parameters)
    Retrieving list of local users.
    ExitCode: 1
    Parsing username list into machine-readable format.
    Retrieving additional information on individual user accounts.

    Username      FullName Enabled PasswordLastSet      LastLogon           
    --------      -------- ------- ---------------      ---------           
    helpdesk               True    9/13/2024 9:01:22 AM 9/13/2024 9:20:25 AM

PARAMETER: -IncludeDisabledUsers
    Include disabled user accounts in the results.

PARAMETER: -WysiwygCustomField "ReplaceMeWithAnyWysiwygCustomField"
    Optionally specify the name of a WYSIWYG custom field to store the results in.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Added WYSIWYG support, switched to using only "net user", made more verbose, and improved error handling.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$IncludeDisabledUsers = [System.Convert]::ToBoolean($env:includeDisabledUsers),
    [Parameter()]
    [String]$WysiwygCustomField
)

begin {
    # If script form variables are used, replace the command line parameters with their value.
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WysiwygCustomField = $env:wysiwygCustomFieldName }

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

    function Test-IsEntraJoined {
        # Check if the operating system version is Windows 10 or higher
        if ([environment]::OSVersion.Version.Major -ge 10) {
            # Run the dsregcmd.exe tool to check Entra join status and look for "AzureAdJoined : YES"
            $dsreg = dsregcmd.exe /status | Select-String "AzureAdJoined : YES"
        }
    
        # If the search found the "AzureAdJoined : YES" string, return True, otherwise return False
        if ($dsreg) { return $True }else { return $False }
    }

    # If running on a domain controller, display an error message and exit
    if (Test-IsDomainController) {
        Write-Host -Object "[Error] This script is not compatible with domain controllers."
        exit 1
    }

    # If running on a domain joined machine, warn that only local accounts will be displayed.
    if (Test-IsDomainJoined) {
        Write-Warning -Message "This script will only display local accounts. It will not display Active Directory accounts."
    }

    # If running on an Entra joined machine, warn that only local accounts will be displayed.
    if (Test-IsEntraJoined) {
        Write-Warning -Message "This script will only display local accounts. It will not display Microsoft Entra accounts."
    }

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
        
        # Measure the number of characters in the provided value
        $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters
    
        # Throw an error if the value exceeds the character limit of 200,000 characters
        if ($Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
        
        # Initialize a hashtable for additional documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # Define a list of valid field types
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
    
        # Warn the user if the provided type is not valid
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # Define types that require options to be retrieved
        $NeedsOptions = "Dropdown"
    
        # If the property is being set in a document or field and the type needs options, retrieve them
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # Throw an error if there was an issue retrieving the property options
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
            
        # Process the property value based on its type
        switch ($Type) {
            "Checkbox" {
                # Convert the value to a boolean for Checkbox type
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Convert the value to a Unix timestamp for Date or Date Time type
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Convert the dropdown value to its corresponding GUID
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
            
                # Throw an error if the value is not present in the dropdown options
                if (!($Selection)) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                }
            
                $NinjaValue = $Selection
            }
            default {
                # For other types, use the value as is
                $NinjaValue = $Value
            }
        }
            
        # Set the property value in the document if a document name is provided
        if ($DocumentName) {
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            # Otherwise, set the standard property value
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
            
        # Throw an error if setting the property failed
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated (administrator) privileges. If not elevated, display an error and exit with code 1.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Define paths for standard output and error logs, with random names to avoid conflicts
    $StandardOutLog = "$env:TEMP\$(Get-Random)_stdout.log"
    $StandardErrLog = "$env:TEMP\$(Get-Random)_stderr.log"

    # Define the arguments for the "net user" command to list all users
    $NetUserArguments = @(
        "user"
    )

    # Configure the process start parameters for the "net.exe" command
    $ProcessArguments = @{
        FilePath               = "$env:SystemRoot\System32\net.exe"
        ArgumentList           = $NetUserArguments
        RedirectStandardOutput = $StandardOutLog
        RedirectStandardError  = $StandardErrLog
        PassThru               = $True
        NoNewWindow            = $True
        Wait                   = $True
    }

    # Inform the user that the script is retrieving the list of local users
    Write-Host -Object "Retrieving list of local users."

    # Try to start the "net.exe" process and catch any errors
    try {
        $NetUserProcess = Start-Process @ProcessArguments -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] Failed to start net.exe"
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Output the exit code of the net.exe process
    Write-Host -Object "ExitCode: $($NetUserProcess.ExitCode)"

    # Check if the exit code indicates success (0 or 1)
    if ($NetUserProcess.ExitCode -ne 0 -and $NetUserProcess.ExitCode -ne 1) {
        Write-Warning "Exit code of $($NetUserProcess.ExitCode) does not indicate success."
    }

    # Check if the standard error log exists, indicating an error occurred
    if (Test-Path -Path $StandardErrLog -ErrorAction SilentlyContinue) {

        # Attempt to read the error log
        try {
            $ErrorLog = Get-Content -Path $StandardErrLog -ErrorAction Stop
        }
        catch {
            # If reading the log fails, display an error and exit
            Write-Host -Object "[Error] Failed to open error log at '$StandardErrLog'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        # Remove the error log file after reading
        try {
            Remove-Item -Path $StandardErrLog -ErrorAction Stop
        }
        catch {
            # If removing the log file fails, display an error
            Write-Host -Object "[Error] Failed to remove standard error log at '$StandardErrLog'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # If there is any content in the error log, display it and exit
    if ($ErrorLog) {
        Write-Host -Object "[Error] An error has occurred."
        $ErrorLog | ForEach-Object {
            Write-Host -Object "[Error] $_"
        }
        exit 1
    }

    # Check if the standard output log exists, which contains the user list
    if (!(Test-Path -Path $StandardOutLog -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] No net user output detected."
        exit 1
    }

    # Try to read the standard output log for user data
    try {
        $NetUserOutput = Get-Content -Path $StandardOutLog -ErrorAction Stop
    }
    catch {
        # If reading the log fails, display an error and exit
        Write-Host -Object "[Error] Failed to open output log at '$StandardOutLog'."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Try to remove the standard output log after reading
    try {
        Remove-Item -Path $StandardOutLog -ErrorAction Stop
    }
    catch {
        # If removing the log file fails, display an error
        Write-Host -Object "[Error] Failed to remove standard output log at '$StandardOutLog'."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    # Inform the user that the username list is being parsed
    Write-Host -Object "Parsing username list into machine-readable format."

    # Skip the first 4 lines of the output and filter out any empty lines or the completion message
    $NetUserOutput = $NetUserOutput | Select-Object -Skip 4 | Where-Object { $_ -and $_ -notmatch 'command completed' }

    # Split the usernames by 4 or more spaces and trim whitespace
    $Usernames = $NetUserOutput -split '\s{4,}' | ForEach-Object { $_.Trim() } | Where-Object { $_ }

    # Create a list to hold user account information
    $LocalUserAccounts = New-Object System.Collections.Generic.List[object]

    # Inform the user that additional information is being retrieved for each account
    Write-Host -Object "Retrieving additional information on individual user accounts."

    # For each username in the list, retrieve more details
    $Usernames | ForEach-Object {
        $Username = if ($_ -notmatch '"') { "`"$_`"" }else { $_ }
        $StandardOutLog = "$env:TEMP\$(Get-Random)_stdout.log"
        $StandardErrLog = "$env:TEMP\$(Get-Random)_stderr.log"

        # Define the arguments for the "net user" command for a specific user
        $NetUserArguments = @(
            "user"
            $Username
        )

        # Configure the process start parameters for the "net.exe" command
        $ProcessArguments = @{
            FilePath               = "$env:SystemRoot\System32\net.exe"
            ArgumentList           = $NetUserArguments
            RedirectStandardOutput = $StandardOutLog
            RedirectStandardError  = $StandardErrLog
            PassThru               = $True
            NoNewWindow            = $True
            Wait                   = $True
        }

        # Try to start the "net.exe" process for the current user
        try {
            $NetUserProcess = Start-Process @ProcessArguments -ErrorAction Stop
        }
        catch {
            # If the process fails, display an error and return to the next iteration
            Write-Host -Object "[Error] Failed to start net.exe for user '$_'"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            return
        }

        # Check if the exit code of the net.exe process indicates failure
        if ($NetUserProcess.ExitCode -ne 0) {
            Write-Warning "Exit code of $($NetUserProcess.ExitCode) does not indicate success."
        }

        # Check if the standard error log exists, indicating an error occurred
        if (Test-Path -Path $StandardErrLog -ErrorAction SilentlyContinue) {
            try {
                $ErrorLog = Get-Content -Path $StandardErrLog -ErrorAction Stop
            }
            catch {
                # If reading the log fails, display an error and set the exit code to 1
                Write-Host -Object "[Error] Failed to open error log at '$StandardErrLog'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                $ExitCode = 1
            }

            # Remove the error log file after reading
            try {
                Remove-Item -Path $StandardErrLog -ErrorAction Stop
            }
            catch {
                # If removing the log file fails, display an error and set the exit code to 1
                Write-Host -Object "[Error] Failed to remove standard error log at '$StandardErrLog'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                $ExitCode = 1
            }
        }

        # If there is any content in the error log, display it and set the exit code to 1
        if ($ErrorLog) {
            Write-Host -Object "[Error] An error has occurred."
            $ErrorLog | ForEach-Object {
                Write-Host -Object "[Error] $_"
            }
            $ExitCode = 1
        }

        # Check if the standard output log exists, which contains the user details
        if (!(Test-Path -Path $StandardOutLog -ErrorAction SilentlyContinue)) {
            Write-Host -Object "[Error] No net user output detected for '$_'."
            return
        }

        # Try to read the standard output log for user details
        try {
            $NetUserOutput = Get-Content -Path $StandardOutLog -ErrorAction Stop
        }
        catch {
            # If reading the log fails, display an error and return
            Write-Host -Object "[Error] Failed to open output log at '$StandardOutLog'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            return
        }

        # Try to remove the standard output log after reading
        try {
            Remove-Item -Path $StandardOutLog -ErrorAction Stop
        }
        catch {
            # If removing the log file fails, display an error and set the exit code to 1
            Write-Host -Object "[Error] Failed to remove standard output log at '$StandardOutLog'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }

        # Extract relevant information from the output log for each user account
        $LastSet = "$(($NetUserOutput | Select-String 'Password last set') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
        $Expired = "$(($NetUserOutput | Select-String 'Password expires') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
        $Changeable = "$(($NetUserOutput | Select-String 'Password changeable') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
        $LastLogon = "$(($NetUserOutput | Select-String 'Last logon') -split '\s{4,}' | Select-Object -Skip 1)".Trim()

        # Try to add user account details to the list of local user accounts
        try {
            $ErrorActionPreference = "Stop"
            $LocalUserAccounts.Add(
                [PSCustomObject]@{
                    Username              = $_
                    FullName              = "$(($NetUserOutput | Select-String 'Full Name') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
                    Comment               = "$(($NetUserOutput | Select-String 'Comment') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
                    Enabled               = if ("$(($NetUserOutput | Select-String 'Account active') -split '\s{4,}' | Select-Object -Skip 1)".Trim() -like "Yes") { $true }else { $false }
                    AccountExpires        = "$(($NetUserOutput | Select-String 'Account expires') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
                    PasswordLastSet       = if ($LastSet) { Get-Date -Date $LastSet }else { $null }
                    PasswordExpires       = if ($Expired -notmatch "Never" -and $Expired -notlike "") { Get-Date -Date $Expired }else { $Expired }
                    PasswordChangeable    = if ($Changeable) { Get-Date -Date $Changeable }else { $null }
                    PasswordRequired      = if ("$(($NetUserOutput | Select-String 'Password required') -split '\s{4,}' | Select-Object -Skip 1)".Trim() -like "Yes") { $true }else { $false }
                    UserMayChangePassword = if ("$(($NetUserOutput | Select-String 'User may change password') -split '\s{4,}' | Select-Object -Skip 1)".Trim() -like "Yes") { $true }else { $false }
                    WorkstationsAllowed   = "$(($NetUserOutput | Select-String 'Workstations allowed') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
                    LogonScript           = "$(($NetUserOutput | Select-String 'Logon script') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
                    UserProfile           = "$(($NetUserOutput | Select-String 'User profile') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
                    LastLogon             = if ($LastLogon -notmatch "Never" -and $LastLogon -notlike "") { Get-Date -Date $LastLogon }else { $LastLogon }
                    LogonHoursAllowed     = "$(($NetUserOutput | Select-String 'Logon hours allowed') -split '\s{4,}' | Select-Object -Skip 1)".Trim()
                }
            )
            $ErrorActionPreference = "Continue"
        }
        catch {
            # If adding the account details fails, display an error and set the exit code to 1
            Write-Host -Object "[Error] Failed to parse account '$_'"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            $ExitCode = 1

            # Silently continue and add a basic object with just the username to the list
            $ErrorActionPreference = "SilentlyContinue"
            $LocalUserAccounts.Add(
                [PSCustomObject]@{
                    Username = $_
                }
            )
            $ErrorActionPreference = "Continue"
        }
        
    }
    
    # Filter out disabled users if $IncludeDisabledUsers is not specified
    if (!$IncludeDisabledUsers) {
        $LocalUserAccounts = $LocalUserAccounts | Where-Object { $_.Enabled }
    }

    # Display the final list of users in a table format
    Write-Host -Object ""
    ($LocalUserAccounts | Sort-Object -Property Username | Format-Table -Property Username, FullName, Enabled, PasswordLastSet, LastLogon -AutoSize | Out-String).Trim() | Write-Host
    Write-Host -Object ""

    # If a custom field is specified, try to set it
    if ($WysiwygCustomField) {
        try {
            Write-Host "Attempting to set Custom Field '$WysiwygCustomField'."

            # Generate HTML content from the user accounts and format the output
            $CustomFieldValue = $LocalUserAccounts | Sort-Object -Property Username | Select-Object -Property Username, @{ Name = "Full Name" ; Expression = { $_.FullName } }, Enabled, @{ Name = "Password Last Set" ; Expression = { $_.PasswordLastSet } }, @{ Name = "Last Logon" ; Expression = { $_.LastLogon } } | ConvertTo-Html -Fragment
            $CustomFieldValue = $CustomFieldValue -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
            $CustomFieldValue = $CustomFieldValue -replace "<table>", "<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Local Users</b></caption>"

            # Set the custom field using the generated HTML
            Set-NinjaProperty -Name $WysiwygCustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$WysiwygCustomField'!"
        }
        catch {
            # If setting the custom field fails, display an error and exit
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Exit with the appropriate exit code
    exit $ExitCode
}
end {
    
    
    
}
