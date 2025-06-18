# Alerts if no user is logged in or if the specified user(s) are not logged in. You can optionally retrieve a comma-separated list from a custom field you specify.

<#
.SYNOPSIS
    Alerts if no user is logged in or if the specified user(s) are not logged in. You can optionally retrieve a comma-separated list from a custom field you specify.
.DESCRIPTION
    Alerts if no user is logged in or if the specified user(s) are not logged in. You can optionally retrieve a comma-separated list from a custom field you specify.
.EXAMPLE
    (No Parameters)
    A user was not given to look for. Alerting if no user is logged in.
    A user is currently signed in!

    Username SessionName ID State  IdleTime LogonTime         
    -------- ----------- -- -----  -------- ---------         
    cheart   console     1  Active none     10/24/2024 6:31 PM

PARAMETER: -UsersToCheckFor "itAdmin"
    Specify a comma-separated list of users you would like to alert on if they are not currently logged in.

PARAMETER: -CustomFieldName "ReplaceMeWithAnyTextCustomField"
    The name of a text custom field from which to retrieve the UsersToCheckFor value.

PARAMETER: -ActiveOnly
    Alerts only if the user is listed as 'active' in quser.exe.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Allows checking for multiple users, added data validation, stopped using exit codes as alert triggers, removed Write-Error, switched to the standard alert tag '[Alert]' for when an alert is triggered. Updated functions.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$UsersToCheckFor,
    [Parameter()]
    [String]$CustomFieldName,
    [Parameter()]
    [Switch]$ActiveOnly = [System.Convert]::ToBoolean($env:userMustBeActive)
)

begin {
    # If script variables are used overwrite the existing variables.
    if ($env:usersToCheckFor -and $env:usersToCheckFor -notlike "null") { $UsersToCheckFor = $env:usersToCheckFor }
    if ($env:retrieveUserFromCustomFieldName -and $env:retrieveUserFromCustomFieldName -notlike "null") { $CustomFieldName = $env:retrieveUserFromCustomFieldName }

    if ($PSversionTable.PSVersion.Major -lt 3 -and $CustomFieldName) {
        Write-Host -Object "[Error] PowerShell 3 or higher is required to retrieve from custom fields."
        Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/en-us/articles/4405408656013-Custom-Fields-and-Documentation-CLI-and-Scripting"
        exit 1
    }

    # This function is to make it easier to parse Ninja Custom Fields.
    function Get-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter()]
            [String]$DocumentName
        )
        
        # Initialize a hashtable for documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
    
        # Define types that require options to be retrieved
        $NeedsOptions = "DropDown", "MultiSelect"
        
        # If a document name is provided, retrieve the property value from the document
        if ($DocumentName) {
            # Throw an error if the type is "Secure", as it's not a valid type in this context
            if ($Type -Like "Secure") { throw [System.ArgumentOutOfRangeException]::New("$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality") }
        
            # Notify the user that the value is being retrieved from a Ninja document
            Write-Host "Retrieving value from Ninja Document..."
            $NinjaPropertyValue = Ninja-Property-Docs-Get -AttributeName $Name @DocumentationParams 2>&1
        
            # If the property type requires options, retrieve them
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            # If no document name is provided, retrieve the property value directly
            $NinjaPropertyValue = Ninja-Property-Get -Name $Name 2>&1
    
            # If the property type requires options, retrieve them
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # Throw an exception if there was an error retrieving the property value or options
        if ($NinjaPropertyValue.Exception) { throw $NinjaPropertyValue }
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
        
        # Throw an error if the retrieved property value is null or empty
        if (!($NinjaPropertyValue)) {
            Write-Warning -Message "The Custom Field '$Name' is empty."
        }
        
        # Handle the property value based on its type
        switch ($Type) {
            "Attachment" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Checkbox" {
                # Convert the value to a boolean
                [System.Convert]::ToBoolean([int]$NinjaPropertyValue)
            }
            "Date or Date Time" {
                # Convert a Unix timestamp to local date and time
                $UnixTimeStamp = $NinjaPropertyValue
                $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds($UnixTimeStamp)
                $TimeZone = [TimeZoneInfo]::Local
                [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
            }
            "Decimal" {
                # Convert the value to a double (floating-point number)
                [double]$NinjaPropertyValue
            }
            "Device Dropdown" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Device MultiSelect" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Dropdown" {
                # Convert options to a CSV format and match the GUID to retrieve the display name
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Options | Where-Object { $_.GUID -eq $NinjaPropertyValue } | Select-Object -ExpandProperty Name
            }
            "Integer" {
                # Convert the value to an integer
                [int]$NinjaPropertyValue
            }
            "MultiSelect" {
                # Convert options to a CSV format, then match and return selected items
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = ($NinjaPropertyValue -split ',').trim()
        
                foreach ($Item in $Selection) {
                    $Options | Where-Object { $_.GUID -eq $Item } | Select-Object -ExpandProperty Name
                }
            }
            "Organization Dropdown" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location Dropdown" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location MultiSelect" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization MultiSelect" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Time" {
                # Convert the value from seconds to a time format in the local timezone
                $Seconds = $NinjaPropertyValue
                $UTC = ([timespan]::fromseconds($Seconds)).ToString("hh\:mm\:ss")
                $TimeZone = [TimeZoneInfo]::Local
                $ConvertedTime = [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
        
                Get-Date $ConvertedTime -DisplayHint Time
            }
            default {
                # For any other types, return the raw value
                $NinjaPropertyValue
            }
        }
    }

    function Get-QueryUser {
        # Run the quser.exe command to get the list of currently logged-in users
        try {
            $ErrorActionPreference = "Stop"
            $QuserOutput = quser.exe
            $ErrorActionPreference = "Continue"
        }
        catch {
            throw $_
        }
    
        $i = 0
        $QuserOutput | Where-Object { $_.Trim() } | ForEach-Object {
            # Skip the first line (header) and process only the data lines
            if ($i -ne 0) {
                # Extract the relevant columns using fixed width positions
                [PSCustomObject]@{
                    Username    = ($_.Substring(0, 21).Trim() -replace '^>')
                    SessionName = $_.Substring(21, 21).Trim()
                    ID          = $_.Substring(40, 5).Trim()
                    State       = $_.Substring(45, 10).Trim()
                    IdleTime    = $_.Substring(55, 10).Trim()
                    LogonTime   = $_.Substring(65).Trim()
                }
            }
    
            $i++
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}process {
    # Initialize an empty list to store the usernames that will be alerted on.
    $UsersToAlertOn = New-Object System.Collections.Generic.List[string]

    # Split the $UsersToCheckFor string by commas, trim each username, and add to the list.
    $UsersToCheckFor -split ',' | ForEach-Object {
        $User = $_.Trim()

        # Check if the username starts and ends with double quotes (") using regex matching.
        if ($User -match '^"' -and $User -match '"$') {
            $User = $User -replace '^"' -replace '"$'
        }

        # Check if the username contains any invalid characters (special characters) using a regular expression.
        if ($User -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|"|@') {
            Write-Host -Object ("[Error] $_ contains one of the following invalid characters." + ' " [ ] : ; | = + * ? < > / \ @')

            # Set an exit code to indicate an error
            $ExitCode = 1
            return
        }

        # Only add non-empty usernames to the list.
        if ($User) {
            $UsersToAlertOn.Add($User)
        }
    }

    # If a custom field name is provided, retrieve user list from that field.
    if ($CustomFieldName) { 
        try {
            # Retrieve users from the custom field.
            $UsersToCheckFor = Get-NinjaProperty -Name $CustomFieldName

            # Split, trim, and add users from the custom field to the alert list.
            $UsersToCheckFor -split ',' | ForEach-Object {
                $User = $_.Trim()

                # Check if the username starts and ends with double quotes (") using regex matching.
                if ($User -match '^"' -and $User -match '"$') {
                    $User = $User -replace '^"' -replace '"$'
                }

                # Check if the username contains any invalid characters (special characters) using a regular expression.
                if ($User -match '\[|\]|:|;|\||=|\+|\*|\?|<|>|/|\\|"|@') {
                    Write-Host -Object ("[Error] $_ contains one of the following invalid characters." + ' " [ ] : ; | = + * ? < > / \ @')

                    # Set an exit code to indicate an error
                    $ExitCode = 1
                    return
                }
        
                # Add non-empty usernames to the list.
                if ($User) {
                    $UsersToAlertOn.Add($User)
                }
            }
        }
        catch {
            # If an error occurs, output the error message and exit the script with status 1.
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # If users were added to the alert list, display them. Otherwise, notify that no specific user was given.
    if ($UsersToAlertOn.Count -gt 0) {
        Write-Host -Object "Checking for the following users: $($UsersToAlertOn -join ", ")"
    }
    else {
        Write-Host -Object "A user was not given to look for. Alerting if no user is logged in."
    }

    # Try to retrieve the currently logged-in users.
    try {
        $LoggedInUsers = Get-QueryUser
    }
    catch {
        # Output error message and exit if the Get-QueryUser command fails.
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # If specific users are being checked, filter the logged-in users to only include those from the alert list.
    if ($UsersToAlertOn.Count -gt 0) {
        $LoggedInUsers = $LoggedInUsers | Where-Object { $UsersToAlertOn -contains $_.Username }
    }

    # If the $ActiveOnly flag is set, further filter the logged-in users to only include those marked as active.
    if ($ActiveOnly) {
        $LoggedInUsers = $LoggedInUsers | Where-Object { $_.State -like "Active" }
    }

    # If no users were found after filtering, alert that no users are logged in or specific users are not logged in.
    if (!$LoggedInUsers) {
        if ($UsersToAlertOn.Count -gt 0) {
            Write-Host -Object "[Alert] The user(s) you are checking for are not currently logged in."
        }
        else {
            Write-Host -Object "[Alert] No users are currently logged in."
        }
    }

    # If users were found after filtering, check if any of the users from the alert list are logged in or not.
    if ($LoggedInUsers) {
        if ($UsersToAlertOn.Count -gt 0) {
            # Alert for users who are not logged in.
            $UsersToAlertOn | Where-Object { $LoggedInUsers.Username -notcontains $_ } | ForEach-Object {
                Write-Host -Object "[Alert] $_ is not currently logged in."
            }

            # Notify for users who are currently logged in.
            $UsersToAlertOn | Where-Object { $LoggedInUsers.Username -contains $_ } | ForEach-Object {
                Write-Host -Object "$_ is currently logged in."
            }
        }
        else {
            # If no specific users were given, notify that a user is logged in.
            Write-Host -Object "A user is currently signed in!"
        }
    }
    
    # Display the list of logged-in users in a table format.
    $LoggedInUsers | Format-Table | Out-String | Write-Host
    
    exit $ExitCode
}end {
    
    
    
}

