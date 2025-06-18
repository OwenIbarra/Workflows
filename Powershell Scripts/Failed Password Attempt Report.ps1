# Returns the number of failed login attempts of all users or for a specific user.
#Requires -Version 4 -RunAsAdministrator

<#
.SYNOPSIS
    Returns the number of failed login attempts of all users or for a specific user.
.DESCRIPTION
    Returns the number of failed login attempts of all users or for a specific user.
.EXAMPLE
    -UserName "tuser"

    No failed logins detected for user tuser.

.EXAMPLE
    -UserName "tuser" -Detailed

    WARNING: Failed logins detected.

    TimeGenerated         Username SourceIP  FailureStatus                 
    -------------         -------- --------  -------------                 
    12/7/2023 10:33:48 AM tuser    127.0.0.1 Incorrect username or password
    12/7/2023 10:33:29 AM tuser    127.0.0.1 Incorrect username or password
    12/7/2023 10:33:25 AM tuser    127.0.0.1 Incorrect username or password

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012

    Release Notes: Renamed script, added Script Variable support, made output more verbose.
.COMPONENT
    ManageUsers
#>

param (
    # The name of a remote computer to get event logs for failed logins
    [Parameter()]
    [String]$ComputerName = [System.Net.Dns]::GetHostName(),
    # A username
    [Parameter()]
    [String]$UserName,
    # Returns all relevant events, sorted by TimeGenerated
    [Parameter()]
    [Switch]$Detailed = [System.Convert]::ToBoolean($env:detailedReport),
    # Name of a WYSIWYG custom field to optionally save the results to.
    [Parameter()]
    [String]$WysiwygCustomField
)

begin {

    if ($env:usernameToCheck -and $env:usernameToCheck -notlike "null") { $UserName = $env:usernameToCheck }
    if ($env:retrieveLogsFromComputerName -and $env:retrieveLogsFromComputerName -notlike "null") { $ComputerName = $env:retrieveLogsFromComputerName }
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WysiwygCustomField = $env:wysiwygCustomFieldName }

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
        $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
    
        # Throw an error if the value exceeds the character limit of 200,000 characters
        if ($Characters -ge 200000) {
            throw "Character limit exceeded: the value is greater than or equal to 200,000 characters."
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

    # Support functions
    # Returns the matching FailureReason like Incorrect password
    function Get-FailureReason {
        Param($FailureReason)
        switch ($FailureReason) {
            '0xC0000064' { "Account does not exist"; break; }
            '0xC000006A' { "Incorrect password"; break; }
            '0xC000006D' { "Incorrect username or password"; break; }
            '0xC000006E' { "Account restriction"; break; }
            '0xC000006F' { "Invalid logon hours"; break; }
            '0xC000015B' { "Logon type not granted"; break; }
            '0xc0000070' { "Invalid Workstation"; break; }
            '0xC0000071' { "Password expired"; break; }
            '0xC0000072' { "Account disabled"; break; }
            '0xC0000133' { "Time difference at DC"; break; }
            '0xC0000193' { "Account expired"; break; }
            '0xC0000224' { "Password must change"; break; }
            '0xC0000234' { "Account locked out"; break; }
            '0x0' { "0x0"; break; }
            default { "Other"; break; }
        }
    }
    function Get-LogonType {
        Param($LogonType)
        switch ($LogonType) {
            '0' { 'Interactive'; break; }
            '2' { 'Interactive'; break; }
            '3' { 'Network'; break; }
            '4' { 'Batch'; break; }
            '5' { 'Service'; break; }
            '6' { 'Proxy'; break; }
            '7' { 'Unlock'; break; }
            '8' { 'Networkcleartext'; break; }
            '9' { 'NewCredentials'; break; }
            '10' { 'RemoteInteractive'; break; }
            '11' { 'CachedInteractive'; break; }
            '12' { 'CachedRemoteInteractive'; break; }
            '13' { 'CachedUnlock'; break; }
            Default {}
        }
    }

    $script:FailedLoginsFound = $false
}
process {
    #-Newest $Records
    $Events = Get-EventLog -ComputerName $ComputerName -LogName 'security' -InstanceId 4625, 4624 | Sort-Object -Descending -Property TimeGenerated | ForEach-Object {
        if ($_.InstanceId -eq 4625) {
            $_ | Select-Object -Property @(
                @{Label = 'TimeGenerated'; Expression = { $_.TimeGenerated } },
                @{Label = 'EventID'; Expression = { $_.InstanceId } },
                @{Label = 'Category'; Expression = { $_.CategoryNumber } },
                @{Label = 'Username'; Expression = { "$($_.ReplacementStrings[5])".ToLower() } },
                @{Label = 'Domain'; Expression = { $_.ReplacementStrings[6] } },
                @{Label = 'UserSID'; Expression = { (($_.Message -Split '\r\n' | Select-String 'Security ID')[1] -Split '\s+')[3] } },
                # @{Label = 'UserSID'; Expression = { $_.ReplacementStrings[0] } },
                @{Label = 'Workstation'; Expression = { $_.ReplacementStrings[13] } },
                @{Label = 'SourceIP'; Expression = { $_.ReplacementStrings[19] } },
                @{Label = 'Port'; Expression = { $_.ReplacementStrings[20] } },
                @{Label = 'LogonType'; Expression = { $_.ReplacementStrings[8] } },
                @{Label = 'FailureStatus'; Expression = { Get-FailureReason($_.ReplacementStrings[7]) } },
                @{Label = 'FailureSubStatus'; Expression = { Get-FailureReason($_.ReplacementStrings[9]) } }
            )
        }
        elseif ($_.InstanceId -eq 4624 -and (Get-LogonType($_.ReplacementStrings[8])) -notlike 'Service') {
            $_ | Select-Object -Property @(
                @{Label = 'TimeGenerated'; Expression = { $_.TimeGenerated } },
                @{Label = 'EventID'; Expression = { $_.InstanceId } },
                @{Label = 'Category'; Expression = { $_.CategoryNumber } },
                @{Label = 'Username'; Expression = { "$($_.ReplacementStrings[5])".ToLower() } },
                @{Label = 'Domain'; Expression = { $_.ReplacementStrings[6] } },
                @{Label = 'UserSID'; Expression = { $_.ReplacementStrings[0] } },
                @{Label = 'Workstation'; Expression = { $_.ReplacementStrings[11] } },
                @{Label = 'SourceIP'; Expression = { $_.ReplacementStrings[18] } },
                @{Label = 'Port'; Expression = { $_.ReplacementStrings[19] } },
                @{Label = 'LogonType'; Expression = { Get-LogonType($_.ReplacementStrings[8]) } },
                @{Label = 'LogonID'; Expression = { Get-FailureReason($_.ReplacementStrings[7]) } },
                @{Label = 'LogonProcess'; Expression = { Get-FailureReason($_.ReplacementStrings[9]) } }
            )
        }
    }

    if ( -not $Events) {
        Write-Host "[Info] No Logins Detected!"
        exit 0
    }

    if ($Detailed) {
        $Report = if ($UserName) {
            Write-Host "[Info] Checking for failed logins for user $UserName"
            $Events | Where-Object { $_.Username -like "*$UserName*" -and $_.EventID -ne 4624 } | Select-Object -Property TimeGenerated, Username, SourceIP, FailureStatus
        }
        else {
            Write-Host "[Info] Checking for failed logins for all users"
            $Events | Where-Object { $_.Username -notlike "DWM*" -and $_.Username -notlike "UMFD*" -and $_.Username -notlike "SYSTEM" -and $_.EventID -ne 4624 } | Select-Object -Property TimeGenerated, Username, SourceIP, FailureStatus
        }

        if ($UserName -and $Report) {
            $script:FailedLoginsFound = $true
        }
        elseif ($Report) { $script:FailedLoginsFound = $true }
    }
    else {
        $ReportObject = New-Object System.Collections.Generic.List[PSCustomObject]
        $UserNames = if ($UserName) {
            Write-Host "[Info] Checking for failed logins for user $UserName"
            $Events | Select-Object -ExpandProperty UserName -Unique | Where-Object { $_ -like "$UserName" }
        }
        else {
            Write-Host "[Info] Checking for failed logins for all users"
            $Events | Select-Object -ExpandProperty UserName -Unique | Where-Object { $_ -notlike "DWM*" -and $_ -notlike "UMFD*" -and $_ -notlike "SYSTEM" }
        }

        $UserNames | ForEach-Object {
            $CurrentUserName = $_
            $FailedLoginCount = 0
            for ($i = 0; $i -lt $Events.Count; $i++) {
                if ($Events[$i].EventID -eq 4625 -and $Events[$i].Username -like $CurrentUserName) {
                    # User failed to login X times
                    # Count the number of failed logins
                    $FailedLoginCount++
                }
            }
            if ($UserName) {
                # If a UserName was specified, then return only the failed login count
                if ($FailedLoginCount -gt 0) {
                    $script:FailedLoginsFound = $true
                }
            }
            else {
                if ($FailedLoginCount -gt 0) {
                    $script:FailedLoginsFound = $true
                }

                # If no UserName was specified, then return the user name and failed login count
                $ReportObject.Add($([PSCustomObject]@{ UserName = $CurrentUserName; FailedLoginAttempts = $FailedLoginCount }))
            }
        }
    }

    if ($script:FailedLoginsFound) {
        Write-Host "[Warn] Failed logins detected"
    }
    else {
        Write-Host "[Info] No failed logins detected"
    }

    if ($Detailed) {
        if ($UserName) {
            if (-not $Report) {
                Write-Host "[Info] No failed logins detected for user $UserName"
            }
            else {
                Write-Host "[Warn] Failed logins detected for user $UserName"
            }
        }
        else {
            if (-not $Report) {
                Write-Host "[Info] No failed logins detected"
            }
        }
        if ($Report) { $Report | Format-Table -AutoSize | Out-String | Write-Host }
    }
    else {
        if ($ReportObject) {
            if ($UserName) {
                $ReportObject | Where-Object { $_.UserName -like $UserName } | ForEach-Object {
                    if ($_.FailedLoginAttempts -gt 0) {
                        Write-Host "[Warn] $($_.UserName) has $($_.FailedLoginAttempts) failed logins"
                    }
                    else {
                        Write-Host "[Info] $($_.UserName) has no failed logins"
                    }
                }
            }
            else {
                $ReportObject | ForEach-Object {
                    if ($_.FailedLoginAttempts -gt 0) {
                        Write-Host "[Warn] $($_.UserName) has $($_.FailedLoginAttempts) failed logins"
                    }
                    else {
                        Write-Host "[Info] $($_.UserName) has no failed logins"
                    }
                }
            }
            $ReportObject | Format-Table -AutoSize | Out-String | Write-Host
        }
    }

    if ($WysiwygCustomField) {
        try {
            $WysiwygReport = if ($Detailed) {
                if ($script:FailedLoginsFound) {
                    "<h2>Failed Login Events</h2>"
                    $($Report | ConvertTo-Html -Fragment | Out-String)
                }
                else {
                    "<h2>No Failed Logins Detected!</h2>"
                }
            }
            else {
                if ($script:FailedLoginsFound) {
                    "<h2>Failed Logins</h2>"
                    $($ReportObject | ConvertTo-Html -Fragment | Out-String)
                }
                else {
                    "<h2>No Failed Logins Detected!</h2>"
                }
            }
            Write-Host "[Info] Attempting to set Custom Field '$WysiwygCustomField'"
            Set-NinjaProperty -Name $WysiwygCustomField -Value $WysiwygReport
            Write-Host "[Info] Successfully set Custom Field '$WysiwygCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
}
end {
    
    
    
}


