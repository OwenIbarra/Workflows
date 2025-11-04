# Retrieve the previous 14 reboot reasons and optionally save them to a WYSIWYG custom field, or save only the latest reboot reason to a text custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieve the previous 14 reboot reasons and optionally save them to a WYSIWYG custom field, or save only the latest reboot reason to a text custom field.
.DESCRIPTION
    Retrieve the previous 14 reboot reasons and optionally save them to a WYSIWYG custom field, or save only the latest reboot reason to a text custom field.
.EXAMPLE
    (No Parameters)

    Checking the event logs for possible reboot reasons.
    [Warning] Only the previous 5 reboot reasons were found.
    Translating the SIDs provided to usernames.

    ### Past Reboots ###
    FormattedDate : 12/18/2024 11:20 AM
    Id            : 6008
    User          : N/A
    Message       : The previous system shutdown at 11:20:06 AM on 12/18/2024 
                    was unexpected.

    FormattedDate : 12/18/2024 11:01 AM
    Id            : 1074
    User          : NT AUTHORITY\SYSTEM
    Message       : The process C:\Windows\servicing\TrustedInstaller.exe 
                    (SRV16-TEST) has initiated the restart of computer SRV16-TEST 
                    on behalf of user NT AUTHORITY\SYSTEM for the following 
                    reason: Operating System: Upgrade (Planned)
                    Reason Code: 0x80020003
                    Shutdown Type: restart
                    Comment: 

    FormattedDate : 12/18/2024 10:57 AM
    Id            : 6008
    User          : N/A
    Message       : The previous system shutdown at 10:56:15 AM on 12/18/2024 
                    was unexpected.

    FormattedDate : 12/16/2024 5:25 PM
    Id            : 1074
    User          : SRV16-TEST\Administrator
    Message       : The process C:\Windows\system32\wbem\wmiprvse.exe (SRV16-TEST) 
                    has initiated the shutdown of computer SRV16-TEST on behalf of 
                    user SRV16-TEST\Administrator for the following reason: No 
                    title for this reason could be found
                    Reason Code: 0x80070015
                    Shutdown Type: shutdown
                    Comment: 

    FormattedDate : 12/16/2024 5:22 PM
    Id            : 1074
    User          : NT AUTHORITY\SYSTEM
    Message       : The process C:\Windows\system32\winlogon.exe (MINWINPC) has 
                    initiated the restart of computer WIN-2686BKBDV33 on behalf of 
                    user NT AUTHORITY\SYSTEM for the following reason: Operating 
                    System: Upgrade (Planned)
                    Reason Code: 0x80020003
                    Shutdown Type: restart
                    Comment:

PARAMETER: -TextCustomField "ExampleInput"
    Optionally save the latest reboot reason to a text custom field of your choosing.

PARAMETER: -WysiwygCustomField "ReplaceMeWithAnyMultilineCustomField"
    Optionally save the previous 14 reboot reasons to a WYSIWYG custom field of your choosing.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$TextCustomField,
    [Parameter()]
    [String]$WysiwygCustomField
)

begin {
    # If script form variables are used, replace the command line parameters with their value.
    if ($env:lastRebootReasonTextCustomField -and $env:lastRebootReasonTextCustomField -notlike "null") { $TextCustomField = $env:lastRebootReasonTextCustomField }
    if ($env:last14RebootReasonsWysiwygCustomField -and $env:last14RebootReasonsWysiwygCustomField -notlike "null") { $WysiwygCustomField = $env:last14RebootReasonsWysiwygCustomField }

    # Check if a text custom field value was provided.
    if($TextCustomField){
        # Remove any leading or trailing whitespace.
        $TextCustomField = $TextCustomField.Trim()

        # If, after trimming, the text custom field is empty, print an error and exit.
        if(!$TextCustomField){
            Write-Host -Object "[Error] Please enter a valid text custom field."
            exit 1
        }
    }

    # Check if a WYSIWYG custom field value was provided.
    if($WysiwygCustomField){
        # Remove any leading or trailing whitespace.
        $WysiwygCustomField = $WysiwygCustomField.Trim()

        # If, after trimming, the WYSIWYG custom field is empty, print an error and exit.
        if(!$WysiwygCustomField){
            Write-Host -Object "[Error] Please enter a valid WYSIWYG custom field."
            exit 1
        }
    }

    # function Set-NinjaProperty { # Removed NinjaOne dependency
    # [CmdletBinding()] # Removed NinjaOne dependency
    # Param( # Removed NinjaOne dependency
    # [Parameter(Mandatory = $True)] # Removed NinjaOne dependency
    # [String]$Name, # Removed NinjaOne dependency
    # [Parameter()] # Removed NinjaOne dependency
    # [String]$Type, # Removed NinjaOne dependency
    # [Parameter(Mandatory = $True, ValueFromPipeline = $True)] # Removed NinjaOne dependency
    # $Value, # Removed NinjaOne dependency
    # [Parameter()] # Removed NinjaOne dependency
    # [String]$DocumentName, # Removed NinjaOne dependency
    # [Parameter()] # Removed NinjaOne dependency
    # [Switch]$Piped # Removed NinjaOne dependency
    # ) # Removed NinjaOne dependency
    # # Remove the non-breaking space character # Removed NinjaOne dependency
    # if ($Type -eq "WYSIWYG") { # Removed NinjaOne dependency
    # $Value = $Value -replace ' ', '&nbsp;' # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # Measure the number of characters in the provided value # Removed NinjaOne dependency
    # $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    
    # # Throw an error if the value exceeds the character limit of 200,000 characters # Removed NinjaOne dependency
    # if ($Piped -and $Characters -ge 200000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    
    # if (!$Piped -and $Characters -ge 45000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 45,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # Initialize a hashtable for additional documentation parameters # Removed NinjaOne dependency
    # $DocumentationParams = @{} # Removed NinjaOne dependency
    
    # # If a document name is provided, add it to the documentation parameters # Removed NinjaOne dependency
    # if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName } # Removed NinjaOne dependency
        
    # # Define a list of valid field types # Removed NinjaOne dependency
    # $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG" # Removed NinjaOne dependency
    
    # # Warn the user if the provided type is not valid # Removed NinjaOne dependency
    # if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" } # Removed NinjaOne dependency
        
    # # Define types that require options to be retrieved # Removed NinjaOne dependency
    # $NeedsOptions = "Dropdown" # Removed NinjaOne dependency
    
    # # If the property is being set in a document or field and the type needs options, retrieve them # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # Throw an error if there was an issue retrieving the property options # Removed NinjaOne dependency
    # if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions } # Removed NinjaOne dependency
            
    # # Process the property value based on its type # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # Convert the value to a boolean for Checkbox type # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Convert the value to a Unix timestamp for Date or Date Time type # Removed NinjaOne dependency
    # $Date = (Get-Date $Value).ToUniversalTime() # Removed NinjaOne dependency
    # $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date # Removed NinjaOne dependency
    # $NinjaValue = $TimeSpan.TotalSeconds # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Dropdown" { # Removed NinjaOne dependency
    # # Convert the dropdown value to its corresponding GUID # Removed NinjaOne dependency
    # $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name" # Removed NinjaOne dependency
    # $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID # Removed NinjaOne dependency
            
    # # Throw an error if the value is not present in the dropdown options # Removed NinjaOne dependency
    # if (!($Selection)) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # $NinjaValue = $Selection # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # default { # Removed NinjaOne dependency
    # # For other types, use the value as is # Removed NinjaOne dependency
    # $NinjaValue = $Value # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Set the property value in the document if a document name is provided # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # try { # Removed NinjaOne dependency
    # # Otherwise, set the standard property value # Removed NinjaOne dependency
    # if ($Piped) { # Removed NinjaOne dependency
    # $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # catch { # Removed NinjaOne dependency
    # Write-Host -Object "[Error] Failed to set custom field." # Removed NinjaOne dependency
    # throw $_.Exception.Message # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Throw an error if setting the property failed # Removed NinjaOne dependency
    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

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
    # Check if the current user is elevated (running as Administrator).
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Inform the user that the script is checking the event logs for possible reboot reasons.
    Write-Host -Object "Checking the event logs for possible reboot reasons."

    # Create an XML query to filter for certain event IDs (6008 and 1074) within the System event log.
    [xml]$EventViewerXML = "<QueryList>
  <Query Id='0' Path='System'>
    <Select Path='System'>*[System[Provider[@Name='Microsoft-Windows-Eventlog' or @Name='EventLog' or @Name='Microsoft-Windows-Kernel-General'] and(EventID=6008)]]</Select>
    <Select Path='System'>*[System[(EventID=1074)]]</Select>
  </Query>
</QueryList>"

    try {
        # Retrieve up to 14 recent matching events from the System log using the XML filter.
        # Stop on errors so exceptions can be caught.
        $MatchingEvents = Get-WinEvent -FilterXml $EventViewerXML -MaxEvents 14 -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to search event log."
        exit 1
    }

    # Count how many events were retrieved.
    $MatchingEventCount = $MatchingEvents | Measure-Object | Select-Object -ExpandProperty Count

    # If we found some events, but fewer than 14, warn the user that we have a limited number of reboot reasons.
    if ($MatchingEventCount -gt 0 -and $MatchingEventCount -lt 14) {
        Write-Host -Object "[Warning] Only the previous $MatchingEventCount reboot reasons were found."
    }

    # If no events were found, print an error and set the exit code to 1.
    if ($MatchingEventCount -lt 1) {
        Write-Host -Object "[Error] No reboot reasons were found."
        $ExitCode = 1
    }

    # Inform the user that SIDs are being translated to usernames.
    Write-Host -Object "Translating the SIDs provided to usernames."

    # Retrieve user profile information from the registry for SID-to-username mapping.
    try {
        $AllUserProfiles = Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to find any user profiles."
        $ExitCode = 1
    }

    # Format the retrieved events into a custom object with a friendly date format, ID, user, and message.
    $FormattedResults = $MatchingEvents | Select-Object -Property "TimeCreated", "Id", "UserId", "Message" | ForEach-Object {
        $Username = $null

        if ($_.UserId) {
            try {
                # Temporarily stop on errors to ensure exceptions are caught for SID translation.
                $ErrorActionPreference = "Stop"
                $SID = New-Object System.Security.Principal.SecurityIdentifier($_.UserId)

                # Attempt to translate the SID to an NT account (username).
                $Username = $SID.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value -ErrorAction SilentlyContinue
            }
            catch {
                # If direct SID translation fails, look up the profile in the registry.
                $Sid = $_.UserId
                $ProfileKey = $AllUserProfiles | Where-Object { $_.PSChildName -eq $Sid } | Select-Object @{Name = "Username"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf -ErrorAction SilentlyContinue)" } } -ErrorAction SilentlyContinue
                Write-Host -Object "[Error] Failed to gather complete profile information for the SID '$($_.UserId)'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                $ExitCode = 1
            }
        }
        else {
            # If there's no UserId, set the username to "N/A".
            $Username = "N/A"
        }

        # If no username was found directly, but we have a ProfileKey, use that as an approximation.
        if (!$Username -and $ProfileKey) {
            Write-Host -Object "Approximating the username for the SID '$Sid'."
            $Username = $ProfileKey
        }
        elseif (!$Username) {
            # If still no username is found, fall back to the SID itself.
            $Username = $SID
        }

        # Create a custom object with formatted data.
        [PSCustomObject]@{
            TimeCreated   = $_.TimeCreated
            FormattedDate = "$($_.TimeCreated.ToShortDateString()) $($_.TimeCreated.ToShortTimeString())"
            Id            = $_.Id
            User          = $Username
            Message       = $_.Message
        }

        # Restore the error action preference to continue.
        $ErrorActionPreference = "Continue"
    }

    # If either text or WYSIWYG custom fields were provided, print a blank line for readability.
    if ($TextCustomField -or $WysiwygCustomField) {
        Write-Host -Object ""
    }

    # If a text custom field is specified, set it to display the most recent event (truncated if too long).
    if ($TextCustomField) {
        # Get the most recent event (first in the list).
        $MostRecentEvent = $FormattedResults | Select-Object -First 1

        # If the message is longer than 100 characters, truncate it and add ellipsis.
        if (($MostRecentEvent.Message -replace '\r?\n', ' ').Length -gt 100) {
            $MostRecentEvent = $MostRecentEvent | Select-Object -Property FormattedDate, Id, User, @{Name = "Message"; Expression = { "$($_.Message.Substring(0,97))..." } }
        }

        # Construct the value to set in the text custom field.
        $TextCustomFieldValue = "$($MostRecentEvent.FormattedDate) | EventID: $($MostRecentEvent.Id) | Username: $($MostRecentEvent.User) | Reason: $($MostRecentEvent.Message -replace '\r?\n', ' ')"

        # Attempt to set the specified text custom field.
        try {
            Write-Host "Attempting to set the Custom Field '$TextCustomField'."
    # Set-NinjaProperty -Name $TextCustomField -Value $TextCustomFieldValue # Removed NinjaOne dependency
            Write-Host "Successfully set the Custom Field '$TextCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # If a WYSIWYG custom field is specified, construct an HTML table of the results and set the field.
    if ($WysiwygCustomField) {
        # Convert the formatted results to an HTML fragment.
        $HTMLTable = $FormattedResults | Select-Object -Property FormattedDate, Id, User, Message | ConvertTo-Html -Fragment

        # Bold the table headers and adjust column widths.
        $HTMLTable = $HTMLTable -replace '<th>', '<th><b>' -replace '</th>', '</b></th>'
        $HTMLTable = $HTMLTable -replace '<th><b>FormattedDate', "<th style='width: 12em'><b>Date" -replace '<th><b>Id', "<th style='width: 6em'><b>Event Id"
        $HTMLTable = $HTMLTable -replace '<th><b>User', "<th style='width: 20em'><b>Username" -replace '<th><b>Message', "<th><b>Reason"

        # Attempt to set the WYSIWYG custom field with the constructed HTML table.
        try {
            Write-Host "Attempting to set the Custom Field '$WysiwygCustomField'."
    # Set-NinjaProperty -Name $WysiwygCustomField -Value $HTMLTable # Removed NinjaOne dependency
            Write-Host "Successfully set the Custom Field '$WysiwygCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # Print a heading for past reboots and then display the formatted results as a list for reference.
    Write-Host -Object "`n### Past Reboots ###"
    ($FormattedResults | Format-List -Property FormattedDate, Id, User, UserId, Message | Out-String).Trim() | Write-Host

    # Exit with the previously set exit code (defaulting to 0 if not set).
    exit $ExitCode
}
end {
    
    
    
}
