# Reports on all installed browser extensions for Chrome, Firefox and Edge.
#Requires -Version 5.1

<#
.SYNOPSIS
    Reports on all installed browser extensions for Chrome, Firefox and Edge.
.DESCRIPTION
    Reports on all installed browser extensions for Chrome, Firefox and Edge.
.EXAMPLE
    (No Parameters)

    A Google Chrome installation was detected. Searching Chrome for browser extensions...
    A Microsoft Edge installation was detected. Searching Microsoft Edge for browser extensions...
    A Firefox installation was detected. Searching Firefox for browser extensions...
    Attempting to set Custom Field 'Multiline'.
    WARNING: 10,000 Character Limit has been reached! Trimming output until the character limit is satisfied...
    Successfully set Custom Field 'Multiline'!
    Attempting to set Custom Field 'WYSIWYG'.
    Successfully set Custom Field 'WYSIWYG'!
    Browser extensions were detected.


    Browser      : Chrome
    User         : cheart
    Name         : askBelynda | Sustainable Shopping
    Extension ID : pcmbjnfbjkeieekkahdfgchcbjfhhgdi
    Description  : Sustainable shopping made simple with askBelynda. Choose ethical products o(...)

    Browser      : Chrome
    User         : cheart
    Name         : Beni - Your secondhand shopping assistant
    Extension ID : efdgbhncnligcbloejoaemnfhjihkccj
    Description  : The easiest way to shop secondhand.  Beni finds the best resale alternative(...)

    Browser      : Chrome
    User         : cheart
    Name         : Bonjourr Ã‚Â· Minimalist Startpage
    Extension ID : dlnejlppicbjfcfcedcflplfjajinajd
    Description  : Improve your web browsing experience with Bonjourr, a beautiful, customizab(...)

    Browser      : Chrome
    User         : cheart
    Name         : Boxel 3D
    Extension ID : mjjgmlmpeaikcaajghilhnioimmaibon
    Description  : Boxel 3D is the 3rd release of your favorite box jumping game made by the d(...)

    ...

PARAMETER: -MultilineCustomField "ReplaceMeWithNameOfAMultilineCustomField"
    Specify the name of a multiline custom field to optionally store the search results in. Leave blank to not set a multiline field.

PARAMETER: -WysiwygCustomField "ReplaceMeWithAnyWYSIWYGCustomField"
    Specify the name of a WYSIWYG custom field to optionally store the search results in. Leave blank to not set a WYSIWYG field.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$MultilineCustomField,
    [Parameter()]
    [String]$WysiwygCustomField
)

begin {
    # Replace parameters with the dynamic script variables.
    if ($env:multilineCustomFieldName -and $env:multilineCustomFieldName -notlike "null") { $MultilineCustomField = $env:multilineCustomFieldName }
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WysiwygCustomField = $env:wysiwygCustomFieldName }

    # Check if $MultilineCustomField and $WysiwygCustomField are both not null and have the same value
    if ($MultilineCustomField -and $WysiwygCustomField -and $MultilineCustomField -eq $WysiwygCustomField) {
        Write-Host "[Error] Custom Fields of different types cannot have the same name."
        Write-Host "https://ninjarmm.zendesk.com/hc/en-us/articles/360060920631-Custom-Fields-Configuration-Device-Role-Fields"
        exit 1
    }

    # Function to get user registry hives based on the type of account
    function Get-UserHives {
        param (
            [Parameter()]
            [ValidateSet('AzureAD', 'DomainAndLocal', 'All')]
            [String]$Type = "All",
            [Parameter()]
            [String[]]$ExcludedUsers,
            [Parameter()]
            [switch]$IncludeDefault
        )
    
        # Patterns for user SID depending on account type
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # Fetch user profiles whose SIDs match the defined patterns and prepare objects with their details
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } | 
                Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                @{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                @{Name = "Path"; Expression = { $_.ProfileImagePath } }
        }
    
        # Handle inclusion of the default user profile if requested
        switch ($IncludeDefault) {
            $True {
                $DefaultProfile = "" | Select-Object UserName, SID, UserHive, Path
                $DefaultProfile.UserName = "Default"
                $DefaultProfile.SID = "DefaultProfile"
                $DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                $DefaultProfile.Path = "C:\Users\Default"
    
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.UserName }
            }
        }

        # Return user profiles, excluding any specified users
        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
    }

    # Function to check if the current PowerShell session is running with elevated permissions
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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

    # Function to find installation keys based on the display name, optionally returning uninstall strings
    function Find-InstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString,
            [Parameter()]
            [String]$UserBaseKey
        )
        process {
            # Initialize an empty list to hold installation objects
            $InstallList = New-Object System.Collections.Generic.List[Object]

            # If no user base key is specified, search in the default system-wide uninstall paths
            if (!$UserBaseKey) {
                # Search for programs in 32-bit and 64-bit locations. Then add them to the list if they match the display name
                $Result = Get-ChildItem -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }

                $Result = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
            else {
                # If a user base key is specified, search in the user-specified 64-bit and 32-bit paths.
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
    
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
    
            # If the UninstallString switch is specified, return only the uninstall strings; otherwise, return the full installation objects.
            if ($UninstallString) {
                $InstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $InstallList
            }
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated permissions (administrator rights)
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Search for Chrome installations on the system and enable chrome extension search if found.
    Find-InstallKey -DisplayName "Chrome" | ForEach-Object {
        $ChromeInstallations = $True
    }

    # Search for Firefox installations on the system and enable firefox extension search if found.
    Find-InstallKey -DisplayName "Firefox" | ForEach-Object {
        $FireFoxInstallations = $True
    }

    # Search for Edge installations on the system and flag if found and enable edge extension search if found.
    Find-InstallKey -DisplayName "Edge" | ForEach-Object {  
        $EdgeInstallations = $True
    }

    # Retrieve all user profiles from the system
    $UserProfiles = Get-UserHives -Type "All"
    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
        }

        # Repeat search for installations of browsers but in the user's registry context
        Find-InstallKey -UserBaseKey "Registry::HKEY_USERS\$($UserProfile.SID)" -DisplayName "Chrome" | ForEach-Object { 
            $ChromeInstallations = $True
        }
        Find-InstallKey -UserBaseKey "Registry::HKEY_USERS\$($UserProfile.SID)" -DisplayName "Firefox" | ForEach-Object { 
            $FireFoxInstallations = $True
        }
        Find-InstallKey -UserBaseKey "Registry::HKEY_USERS\$($UserProfile.SID)" -DisplayName "Edge" | ForEach-Object { 
            $EdgeInstallations = $True
        }

        # Unload NTuser.dat
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Initialize a list to store details of detected browser extensions
    $BrowserExtensions = New-Object System.Collections.Generic.List[object]

    # If Chrome was found, search for Chrome extensions in each user's profile
    if ($ChromeInstallations) {
        Write-Host -Object "A Google Chrome installation was detected. Searching Chrome for browser extensions..."
        $UserProfiles | ForEach-Object {
            if (!(Test-Path -Path "$($_.Path)\AppData\Local\Google\Chrome\User Data" -ErrorAction SilentlyContinue)) {
                return
            }

            if(Test-Path -Path "$($_.Path)\AppData\Local\Google\Chrome\User Data\Local State" -ErrorAction SilentlyContinue){
                $AllProfiles = Get-Content -Path "$($_.Path)\AppData\Local\Google\Chrome\User Data\Local State" | ConvertFrom-JSON
            }

            $PreferenceFiles = Get-ChildItem "$($_.Path)\AppData\Local\Google\Chrome\User Data\*\Preferences" -Exclude "System Profile" | Select-Object -ExpandProperty Fullname

            foreach ($PreferenceFile in $PreferenceFiles) {

                $GooglePreferences = Get-Content -Path $PreferenceFile | ConvertFrom-Json
                if($AllProfiles){
                    $ProfileLocation = $PreferenceFile | Get-Item | Select-Object -ExpandProperty Directory | Split-Path -Leaf
                    $ProfileName = $AllProfiles.profile.info_cache | Select-Object -ExpandProperty $ProfileLocation | Select-Object -ExpandProperty Name
                }else{
                    $ProfileName = $GooglePreferences.profile.name
                }

                foreach ($Extension in $GooglePreferences.extensions.settings.PSObject.Properties) {
                    $BrowserExtensions.Add(
                        [PSCustomObject]@{
                            Browser        = "Chrome"
                            User           = $_.UserName
                            Profile        = $ProfileName
                            Name           = $Extension.Value.manifest.name
                            "Extension ID" = $Extension.name
                            Description    = $Extension.Value.manifest.description
                        }
                    )
                }
            }
        }
    }

    # If Edge was found, search for Edge extensions in each user's profile
    if ($EdgeInstallations) {
        Write-Host -Object "A Microsoft Edge installation was detected. Searching Microsoft Edge for browser extensions..."
        $UserProfiles | ForEach-Object {
            if (!(Test-Path -Path "$($_.Path)\AppData\Local\Microsoft\Edge\User Data" -ErrorAction SilentlyContinue)) {
                return
            }

            if(Test-Path -Path "$($_.Path)\AppData\Local\Microsoft\Edge\User Data\Local State" -ErrorAction SilentlyContinue){
                $AllProfiles = Get-Content -Path "$($_.Path)\AppData\Local\Microsoft\Edge\User Data\Local State" | ConvertFrom-JSON
            }

            $PreferenceFiles = Get-ChildItem "$($_.Path)\AppData\Local\Microsoft\Edge\User Data\*\Preferences" -Exclude "System Profile" | Select-Object -ExpandProperty Fullname

            foreach ($PreferenceFile in $PreferenceFiles) {

                $EdgePreferences = Get-Content -Path $PreferenceFile | ConvertFrom-Json
                if($AllProfiles){
                    $ProfileLocation = $PreferenceFile | Get-Item | Select-Object -ExpandProperty Directory | Split-Path -Leaf
                    $ProfileName = $AllProfiles.profile.info_cache | Select-Object -ExpandProperty $ProfileLocation | Select-Object -ExpandProperty Name
                }else{
                    $ProfileName = $EdgePreferences.profile.name
                }

                foreach ($Extension in $EdgePreferences.extensions.settings.PSObject.Properties) {
                    if ($Extension.Value.active_bit -like "False" ) { continue }
                    if (!$Extension.Value.manifest.name) { continue }
                    $BrowserExtensions.Add(
                        [PSCustomObject]@{
                            Browser        = "Edge"
                            User           = $_.UserName
                            Profile        = $ProfileName
                            Name           = $Extension.Value.manifest.name
                            "Extension ID" = $Extension.name
                            Description    = $Extension.Value.manifest.description
                        }
                    )
                }
            }
        }
    }

    # If Firefox was found, search for Firefox extensions in each user's profile
    if ($FireFoxInstallations) {
        Write-Host -Object "A Firefox installation was detected. Searching Firefox for browser extensions..." 
        $UserProfiles | ForEach-Object {
            if (!(Test-Path -Path "$($_.Path)\AppData\Roaming\Mozilla\Firefox\Profiles" -ErrorAction SilentlyContinue)) {
                return
            }

            $FirefoxProfileFolders = Get-ChildItem -Path "$($_.Path)\AppData\Roaming\Mozilla\Firefox\Profiles" -Directory | Where-Object { $_.Name -match "\.default-release$" } | Select-Object -ExpandProperty Fullname

            foreach ( $FirefoxProfile in $FirefoxProfileFolders ) {

                if (!(Test-Path -Path "$FirefoxProfile\extensions.json")) {
                    continue
                }

                $Extensions = Get-Content -Path "$FirefoxProfile\extensions.json" | ConvertFrom-Json

                foreach ($Extension in $Extensions.addons) {
                    $BrowserExtensions.Add(
                        [PSCustomObject]@{
                            Browser        = "Firefox"
                            User           = $_.UserName
                            Profile        = "N/A"
                            Name           = $Extension.defaultlocale.name
                            "Extension ID" = $Extension.id
                            Description    = $Extension.defaultlocale.description
                        }
                    )
                }
            }
        }
    }

    # Check if there are any browser extensions to process
    if ($BrowserExtensions.Count -gt 0) {
        # Format the BrowserExtensions list to include a shortened description if the description is too long.
        $BrowserExtensions = $BrowserExtensions | Select-Object Browser, User, Profile, Name, "Extension ID", @{
            Name       = "Description"
            Expression = {
                $Characters = $_.Description | Measure-Object -Character | Select-Object -ExpandProperty Characters
                if ($Characters -gt 75) {
                    "$(($_.Description).SubString(0,75))(...)"
                }
                else {
                    $_.Description
                }
            }
        }
    }

    # Check if extensions were found and if we were requested to set a multiline custom field
    if ($BrowserExtensions.Count -gt 0 -and $MultilineCustomField) {
        try {
            Write-Host "Attempting to set Custom Field '$MultilineCustomField'."
            $CustomFieldValue = New-Object System.Collections.Generic.List[string]

            # Sort and format the list of extensions for output
            $CustomFieldList = $BrowserExtensions | Sort-Object Browser, User, Profile, Name | Select-Object Browser, User, Profile, Name, "Extension ID", Description
            $CustomFieldValue.Add(($CustomFieldList | Format-List | Out-String))

            # Measure the total character count of the formatted string
            $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
            if ($Characters -ge 9500) {
                Write-Warning "10,000 Character Limit has been reached! Trimming output until the character limit is satisfied..."
                    
                # If it doesn't comply with the limits we'll need to recreate it with some adjustments.
                $i = 0
                do {
                    # Recreate the custom field output starting with a warning that we truncated the output.
                    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
                    $CustomFieldValue.Add("This info has been truncated to accommodate the 10,000 character limit.")
                    
                    # Flip the array so that the last entry is on top.
                    [array]::Reverse($CustomFieldList)
    
                    # Remove the next item.
                    $CustomFieldList[$i] = $null
                    $i++
    
                    # We'll flip the array back to right side up.
                    [array]::Reverse($CustomFieldList)
    
                    # Add it back to the output.
                    $CustomFieldValue.Add(($CustomFieldList | Format-List | Out-String))
    
                    # Check that we now comply with the character limit. If not restart the do loop.
                    $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
                }while ($Characters -ge 9500)
            }

            Set-NinjaProperty -Name $MultilineCustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$MultilineCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # Check if extensions were found and if we were requested to set a WYSIWYG custom field.
    if ($BrowserExtensions.Count -gt 0 -and $WysiwygCustomField) {
        try {
            Write-Host "Attempting to set Custom Field '$WysiwygCustomField'."
    
            # Prepare the custom field output.
            $CustomFieldValue = New-Object System.Collections.Generic.List[string]
    
            # Convert the matching events into an html report.
            $htmlTable = $BrowserExtensions | Sort-Object Browser, User, Profile, Name | Select-Object Browser, User, Profile, Name, "Extension ID", Description | ConvertTo-Html -Fragment
    
            # Add the newly created html into the custom field output.
            $CustomFieldValue.Add($htmlTable)
    
            # Check that the output complies with the hard character limits.
            $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
            if ($Characters -ge 199500) {
                Write-Warning "200,000 Character Limit has been reached! Trimming output until the character limit is satisfied..."
                    
                # If it doesn't comply with the limits we'll need to recreate it with some adjustments.
                $i = 0
                do {
                    # Recreate the custom field output starting with a warning that we truncated the output.
                    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
                    $CustomFieldValue.Add("<h1>This info has been truncated to accommodate the 200,000 character limit.</h1>")
    
                    # Flip the array so that the last entry is on top.
                    [array]::Reverse($htmlTable)
                    # If the next entry is a row we'll delete it.
                    if ($htmlTable[$i] -match '<tr><td>' -or $htmlTable[$i] -match '<tr class=') {
                        $htmlTable[$i] = $null
                    }
                    $i++
                    # We'll flip the array back to right side up.
                    [array]::Reverse($htmlTable)
    
                    # Add it back to the output.
                    $CustomFieldValue.Add($htmlTable)
    
                    # Check that we now comply with the character limit. If not restart the do loop.
                    $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
                }while ($Characters -ge 199500)
            }
    
            # Set the custom field.
            Set-NinjaProperty -Name $WysiwygCustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$WysiwygCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    if ($BrowserExtensions.Count -gt 0) {
        Write-Host "Browser extensions were detected."
        $BrowserExtensions | Sort-Object Browser, User, Profile, Name | Format-List | Out-String | Write-Host
    }
    else {
        Write-Host "No browser extensions were found!"
    }

    exit $ExitCode
}
end {
    
    
    
}
