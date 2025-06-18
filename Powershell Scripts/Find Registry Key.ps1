# Find a registry key path, property or value that contains your given search text. Larger depth values may increase script runtime.
#Requires -Version 5.1

<#
.SYNOPSIS
    Find a registry key path, property or value that contains your given search text. Larger depth values may increase script runtime.
.DESCRIPTION
    Find a registry key path, property or value that contains your given search text. Larger depth values may increase script runtime.
.EXAMPLE
    -RootKey "HKEY_USERS" -SearchPath "*\Software" -Search "Microsoft" -Path -Property -Value

    WARNING: Matching registry path names found!
    WARNING: Matching registry properties found!
    WARNING: Matching registry key values found!


    Path     : HKEY_USERS\.DEFAULT\Software\AppDataLow\Software\Microsoft
    Property : N/A
    Value    : N/A

    Path     : HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CClipchamp.Clipchamp_2.9.1.0_neutral__yxz26nhyzhsrt%5Cresources.pri\1da6c1775fdf538\a37dfe62
    Property : @{C:\Program Files\WindowsApps\Clipchamp.Clipchamp_2.9.1.0_neutral__yxz26nhyzhsrt\resources.pri? ms-resource:///resources/Clipchamp/AppName}
    Value    : Microsoft Clipchamp

    Path     : HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.BingNews_4.55.62231.0_x64__8wekyb3d8bbwe%5Cresources.pri\1da6c1719ed8ee6\a37dfe62
    Property : @{C:\Program Files\WindowsApps\Microsoft.BingNews_4.55.62231.0_x64__8wekyb3d8bbwe\resources.pri? ms-resource:///resources/ApplicationTitleWithTagline}
    Value    : News

    Path     : HKEY_USERS\.DEFAULT\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.BingWeather_1.0.6.0_x64__8wekyb3d8bbwe%5Cresources.pri\1d861e9fdbc0f2\a37dfe62
    Property : @{C:\Program Files\WindowsApps\Microsoft.BingWeather_1.0.6.0_x64__8wekyb3d8bbwe\resources.pri? ms-resource:///resources/ApplicationTitleWithBranding}
    Value    : MSN W...

PARAMETER: -RootKey "HKEY_LOCAL_MACHINE"
    Enter the root registry key where your search will begin.

PARAMETER: -SearchPath "SOFTWARE\ReplaceMe"
    Specify the subpath within the selected root key where the registry search should start. Exclude the root key from this path.

PARAMETER: -Search "ReplaceMe"
    Enter the text that must be present in the registry path, property, or value for it to be considered a match in the search results.

PARAMETER: -Depth "3"
    Set the maximum number of levels deep to search within the registry from the specified path. Increasing this value can significantly impact script performance due to deeper searches.

PARAMETER: -CustomField "ReplaceMeWithAnyMultilineCustomField"
    Specifies the name of an optional multiline custom field where results can be sent. Leave blank if not applicable.

PARAMETER: -Path
    If selected, the search will include registry key paths that contain the specified 'Search For' text as part of the search results.

PARAMETER: -Property
    If selected, the search will include registry key properties (names) that contain the specified 'Search For' text as part of the search results.

PARAMETER: -Value
    If selected, the search will include registry key values that contain the specified 'Search For' text as part of the search results.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$RootKey = "HKEY_LOCAL_MACHINE",
    [Parameter()]
    [String]$SearchPath,
    [Parameter()]
    [String]$Search,
    [Parameter()]
    [int]$Depth = 4,
    [Parameter()]
    [String]$CustomField,
    [Parameter()]
    [Switch]$Path = [System.Convert]::ToBoolean($env:searchForMatchingKeyPaths),
    [Parameter()]
    [Switch]$Property = [System.Convert]::ToBoolean($env:searchForMatchingKeyProperties),
    [Parameter()]
    [Switch]$Value = [System.Convert]::ToBoolean($env:searchForMatchingKeyValues)
)

begin {
    if ($env:rootKeyToSearch -and $env:rootKeyToSearch -notlike "null") { $RootKey = $env:rootKeyToSearch }
    if ($env:searchPath -and $env:searchPath -notlike "null") { $SearchPath = $env:searchPath }
    if ($env:searchFor -and $env:searchFor -notlike "null") { $Search = $env:searchFor }
    if ($env:searchDepth -and $env:searchDepth -notlike "null") { $Depth = $env:searchDepth }
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }

    # Error out if we're not told to match the search string with anything.
    if (-not $Path -and -not $Property -and -not $Value) {
        Write-Host "[Error] You must select the option to either match based on the key path, the property name, or the value."
        exit 1
    }

    # If no search string is given error out.
    if ( -not $Search) {
        Write-Host "[Error] You must specify something to search for."
        exit 1
    }

    # If we're not given a search path error out.
    if ( -not $SearchPath) {
        Write-Host "[Error] You must specify a path to search, e.g., 'SOFTWARE\Microsoft'."
        exit 1
    }

    # If no root key is given error out.
    if ( -not $RootKey) {
        Write-Host "[Error] You must specify a root key to search in."
        exit 1
    }

    # Valid root keys for the search.
    $ValidRootKeys = "HKEY_LOCAL_MACHINE", "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG", "HKEY_CURRENT_USER"
    if ($ValidRootKeys -notcontains $RootKey) {
        Write-Host "[Error] You must specify a valid root key! Valid root keys are 'HKEY_LOCAL_MACHINE', 'HKEY_CLASSES_ROOT', 'HKEY_USERS', 'HKEY_CURRENT_CONFIG', and 'HKEY_CURRENT_USER'."
        exit 1
    }

    # Remove accidental backslashes.
    if ($SearchPath -match "^\\") {
        $SearchPath = $SearchPath -replace "^\\"
        Write-Warning "An extra backslash was detected; changing the search path to $SearchPath."
    }

    # If the search path is not valid error out.
    if (-not (Test-Path "Registry::$RootKey\$SearchPath")) {
        Write-Host "[Error] Search path $RootKey\$SearchPath does not exist! Please specify an existing registry path to start the search from!"
        exit 1
    }

    # Depth must be greater than 0.
    if ( -not $Depth -or $Depth -lt 1) {
        Write-Host "[Error] Depth must be greater than 0."
        exit 1
    }

    # If depth is 5 or higher, output a warning.
    if ($Depth -ge 5) {
        Write-Warning "Executing deep registry searches may significantly extend script runtime."
    }

    # If HKEY_USERS is used we'll need a list of User Profiles and where to mount the corresponding registry hives.
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
    
        # User account SID's follow a particular pattern depending on if they're Azure AD, a Domain account, or a local "workgroup" account.
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # We'll need the NTUSER.DAT file to load each user's registry hive. So we grab it if their account SID matches the above pattern. 
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } | 
                Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                @{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                @{Name = "Path"; Expression = { $_.ProfileImagePath } }
        }
    
        # There are some situations where grabbing the .Default user's info is needed.
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
    
        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # This function makes it easier to set Custom Fields.
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
    
        $Characters = $Value | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 10000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than 10,000 characters.")
        }
        
        # If we're requested to set the field value for a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # This is a list of valid fields that can be set. If no type is given, it will be assumed that the input doesn't need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # The field below requires additional information to be set
        $NeedsOptions = "Dropdown"
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # If an error is received it will have an exception property, the function will exit with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
        
        # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the  Date-Time to be in Unix Epoch time so we'll convert it here.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
        
                if (-not $Selection) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown")
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
            $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1
        }
        
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    $ExitCode = 0
}
process {
    # Test for local administrator rights.
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Load unloaded profiles if asked to search in HKEY_USERS.
    if ($RootKey -eq "HKEY_USERS") {
        $UserProfiles = Get-UserHives -Type "All"
        $ProfileWasLoaded = New-Object System.Collections.Generic.List[string]

        # Loop through each profile on the machine.
        Foreach ($UserProfile in $UserProfiles) {
            # Load user's NTUSER.DAT if it's not already loaded.
            If ((Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
                $ProfileWasLoaded.Add("$($UserProfile.SID)")
            }
        }
    }

    # Retrieve all the registry keys with the given parameters.
    $RegistryKeys = Get-ChildItem -Path "Registry::$RootKey\$SearchPath" -Depth $Depth -Recurse -ErrorAction SilentlyContinue -ErrorVariable RegistryErrors

    if ($RootKey -eq "HKEY_USERS") {
        # Unload all hives that were loaded for this script.
        ForEach ($UserHive in $ProfileWasLoaded) {
            If ($ProfileWasLoaded -eq $false) {
                [gc]::Collect()
                Start-Sleep 1
                Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserHive)" -Wait -WindowStyle Hidden | Out-Null
            }
        }
    }

    # Initialize generic lists.
    $AllKeys = New-Object System.Collections.Generic.List[object]
    $MatchingKeys = New-Object System.Collections.Generic.List[object]
    $CustomFieldValue = New-Object System.Collections.Generic.List[string]

    # For each registry key, retrieve all properties and values if available.
    $RegistryKeys | ForEach-Object {
        $RegistryPath = $_.PSPATH -replace "Microsoft.PowerShell.Core\\Registry::"
        try {
            $ErrorActionPreference = "Stop"
            $Properties = New-Object System.Collections.Generic.List[string]
            $_.GetValueNames() | ForEach-Object { $Properties.Add($_) }
            $Properties.Add("(default)")
        }
        catch {
            $Properties = $Null
        }
        $ErrorActionPreference = "Continue"

        if (-not $Properties) {
            $AllKeys.Add(
                [PSCustomObject]@{
                    Path     = $RegistryPath
                    Property = "N/A"
                    Value    = "N/A"
                }
            )
            return
        }

        foreach ($PropertyName in $Properties) {
            $ErrorActionPreference = "SilentlyContinue"
            $RegValue = ($_ | Get-ItemProperty -ErrorVariable RegistryErrors).$PropertyName
            $ErrorActionPreference = "Continue"
            $AllKeys.Add(
                [PSCustomObject]@{
                    Path     = $RegistryPath
                    Property = $PropertyName
                    Value    = $RegValue
                }
            )
        }
    }

    $MatchingValues = $False
    $MatchingProperties = $False
    $MatchingPaths = $False

    # Match the registry keys based on the key path, property, or value. Add the results to the MatchingKeys generic list.
    if ($Value) {
        $AllKeys | Where-Object { $_.Value -match [regex]::Escape($Search) } | ForEach-Object {
            $MatchingValues = $True 
            $MatchingKeys.Add($_) 
        }
    }

    if ($Property) {
        $AllKeys | Where-Object { $_.Property -match [regex]::Escape($Search) } | ForEach-Object {
            $MatchingProperties = $True 
            $MatchingKeys.Add($_) 
        }
    }

    if ($Path) {
        $AllKeys | Where-Object { $_.Path -match $([regex]::Escape($Search)) } | ForEach-Object {
            $MatchingPaths = $True 
            $MatchingKeys.Add($_) 
        }
    }

    if (-not $MatchingPaths -and -not $MatchingProperties -and -not $MatchingValues) {
        $CustomFieldValue.Add("No matching registry keys found!")
        Write-Host "No matching registry keys found!"
    }

    # If we have any matches, output to Write-Warning.
    if ($MatchingPaths) {
        Write-Warning -Message "Matching registry path names found!"
        $CustomFieldValue.Add("WARNING: Matching registry path names found!")
    }

    if ($MatchingProperties) {
        Write-Warning -Message "Matching registry properties found!"
        $CustomFieldValue.Add("WARNING: Matching registry properties found!")
    }

    if ($MatchingValues) {
        Write-Warning -Message "Matching registry key values found!"
        $CustomFieldValue.Add("WARNING: Matching registry key values found!")
    }
    
    if ($MatchingKeys) {
        $KeysToReport = $MatchingKeys | Format-List Path, Property, Value | Out-String
        $CustomFieldValue.Add($KeysToReport)
    }

    # For each error, output them at the bottom. Most of these errors are not going to be relevant.
    $RegistryErrors | ForEach-Object {
        $CustomFieldValue.Add("[Error] $($_.TargetObject)")
        $CustomFieldValue.Add("[Error] $($_.Exception.Message)")
    }

    # Save the output to a custom field if a field name is provided.
    if ($CustomField) {
        try {
            Write-Host "Attempting to set Custom Field '$CustomField'."
            Set-NinjaProperty -Name $CustomField -Value (($CustomFieldValue | Out-String) -replace "`n")
            Write-Host "Successfully set Custom Field '$CustomField'!"
        }
        catch {
            if ($_.Exception.Message) {
                Write-Host "[Error] $($_.Exception.Message)"
            }
        
            if ($_.Message) {
                Write-Host "[Error] $($_.Message)"
            }
            $ExitCode = 1
        }
    }

    # Activity Log output
    if($MatchingKeys){
        $KeysToReport | Write-Host
    }

    $RegistryErrors | ForEach-Object {
        Write-Host "[Error] $($_.TargetObject)"
        Write-Host "[Error] $($_.Exception.Message)"
    }

    exit $ExitCode
}
end {
    
    
    
}
