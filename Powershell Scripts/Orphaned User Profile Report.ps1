# Looks for user profile folders that do not have an associated user account.
#Requires -Version 5.1

<#
.SYNOPSIS
    Looks for user profile folders that do not have an associated user account.
.DESCRIPTION
    Looks for user profile folders that do not have an associated user account.
.EXAMPLE
    (No Parameters)
    
    [Alert] Orphaned profiles found!

    Username Size      Path             SID                                           
    -------- ----      ----             ---                                           
    UNKNOWN  554.97 MB C:\Users\tuser1  S-1-5-21-1255570301-2732419320-3119746845-1104
    UNKNOWN  86.74 MB  C:\Users\tuser22 S-1-5-21-3797121902-2219393589-2867574441-1001


PARAMETER: -CustomField "ReplaceMeWithTheNameOfaWYSIWYGcustomField"
    Specify the name of an optional WYSIWYG Custom Field to save the results in.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String[]]$DirectoriesToIgnore = ("All Users", "Default", "Default User", "Public"),
    [Parameter()]
    [String]$CustomField
)

begin {
    # Set parameters using dynamic script variables.
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") {
        $CustomField = $env:wysiwygCustomFieldName
    }

    # Function to convert a size in bytes to a more human-readable format
    function Get-FriendlySize {
        param($Bytes)
        # Array of size units
        $Sizes = 'Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
        # Loop to find the appropriate size unit
        for ($i = 0; ($Bytes -ge 1kb) -and ($i -lt $Sizes.Count); $i++) { $Bytes /= 1kb }
        # Number of decimal places to show
        $decimalPlaces = 2
        # If the size is in bytes, no decimal places are needed
        if ($i -eq 0) { $decimalPlaces = 0 }
        # Return the rounded size with the appropriate unit
        if ($Bytes) { "$([System.Math]::Round($Bytes,$decimalPlaces)) $($Sizes[$i])" }else { "0 B" }
    }
    
    # Function to retrieve user profile hives from the registry
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

        # Define patterns to match user SIDs based on the Type parameter
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }

        # Retrieve user profiles from the registry
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } | 
                Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                @{Name = "Username"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                @{Name = "Path"; Expression = { $_.ProfileImagePath } },
                @{Name = "Size"; Expression = { $(Get-ChildItem -Path $_.ProfileImagePath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Sum Length -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Sum -ErrorAction SilentlyContinue) } }
        }

        # Include the default profile if specified
        switch ($IncludeDefault) {
            $True {
                $DefaultProfile = "" | Select-Object Username, SID, UserHive, Path
                $DefaultProfile.Username = "Default"
                $DefaultProfile.SID = "DefaultProfile"
                $DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                $DefaultProfile.Path = "C:\Users\Default"

                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.Username }
            }
        }

        # Iterate over the user profiles to resolve user names from SIDs
        $UserProfiles | ForEach-Object {
            $SidObject = $Null
            $NewUsername = $Null

            # Convert SID to user name
            if ($_.SID) {
                try {
                    $SidObject = New-Object System.Security.Principal.SecurityIdentifier($_.SID)
                    $NewUsername = $SidObject.Translate([System.Security.Principal.NTAccount])
                }
                catch {
                    $NewUsername = $Null
                }
            }

            # Assign the resolved user name or "UNKNOWN" if resolution fails
            if ($NewUsername.Value) {
                $_.Username = $NewUsername.Value
            }
            else {
                $_.Username = "UNKNOWN"
            }
        }

        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.Username }
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
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
            
        # If requested to set the field value for a Ninja document, specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
            
        # This is a list of valid fields that can be set. If no type is specified, assume that the input does not need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
            
        # The field below requires additional information to set.
        $NeedsOptions = "Dropdown"
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                # Redirect error output to the success stream to handle errors more easily if nothing is found or something else goes wrong.
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
            
        # If an error is received with an exception property, exit the function with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
            
        # The types below require values not typically given to be set. The code below will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # Although it's highly likely we were given a value like "True" or a boolean data type, it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, match the given value with a GUID.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli expects the GUID of the option we're trying to select, so match the value we were given with a GUID.
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
            
        # Set the field differently depending on whether it's a field in a Ninja Document or not.
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

    # Function to check if the computer is joined to a domain
    function Test-IsDomainJoined {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

    # Function to check if the computer is a domain controller
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

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsDomainReachable {
        try {
            $searcher = [adsisearcher]"(&(objectCategory=computer)(name=$env:ComputerName))"
            $searcher.FindOne()
        }
        catch {
            Write-Host -Object "[Error] Failed to connect to the domain!"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            $False
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the computer is domain joined, can connect to the domain controller, and is not itself a domain controller
    if ((Test-IsDomainJoined) -and !(Test-IsDomainReachable) -and !(Test-IsDomainController)) {
        Write-Host -Object "[Error] Unable to connect to the domain controller! The domain must be reachable to confirm which profiles are orphaned."
        exit 1
    }

    # Initialize a list to hold user profiles
    $UserProfiles = New-Object System.Collections.Generic.List[Object]
    # Retrieve user hives and add them to the list of user profiles
    try {
        $UserHives = Get-UserHives -Type "All"
    }
    catch {
        Write-Host -Object "[Error] Failed to retrieve the user profile information from the registry!"
        Write-Host -Object "$($_.Exception.Message)"
        exit 1
    }

    $UserHives | ForEach-Object {
        if ((Test-IsDomainJoined) -and $_.Username -notmatch [Regex]::Escape("$env:ComputerName") -and $_.Username -notmatch "AzureAD" -and $_.Username -ne "UNKNOWN") {
            try {
                $ADSIsearch = [adsisearcher]"(objectSid=$($_.SID))"
                if (!($ADSIsearch.FindOne())) {
                    $_.Username = "UNKNOWN"
                }
            }
            catch {
                Write-Host -Object "[Error] Failed to connect to the domain to verify the account with the sid $($_.SID) is active."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }

        try {
            $UserProfiles.Add(
                [PSCustomObject]@{
                    SID          = $_.SID
                    Username     = $_.Username
                    UserHive     = $_.UserHive
                    Path         = $_.Path
                    Size         = $_.Size
                    FriendlySize = (Get-FriendlySize -Bytes $_.Size)
                }
            )
        }
        catch {
            Write-Host -Object "[Error] Failed to add the profile with the SID $($_.SID) to the profile list!"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
    
    # Attempt to retrieve the user profiles directory from the registry (typically C:\Users)
    try {
        $ProfilesDirectory = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop).ProfilesDirectory
    }
    catch {
        Write-Host -Object "[Error] Unable to find the user profiles directory!"
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Attempt to get information about directories in the profiles directory that have not already been identified/found
    try {
        $ProfilesDirectory | Get-ChildItem -Directory -Force -ErrorAction Stop | Where-Object { $DirectoriesToIgnore -notcontains $_.Name -and $UserProfiles.Path -notcontains $_.FullName } | ForEach-Object {
            $FriendlySize = $Null
            $Size = $Null
            $Hive = $Null

            # Check if the NTuser.dat file exists in the profile directory
            if (Test-Path -Path "$($_.FullName)\NTuser.dat" -ErrorAction SilentlyContinue) {
                $Hive = "$($_.FullName)\NTuser.dat"
            }
            else {
                $Hive = "UNKNOWN"
            }

            # Calculate the size of the profile directory
            $Size = $(Get-ChildItem -Path $_.FullName -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Sum Length -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Sum -ErrorAction SilentlyContinue)
            if ($Size) {
                $FriendlySize = Get-FriendlySize -Bytes $Size
            }

            # Add the profile information to the list of user profiles
            $UserProfiles.Add(
                [PSCustomObject]@{
                    SID          = "UNKNOWN"
                    Username     = "UNKNOWN"
                    UserHive     = $Hive
                    Path         = $_.FullName
                    Size         = $Size
                    FriendlySize = $FriendlySize
                }
            )
        }
    }
    catch {
        Write-Host -Object "[Error] Unable to get all of the user profile information for $($_.FullName)!"
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Filter the list to find orphaned profiles (those with "UNKNOWN" as a username)
    $OrphanedProfiles = $UserProfiles | Where-Object { $_.Username -eq "UNKNOWN" }

    # If a custom field is specified, generate an HTML report and set the custom field
    if ($CustomField) {
        $HTMLreport = $UserProfiles | Sort-Object Size -Descending | Select-Object Username, @{Label = "Size"; Expression = { $_.FriendlySize } }, Path, SID | ConvertTo-Html -Fragment

        # Highlight orphaned profiles in the HTML report
        $HTMLreport = $HTMLreport | ForEach-Object {
            $_ -replace '<tr><td>UNKNOWN</td>', '<tr class="danger"><td>UNKNOWN</td>'
        }

        try {
            Write-Host "Attempting to set Custom Field '$CustomField'."
            Set-NinjaProperty -Name $CustomField -Value $HTMLreport
            Write-Host "Successfully set Custom Field '$CustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }

        Write-Host ""
    }
    
    # Display a message about orphaned profiles
    if ($OrphanedProfiles) {
        Write-Host -Object "[Alert] Orphaned profiles found!"
        $OrphanedProfiles | Sort-Object Size -Descending | Format-Table Username, @{Label = "Size"; Expression = { $_.FriendlySize } }, Path, SID | Out-String | Write-Host
    }
    else {
        Write-Host -Object "No orphaned profiles found!"
    }

    exit $ExitCode
}
end {
    
    
    
}
