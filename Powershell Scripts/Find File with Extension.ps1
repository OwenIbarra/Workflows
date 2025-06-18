# Creates a report based on the files found in the directory or subdirectory you specified with your desired extension.
#Requires -Version 5.1

<#
.SYNOPSIS
    Creates a report based on the files found in the directory or subdirectory you specified with your desired extension.
.DESCRIPTION
    Creates a report based on the files found in the directory or subdirectory you specified with your desired extension.
.EXAMPLE
    -Extensions ".exe" -SearchPaths "C:\Users\tuser\Downloads"
    
    Searching C:\Users\tuser\Downloads for files with extension '.exe'...
    No files found with extension .exe!


PARAMETER: -Extensions "exe, .ico"
    A comma-separated list of extensions to search for. You can use the * character as a wildcard.

PARAMETER: -SearchPaths "C:\Replace\Me\With\Valid\Path"
    Enter the starting directories for the search, separated by commas. This will include all subdirectories as well.

PARAMETER: -MultiLineField "ReplaceMeWithNameOfMultilineCustomField"
    Optional multiline field to record search results. Leave blank if unused.

PARAMETER: -WysiwygField "ReplaceMeWithNameOfWYSIWYGCustomField"
    Optional WYSIWYG field to record search results. Leave blank if unused.

PARAMETER: -ScanSystemDrive
    This will set the system drive (usually drive C:\) as the starting point for the search.

PARAMETER: -ScanAllDrives
    This will set all drives (including flash drives) as the starting point for the search.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated checkbox script variables.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Extensions,
    [Parameter()]
    [String]$SearchPaths,
    [Parameter()]
    [String]$MultiLineField,
    [Parameter()]
    [String]$WysiwygField,
    [Parameter()]
    [Switch]$ScanSystemDrive = [System.Convert]::ToBoolean($env:scanSystemDrive),
    [Parameter()]
    [Switch]$ScanAllDrives = [System.Convert]::ToBoolean($env:scanAllDrives)
)
begin {
    # Set parameters using dynamic script variables.
    if ($env:fileExtension -and $env:fileExtension -notlike "null") { $Extensions = $env:fileExtension }
    if ($env:searchPath -and $env:searchPath -notlike "null") { $SearchPaths = $env:searchPath }
    if ($env:multilineCustomField -and $env:multilineCustomField -notlike "null") { $MultiLineField = $env:multilineCustomField }
    if ($env:wysiwygCustomField -and $env:wysiwygCustomField -notlike "null") { $WysiwygField = $env:wysiwygCustomField }

    # Check if no extensions were specified and exit with an error if true.
    if (-not $Extensions) {
        Write-Host -Object "[Error] Missing extension to search for!"
        exit 1
    }

    # Verify that WysiwygField and MultiLineField are not the same, exiting with an error if they are.
    if ($WysiwygField -and $MultiLineField -and ($WysiwygField -eq $MultiLineField)) {
        Write-Host -Object "[Error] Wysiwyg Field and Multiline Field are the same! Custom fields cannot be the same type."
        Write-Host -Object "https://ninjarmm.zendesk.com/hc/en-us/articles/18601842971789-Custom-Fields-by-Type-and-Functionality"
        exit 1
    }

    # Initialize a list to store the extensions to search for.
    $ExtensionsToSearch = New-Object System.Collections.Generic.List[string]
    # Split the extensions if they are comma-separated and trim whitespace.
    if ($Extensions -match ",") {
        $Extensions -split "," | ForEach-Object { $ExtensionsToSearch.Add($_.Trim()) }
    }
    else {
        $ExtensionsToSearch.Add($Extensions.Trim())
    }
    
    # Initialize a list to keep track of extensions that need to be replaced (adding a leading dot if missing).
    $ExtensionsToReplace = New-Object System.Collections.Generic.List[object]
    $ExtensionsToSearch | ForEach-Object {
        if ($_ -notmatch "^\.") {
            $NewExtension = ".$_"

            $ExtensionsToReplace.Add(
                [PSCustomObject]@{
                    Index        = $ExtensionsToSearch.IndexOf("$_")
                    NewExtension = $NewExtension
                }
            )
                
            Write-Warning "Missing . for extension. Changing extension search to '$NewExtension'."
        }
    }

    # Apply the replacements for extensions that were missing a leading dot.
    $ExtensionsToReplace | ForEach-Object {
        $ExtensionsToSearch[$_.index] = $_.NewExtension 
    }

    # Check if no search locations were specified and exit with an error if true.
    if (!$SearchPaths -and !$ScanSystemDrive -and !$ScanAllDrives) {
        Write-Host -Object "[Error] Missing somewhere to search!"
        exit 1
    }

    # If scanning all drives, ignore specific paths and the system drive flag.
    if ($ScanAllDrives) {
        $ScanSystemDrive = $false
        $SearchPaths = $Null
    }

    # Initialize a list for paths to search.
    $PathsToSearch = New-Object System.Collections.Generic.List[string]
    # Split the search paths if they are comma-separated and trim whitespace.
    if ($SearchPaths -match ",") {
        $SearchPaths -split "," | ForEach-Object { $PathsToSearch.Add($_.Trim()) }
    }
    elseif ($SearchPaths) {
        $PathsToSearch.Add($SearchPaths)
    }

    # Add the system drive to the search paths if specified.
    if ($ScanSystemDrive) {
        if ($env:SystemDrive -notmatch '^[A-Z]:\\$' -and $env:SystemDrive -match '^[A-Z]:$') {
            $PathsToSearch.Add("$env:SystemDrive\")
        }
        else {
            $PathsToSearch.Add($env:SystemDrive)
        }
    }

    # Add all filesystem drives to the search paths if scanning all drives.
    if ($ScanAllDrives) {
        Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -and $_.Used } | ForEach-Object {
            if ($_.Root -notmatch '^[A-Z]:\\$' -and $_.Root -match '^[A-Z]:$') {
                $PathsToSearch.Add("$($_.Root)\")
            }
            else {
                $PathsToSearch.Add($_.Root)
            }
        }
    }

    # Initialize a list for paths that need to be corrected (adding a trailing backslash if missing).
    $ReplacementPaths = New-Object System.Collections.Generic.List[Object]

    # Check each path and add a backslash if it's missing.
    $PathsToSearch | ForEach-Object {
        if ($_ -notmatch '^[A-Z]:\\$' -and $_ -match '^[A-Z]:$') {
            $NewPath = "$_\"
            $ReplacementPaths.Add(
                [PSCustomObject]@{
                    Index   = $PathsToSearch.IndexOf("$_")
                    NewPath = $NewPath
                }
            )
                
            Write-Warning "Backslash missing from the search path. Changing it to $NewPath."
        }
    }

    # Apply the path corrections.
    $ReplacementPaths | ForEach-Object {
        $PathsToSearch[$_.index] = $_.NewPath 
    }

    # Function to test if the script is running with elevated permissions.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Handy function to set a custom field.
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
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than or equal to 200,000 characters.")
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
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
    
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    $ExitCode = 0
}
process {
    # Check if the script is running with Administrator privileges. Exit with an error message if not.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Remove illegal extensions
    $ExtensionsToRemove = New-Object System.Collections.Generic.List[String]
    $invalidExtensions = '[<>:"/\\|\x00-\x1F]|\.$'
    $ExtensionsToSearch | ForEach-Object {
        if($_ -match $invalidExtensions){
            Write-Host -Object "[Error] Extension $_ contains one of the following invalid characters or ends in a period. '\:<>`"/|'"
            $ExtensionsToRemove.Add($_)
            $ExitCode = 1
        }
    }

    # Actual removal
    $ExtensionsToRemove | ForEach-Object {
        $ExtensionsToSearch.Remove($_) | Out-Null
    }

    # Exit the script if there are no valid extensions left to search.
    if ($ExtensionsToSearch.Count -eq 0) {
        Write-Host "[Error] No valid extensions to search!"
        exit 1
    }

    # Initialize lists to store information about paths and errors.
    $CustomFieldErrorInfo = New-Object System.Collections.Generic.List[string]

    # These characters are not valid for a search path.
    $invalidSearchPathCharacters = '[<>"/|?\x00-\x1F]'

    # Initialize a generic list to store paths that don't exist and should be removed from the search.
    $PathsToRemove = New-Object System.Collections.Generic.List[String]
    # Check each path in the search list to ensure it exists. Collect paths that don't exist for removal.
    $PathsToSearch | ForEach-Object {
        if($_ -match $invalidSearchPathCharacters){
            Write-Host -Object "[Error] Path $_ contains one of the following invalid characters. '<>`"/|'"
            $PathsToRemove.Add($_)
            $ExitCode = 1
            return
        }

        if (!(Test-Path $_)) {
            Write-Host -Object "[Error] $_ does not exist!"
            $PathsToRemove.Add($_)
            $ExitCode = 1
        }
    }

    # Remove non-existing paths from the search list.
    $PathsToRemove | ForEach-Object {
        $PathsToSearch.Remove($_) | Out-Null
    }

    # Exit the script if there are no valid paths left to search.
    if ($PathsToSearch.Count -eq 0) {
        Write-Host "[Error] No valid paths to search!"
        exit 1
    }

    # Initialize a list to keep track of the search jobs created.
    $SearchJobs = New-Object System.Collections.Generic.List[object]

    # Create and start a PowerShell job for each path and extension combination.
    foreach ($Path in $PathsToSearch) {
        foreach ($Extension in $ExtensionsToSearch) {
            Write-Host "Searching '$Path' for files with extension '$Extension'..."
            $SearchJobs.Add(
                (
                    Start-Job -ScriptBlock {
                        param($Path, $Extension)

                        # Defines a function to convert file sizes to a human-readable format.
                        function Get-FriendlySize {
                            param($Bytes)
                            # Converts Bytes to the highest matching unit
                            $Sizes = 'Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
                            for ($i = 0; ($Bytes -ge 1kb) -and ($i -lt $Sizes.Count); $i++) { $Bytes /= 1kb }
                            $N = 2
                            if ($i -eq 0) { $N = 0 }
                            if ($Bytes) { "$([System.Math]::Round($Bytes,$N)) $($Sizes[$i])" }else { "0 B" }
                        }

                        # Search for files matching the extension and output their details in CSV format.
                        Get-ChildItem -Path $Path -Filter "*$Extension" -Recurse -File -Force | Select-Object Name, FullName, CreationTime, LastWriteTime, Length, @{Name = "Size"; Expression = { Get-FriendlySize $_.Length } } | ConvertTo-Csv
                    } -ArgumentList $Path, $Extension
                )
            )
        }
    }

    # Wait for all search jobs to complete or timeout after 9000 seconds (2.5 hours).
    $SearchJobs | Wait-Job -Timeout 9000 | Out-Null

    # Check for incomplete jobs due to timeout and log an error.
    $IncompleteJobs = $SearchJobs | Get-Job | Where-Object { $_.State -eq "Running" }
    if ($IncompleteJobs) {
        Write-Host "[Error] The timeout period of 2.5 hours has been reached, but not all files or directories have been searched!"
        $CustomFieldErrorInfo.Add("[Error] The timeout period of 2.5 hours has been reached, but not all files or directories have been searched!")
        $ExitCode = 1
    }

    # Collect and process the output from each search job.
    $MatchingItems = $SearchJobs | ForEach-Object {
        $_ | Get-Job | Receive-Job -ErrorAction SilentlyContinue -ErrorVariable JobErrors | ConvertFrom-Csv
    }

    # Clear out duplicate entries
    if ($MatchingItems) {
        $MatchingItems = $MatchingItems | Sort-Object FullName -Unique
    }

    # Check for jobs that failed to complete successfully and log errors.
    $FailedJobs = $SearchJobs | Get-Job | Where-Object { $_.State -ne "Completed" }
    if ($JobErrors -or $FailedJobs) {
        $CustomFieldErrorInfo.Add("[Error] Failed to search certain directories due to an error.")

        if ($JobErrors) {
            $JobErrors | ForEach-Object { 
                $CustomFieldErrorInfo.Add("[Error] $($_.Exception.Message)")
            }
        }
        $ExitCode = 1
    }

    # Process and attempt to set custom field values based on search results and errors, with specific handling for multiline fields.
    # Truncate data if it exceeds character limits for the fields.
    if ($MultiLineField -and $MatchingItems) {
        try {
            Write-Host "Attempting to set Custom Field '$MultiLineField'."

            # Prepare the custom field output.
            $CustomFieldValue = New-Object System.Collections.Generic.List[string]

            # We don't want to edit the matching items array if we have to truncate later so we'll create a duplicate here.
            $CustomFieldList = $MatchingItems | Select-Object -Property Name, FullName, CreationTime, LastWriteTime, Size

            # Format the matching items into a nice list with the relevant properties.
            $CustomFieldValue.Add(($CustomFieldList | Format-List -Property Name, FullName, CreationTime, LastWriteTime, Size | Out-String))
            
            # If any errors were encountered in the search add them to the bottom of the custom field output.
            $CustomFieldErrorInfo | ForEach-Object {
                $CustomFieldValue.Add($_)
            }
            
            # Check that the output complies with the hard character limits.
            $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
            if ($Characters -ge 9500) {
                Write-Warning "10,000 Character Limit has been reached! Trimming output until the character limit is satisified..."
                
                # If it doesn't comply with the limits we'll need to recreate it with some adjustments.
                $i = 0
                do {
                    # Recreate the custom field output starting with a warning that we truncated the output.
                    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
                    $CustomFieldValue.Add("This info has been truncated to accommodate the 10,000 character limit.")
                    
                    # The custom field information is sorted in alphabetical order. We'll flip the array upside down to sort it in reverse alphabetical.
                    [array]::Reverse($CustomFieldList)

                    # Remove the next item which in this case will be the smallest item.
                    $CustomFieldList[$i] = $null
                    $i++

                    # We'll flip the array back to right side up.
                    [array]::Reverse($CustomFieldList)

                    # Add it back to the output.
                    $CustomFieldValue.Add(($CustomFieldList | Format-List -Property Name, FullName, CreationTime, LastWriteTime, Size | Out-String))
                    # Finish with adding any errors we encountered during the search.
                    $CustomFieldErrorInfo | ForEach-Object {
                        $CustomFieldValue.Add($_)
                    }

                    # Check that we now comply with the character limit. If not restart the do loop.
                    $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
                }while ($Characters -ge 9500)
            }

            # Set the custom field.
            Set-NinjaProperty -Name $MultiLineField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$MultiLineField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # Process and attempt to set custom field values based on search results and errors, with specific handling for WYSIWYG fields.
    # Truncate data if it exceeds character limits for the fields.
    if ($WysiwygField -and $MatchingItems) {
        try {
            Write-Host "Attempting to set Custom Field '$WysiwygField'."

            # Prepare the custom field output.
            $CustomFieldValue = New-Object System.Collections.Generic.List[string]

            # Convert the matching items into an html report.
            $htmlTable = $MatchingItems | Select-Object -Property Name, FullName, CreationTime, LastWriteTime, Size | ConvertTo-Html -Fragment
            
            # Add the newly created html into the custom field output.
            $CustomFieldValue.Add($htmlTable)
            # If any errors were encountered in the search add them to the bottom of the custom field output.
            $CustomFieldErrorInfo | ForEach-Object {
                $CustomFieldValue.Add($_)
            }

            # Check that the output complies with the hard character limits.
            $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
            if ($Characters -ge 199500) {
                Write-Warning "200,000 Character Limit has been reached! Trimming output until the character limit is satisified..."
                
                # If it doesn't comply with the limits we'll need to recreate it with some adjustments.
                $i = 0
                do {
                    # Recreate the custom field output starting with a warning that we truncated the output.
                    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
                    $CustomFieldValue.Add("<h1>This info has been truncated to accommodate the 200,000 character limit.</h1>")

                    # The custom field information is sorted in alphabetical order. We'll sort it into reverse alphabetical by flipping the array upside down.
                    [array]::Reverse($htmlTable)
                    # If the next entry is a row we'll delete it.
                    if ($htmlTable[$i] -match '<tr><td>') {
                        $htmlTable[$i] = $null
                    }
                    $i++
                    # We'll flip the array back to right side up.
                    [array]::Reverse($htmlTable)

                    # Add it back to the output.
                    $CustomFieldValue.Add($htmlTable)
                    # Finish with adding any errors we encountered during the search.
                    $CustomFieldErrorInfo | ForEach-Object {
                        $CustomFieldValue.Add($_)
                    }
                    # Check that we now comply with the character limit. If not restart the do loop.
                    $Characters = $CustomFieldValue | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
                }while ($Characters -ge 199500)
            }

            # Set the custom field.
            Set-NinjaProperty -Name $WysiwygField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$WysiwygField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # Output the results of our search into the activity log.
    if (!$MatchingItems) {
        Write-Host "No files found with extension $Extension!"
    }
    else {
        Write-Host "Files found!"
        $MatchingItems | Format-List -Property Name, FullName, CreationTime, LastWriteTime, Size | Out-String | Write-Host
    }

    # If we encountered any errors during the search we'll output them here.
    if ($JobErrors -or $FailedJobs) {
        Write-Host ""
        Write-Host "[Error] Failed to search certain directories due to an error."

        if ($JobErrors) {
            Write-Host ""

            $JobErrors | ForEach-Object {
                Write-Host "[Error] $($_.Exception.Message)" 
            }
        }
        $ExitCode = 1
    }

    # Remove all jobs to clean up.
    $SearchJobs | Get-Job | Remove-Job -Force

    # Exit the script with the appropriate exit code
    exit $ExitCode
}
end {
    
    
     
}
