# Alert if a specified file or folder is found in a directory or subdirectory you specify.
#Requires -Version 5.1

<#
.SYNOPSIS
    Alert if a specified file or folder is found in a directory or subdirectory you specify.
.DESCRIPTION
    Alert if a specified file or folder is found in a directory or subdirectory you specify.

.EXAMPLE
    -SearchPath "C:" -FileOrFolder "autounattend"

    WARNING: Backslash missing from the search path. Changing it to C:\.
    [Alert] File Found.
    C:\Users\Administrator\Desktop\ExampleFolder\Test Folder 1\autounattend.xml
    C:\Users\Administrator\Desktop\ExampleFolder\Test Folder 2\autounattend.xml
    C:\Users\Administrator\Desktop\ExampleFolder\TestFolder1\Test Folder 1\autounattend.xml
    C:\Users\Administrator\Desktop\ExampleFolder\TestFolder1\Test Folder 2\autounattend.xml
    C:\Users\Administrator\Desktop\ExampleFolder\TestFolder2\Test Folder 1\TestFolder1\autounattend.xml
    Attempting to set Custom Field 'multiline'.
    Successfully set Custom Field 'multiline'!

PARAMETER: -SeachPath "C:\ReplaceMeWithAvalidPath"
    Enter the starting directories for the search, separated by commas. This will include all subdirectories as well.

PARAMETER: -FileOrFolder "ReplaceMeWithNameToSearchFor"
    Specify the full or partial name of a file or folder to find. E.g., 'config' or '.exe'.

PARAMETER: -SearchType "Files and Folders"
    Limit the search to either files, folders, or both.

PARAMETER: -Timeout "30"
    Maximum search time in minutes, halts search if exceeded.

PARAMETER: -CustomField "ReplaceMeWithNameOfMultilineCustomField"
    Optional multiline field to record search results. Leave blank if unused.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$SearchPath = "C:\Windows,C:\Program Files",
    [Parameter()]
    [String]$FileOrFolder,
    [Parameter()]
    [String]$SearchType = "Files and Folders",
    [Parameter()]
    [Int]$Timeout = 30,
    [Parameter()]
    [String]$CustomField
)

begin {
    # Set parameters using dynamic script variables.
    if ($env:searchPath -and $env:searchPath -notlike "null") { $SearchPath = $env:searchPath }
    if ($env:fileNameOrFolderNameToSearchFor -and $env:fileNameOrFolderNameToSearchFor -notlike "null") { $FileOrFolder = $env:fileNameOrFolderNameToSearchFor }
    if ($env:searchType -and $env:searchType -notlike "null") { $SearchType = $env:searchType }
    if ($env:timeoutInMinutes -and $env:timeoutInMinutes -notlike "null") { $Timeout = $env:timeoutInMinutes }
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }

    # Error out if no search path was given.
    if (-not $SearchPath) {
        Write-Host "[Error] No search path given!"
        exit 1
    }

    # If given a comma-separated list, split the paths.
    $PathsToSearch = New-Object System.Collections.Generic.List[String]
    if ($SearchPath -match ",") {
        $SearchPath -split "," | ForEach-Object { $PathsToSearch.Add($_.Trim()) }
    }
    else {
        $PathsToSearch.Add($SearchPath)
    }

    # Initialize a generic list for paths to remove or replace.
    $ReplacementPaths = New-Object System.Collections.Generic.List[Object]
    $PathsToRemove = New-Object System.Collections.Generic.List[String]

    # If given a drive without the backslash add it in.
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

    # Apply replacements.
    $ReplacementPaths | ForEach-Object {
        $PathsToSearch[$_.index] = $_.NewPath 
    }

    # Check if the search path is valid.
    $PathsToSearch | ForEach-Object {
        if (-not (Test-Path $_)) {
            Write-Host -Object "[Error] $_ does not exist!"
            $PathsToRemove.Add($_)
            $ExitCode = 1
        }
    }

    # Remove Paths that do not exist.
    $PathsToRemove | ForEach-Object {
        $PathsToSearch.Remove($_) | Out-Null
    }

    # Error out if no valid paths to search.
    if ($($PathsToSearch).Count -eq 0) {
        Write-Host "[Error] No valid paths to search!"
        exit 1
    }

    # If we're not given a file or folder error out.
    if (-not $FileOrFolder) {
        Write-Host -Object "[Error] No file or folder given to search for!"
        exit 1
    }

    # Timeout must be within a given range in minutes.
    if ($Timeout -lt 1 -or $Timeout -gt 120) {
        Write-Host -Object "[Error] Timeout is greater than 120 minutes or less than 1 minute."
        exit 1
    }

    # Scope the search to either files only or folders only.
    $ValidSearchTypes = "Files and Folders", "Files Only", "Folders Only"
    if ($ValidSearchTypes -notcontains $SearchType) {
        Write-Host -Object "[Error] Invalid search type."
        exit 1
    }

    # Test for local administrator rights.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Handy function to set a custom field.
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
    # [String]$DocumentName # Removed NinjaOne dependency
    # ) # Removed NinjaOne dependency
    
    # $Characters = $Value | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    # if ($Characters -ge 10000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than 10,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # If we're requested to set the field value for a Ninja document we'll specify it here. # Removed NinjaOne dependency
    # $DocumentationParams = @{} # Removed NinjaOne dependency
    # if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName } # Removed NinjaOne dependency
        
    # # This is a list of valid fields that can be set. If no type is given, it will be assumed that the input doesn't need to be changed. # Removed NinjaOne dependency
    # $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG" # Removed NinjaOne dependency
    # if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" } # Removed NinjaOne dependency
        
    # # The field below requires additional information to be set # Removed NinjaOne dependency
    # $NeedsOptions = "Dropdown" # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong. # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # If an error is received it will have an exception property, the function will exit with that error information. # Removed NinjaOne dependency
    # if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions } # Removed NinjaOne dependency
        
    # # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports. # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry. # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Ninjarmm-cli expects the  Date-Time to be in Unix Epoch time so we'll convert it here. # Removed NinjaOne dependency
    # $Date = (Get-Date $Value).ToUniversalTime() # Removed NinjaOne dependency
    # $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date # Removed NinjaOne dependency
    # $NinjaValue = $TimeSpan.TotalSeconds # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Dropdown" { # Removed NinjaOne dependency
    # # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid. # Removed NinjaOne dependency
    # $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name" # Removed NinjaOne dependency
    # $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID # Removed NinjaOne dependency
        
    # if (-not $Selection) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # $NinjaValue = $Selection # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # default { # Removed NinjaOne dependency
    # # All the other types shouldn't require additional work on the input. # Removed NinjaOne dependency
    # $NinjaValue = $Value # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # We'll need to set the field differently depending on if its a field in a Ninja Document or not. # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    $ExitCode = 0
}
process {
    # Error out if local administrator rights are not present.
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Initialize generic lists.
    $SearchJobs = New-Object System.Collections.Generic.List[object]
    $CustomFieldValue = New-Object System.Collections.Generic.List[string]

    # For each given path to search, create a PowerShell job with the provided parameters.
    $PathsToSearch | ForEach-Object {
        $SearchJobs.Add(
            (
                Start-Job -ScriptBlock {
                    param($SearchPath, $FileOrFolder, $SearchType)
                    # We're going to wildcard search either files or folders depending on the parameters given.
                    switch ($SearchType) {
                        "Files and Folders" {
                            Get-ChildItem -Path $SearchPath -Filter "*$FileOrFolder*" -Recurse | Select-Object -Property FullName, Attributes | ConvertTo-Csv
                        }
                        "Folders Only" {
                            Get-ChildItem -Path $SearchPath -Filter "*$FileOrFolder*" -Recurse -Directory | Select-Object -Property FullName, Attributes | ConvertTo-Csv
                        }
                        "Files Only" { 
                            Get-ChildItem -Path $SearchPath -Filter "*$FileOrFolder*" -Recurse -File | Select-Object FullName, Attributes | ConvertTo-Csv
                        }
                    }
                } -ArgumentList $_, $FileOrFolder, $SearchType
            )
        )
    }

    # Convert timeout to seconds as Wait-Job requires seconds.
    $TimeoutInSeconds = $Timeout * 60
    $StartTime = Get-Date

    # Wait for all jobs to complete or timeout.
    foreach ($SearchJob in $SearchJobs) {
        # Calculate the remaining time.
        $TimeElapsed = (Get-Date) - $StartTime
        $RemainingTime = $TimeoutInSeconds - $TimeElapsed.TotalSeconds
    
        # If there is no remaining time, break the loop.
        if ($RemainingTime -le 0) {
            break
        }
    
        # Wait for the current job with the remaining time as the timeout.
        $SearchJob | Wait-Job -Timeout $RemainingTime | Out-Null
    }

    # Output a warning if the job fails to complete.
    $IncompleteJobs = $SearchJobs | Get-Job | Where-Object { $_.State -eq "Running" }
    if ($IncompleteJobs) {
        Write-Host "[Error] The timeout period of $Timeout minutes has been reached, but not all files or directories have been searched!"
        $CustomFieldValue.Add("[Error] The timeout period of $Timeout minutes has been reached, but not all files or directories have been searched!")
        $ExitCode = 1
    }

    # Our PowerShell Job outputs in CSV format; we'll convert it here.
    $MatchingItems = $SearchJobs | ForEach-Object {
        $_ | Get-Job | Receive-Job -ErrorAction SilentlyContinue -ErrorVariable JobErrors | ConvertFrom-Csv
    }

    # Identify whether or not we have a match for a file or folder here.
    $FileMatch = $MatchingItems | Where-Object { $_.Attributes -ne "Directory" }
    $FolderMatch = $MatchingItems | Where-Object { $_.Attributes -eq "Directory" }

    # If we have a match for a file we'll output that here.
    if ($FileMatch) { 
        Write-Host -Object "[Alert] File Found."
        $CustomFieldValue.Add("[Alert] File Found.")
    }

    # If we have a match for a folder we'll output that here.
    if ($FolderMatch) { 
        Write-Host -Object "[Alert] Folder Found." 
        $CustomFieldValue.Add("[Alert] Folder Found.")
    }

    # If we have no matches we'll output that here.
    if (-not $FileMatch -and -not $FolderMatch) {
        Write-Host -Object "Unable to find $FileOrFolder."
        $CustomFieldValue.Add("Unable to find $FileOrFolder.")
    }

    # For each matching file we'll output their full path.
    $MatchingItems | ForEach-Object { 
        Write-Host "$($_.FullName)"
        $CustomFieldValue.Add("$($_.FullName)") 
    }

    # Output any failures or errors received.
    $FailedJobs = $SearchJobs | Get-Job | Where-Object { $_.State -ne "Completed" -and $_.State -ne "Running" }
    if ($FailedJobs -or $JobErrors) {
        Write-Host ""
        Write-Host "[Error] Failed to search certain files or directories due to an error."

        $CustomFieldValue.Add("")
        $CustomFieldValue.Add("[Error] Failed to search certain files or directories due to an error.")
        if ($JobErrors) {
            Write-Host ""
            $CustomFieldValue.Add("")

            $JobErrors | ForEach-Object { 
                Write-Host "[Error] $($_.Exception.Message)" 
                $CustomFieldValue.Add("[Error] $($_.Exception.Message)")
            }
        }
        $ExitCode = 1
    }

    $SearchJobs | Get-Job | Remove-Job -Force

    # # Attempt to set the custom field using the Set-NinjaProperty function, if provided. # Removed NinjaOne dependency
    if ($CustomField) {
        try {
            Write-Host "Attempting to set Custom Field '$CustomField'."
    # Set-NinjaProperty -Name $CustomField -Value ($CustomFieldValue | Out-String) # Removed NinjaOne dependency
            Write-Host "Successfully set Custom Field '$CustomField'!"
        }
        catch {
            if (-not $_.Exception.Message) {
                Write-Host "[Error] $($_.Message)"
            }
            else {
                Write-Host "[Error] $($_.Exception.Message)"
            }
            $ExitCode = 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}
