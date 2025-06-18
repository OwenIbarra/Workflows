# Alerts if a file with the extension and specified hash is found in the given search directory or subdirectories. Warning: Hashing large files may impact performance.
#Requires -Version 5.1

<#
.SYNOPSIS
    Alerts if a file with the extension and specified hash is found in the given search directory or subdirectories. Warning: Hashing large files may impact performance.
.DESCRIPTION
    Alerts if a file with the extension and specified hash is found in the given search directory or subdirectories. Warning: Hashing large files may impact performance.
.EXAMPLE
    -Hash "F55A61A82F4F5943F86565E1FA2CCB4F" -SearchPath "C:" -FileType ".ico" -CustomField "multiline"
    WARNING: Backslash missing from the search path. Changing it to C:\.
    WARNING: File with MD5 hash of F55A61A82F4F5943F86565E1FA2CCB4F found!

    File Name         Path                                                                                    
    ---------         ----                                                                                    
    zoo_ecosystem.ico C:\Users\Administrator\Desktop\Find-FileHash\Test Folder 1\zoo_ecosystem.ico            
    zoo_ecosystem.ico C:\Users\Administrator\Desktop\Find-FileHash\TestFolder1\Test Folder 1\zoo_ecosystem.ico
    zoo_ecosystem.ico C:\Users\Administrator\Desktop\Find-FileHash\TestFolder2\Test Folder 1\zoo_ecosystem.ico

    Attempting to set Custom Field 'multiline'.
    Successfully set Custom Field 'multiline'!

PARAMETER: -Hash "REPLACEMEWITHAVALIDHASH"
    Files with this hash should cause the alert to trigger.

PARAMETER: -Algorithm "MD5"
    Hashing algorithm used for the above hash.

PARAMETER: -SearchPath "C:\ReplaceMeWithAValidSearchPath"
   Specifies one or more starting directories for the search, separated by commas. The search will recursively include all subdirectories from these starting points.

PARAMETER: -Timeout "15"
    Once this timeout is reached, the script will stop searching for files that match your given hash.

PARAMETER: -FileType ".exe"
    Specifies the file extension to filter the search. Only files with this extension will be analyzed for a hash match. Example: '.exe'

PARAMETER: -CustomField "NameOfMultiLineCustomField"
    Specifies the name of an optional multiline custom field where results can be sent. 

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Hash,
    [Parameter()]
    [String]$SearchPath = "C:\Windows",
    [Parameter()]
    [String]$FileType,
    [Parameter()]
    [Int]$Timeout = 15,
    [Parameter()]
    [String]$Algorithm = "MD5",
    [Parameter()]
    [String]$CustomField
)

begin {
    # Set parameters using dynamic script variables.
    if ($env:hash -and $env:hash -notlike "null") { $Hash = $env:hash }
    if ($env:hashType -and $env:hashType -notlike "null") { $Algorithm = $env:hashType }
    if ($env:searchPath -and $env:searchPath -notlike "null") { $SearchPath = $env:searchPath }
    if ($env:timeoutInMinutes -and $env:timeoutInMinutes -notlike "null") { $Timeout = $env:timeoutInMinutes }
    if ($env:fileExtensionToSearchFor -and $env:fileExtensionToSearchFor -notlike "null") { $FileType = $env:fileExtensionToSearchFor }
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }

    # If given a comma-separated list, split the paths.
    $PathsToSearch = New-Object System.Collections.Generic.List[String]
    if ($SearchPath -match ",") {
        $SearchPath -split "," | ForEach-Object { $PathsToSearch.Add($_.Trim()) }
    }
    else {
        $PathsToSearch.Add($SearchPath)
    }

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

    # Apply replacements
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

    $PathsToRemove | ForEach-Object {
        $PathsToSearch.Remove($_) | Out-Null
    }


    # Error out if no valid paths to search.
    if ($PathsToSearch.Count -eq 0) {
        Write-Host "[Error] No valid paths to search!"
        exit 1
    }

    # A file extension is required.
    if (-not $FileType) {
        Write-Host -Object "[Error] File Type is required!"
        exit 1
    }

    # If we were given the extension without the . we'll add it back in
    if ($FileType -notmatch '^\.') {
        $FileType = ".$FileType"
        Write-Warning -Message "Extension missing changing filetype to $FileType."
    }

    # The timeout has to be between 1 and 120
    if ($Timeout -lt 1 -or $Timeout -gt 120) {
        Write-Host "[Error] Invalid timeout given of $Timeout minutes. Please enter a value between 1 and 120."
        exit 1
    }

    # PowerShell 5.1 supports more algorithms than this, however PowerShell 7 does not.
    $ValidAlgorithms = "SHA1", "SHA256", "SHA384", "SHA512", "MD5"
    if ($ValidAlgorithms -notcontains $Algorithm) {
        Write-Host "[Error] Invalid Algorithm selected. Only SHA1, SHA256, SHA384, SHA512 and MD5 are supported."
        exit 1
    }

    # Helper function to make it easier to set custom fields.
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

    # Test for local administrator rights
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    $ExitCode = 0
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # If we're given a file instead of a folder, we'll check if it matches anyways.
    $PathsToSearch | ForEach-Object {
        if (-not (Get-Item $_).PSIsContainer) {
            Write-Warning "The search path you gave is actually a file not a folder. Checking the hash of the file..."
        }
    }
    
    $HashJobs = New-Object System.Collections.Generic.List[object]
    $MatchingFiles = New-Object System.Collections.Generic.List[object]
    $CustomFieldValue = New-Object System.Collections.Generic.List[string]

    # We'll use a PowerShell job so that we can timeout appropriately.
    $PathsToSearch | ForEach-Object {
        $HashJobs.Add(
            (
                Start-Job -ScriptBlock {
                    param($SearchPath, $FileType, $Algorithm, $Hash)
                    $Files = Get-ChildItem -Path $SearchPath -Filter "*$FileType" -File -Recurse
                    $Files | ForEach-Object {
                        $CurrentHash = Get-FileHash -Path $_.FullName -Algorithm $Algorithm
                        if ($CurrentHash.Hash -match $Hash) { $_.FullName }
                    }
                } -ArgumentList $_, $FileType, $Algorithm, $Hash
            )
        )
    }

    $TimeoutInSeconds = $Timeout * 60
    $StartTime = Get-Date

    # Wait for all jobs to complete or timeout
    foreach ($HashJob in $HashJobs) {
        # Calculate the remaining time
        $TimeElapsed = (Get-Date) - $StartTime
        $RemainingTime = $TimeoutInSeconds - $TimeElapsed.TotalSeconds
    
        # If there is no remaining time, break the loop
        if ($RemainingTime -le 0) {
            break
        }
    
        # Wait for the current job with the remaining time as the timeout
        $HashJob | Wait-Job -Timeout $RemainingTime | Out-Null
    }

    # If we failed to complete the job, we'll output a warning.
    $IncompleteJobs = $HashJobs | Get-Job | Where-Object { $_.State -eq "Running" }
    if ($IncompleteJobs) {
        Write-Host "[Error] The timeout period of $Timeout minutes has been reached, but some files still require a hash check!"
        $CustomFieldValue.Add("[Error] The timeout period of $Timeout minutes has been reached, but some files still require a hash check!")
        $ExitCode = 1
    }

    # Receive the data from the job.
    $HashJobs | Receive-Job -ErrorAction SilentlyContinue -ErrorVariable JobErrors | ForEach-Object {
        $MatchingFiles.Add(
            [PSCustomObject]@{
                "File Name" = $(Split-Path $_ -Leaf)
                Path        = $_
            }
        )
    }

    # If we have any matching files, we'll output them here.
    if ($MatchingFiles) {
        Write-Warning -Message "File with $Algorithm hash of $Hash found!"
        $MatchingFiles | Format-Table -AutoSize | Out-String | Write-Host
        $MatchingFiles | Select-Object -ExpandProperty Path | ForEach-Object { $CustomFieldValue.Add($_) }
    }
    else {
        Write-Host -Object "No files found with $Hash."
    }

    # If we received any failures or errors, we'll output that here.
    $FailedJobs = $HashJobs | Get-Job | Where-Object { $_.State -ne "Completed" -and $_.State -ne "Running" }
    if ($FailedJobs -or $JobErrors) {
        Write-Host ""
        Write-Host "[Error] Failed to get the hash of certain files due to an error."
        $CustomFieldValue.Add(" ")
        $CustomFieldValue.Add("[Error] Failed to get the hash of certain files due to an error.")
        if ($JobErrors) {
            Write-Host ""
            $JobErrors | ForEach-Object { Write-Host "[Error] $($_.Exception.Message)" }
            $CustomFieldValue.Add(" ")
            $JobErrors | ForEach-Object { $CustomFieldValue.Add("[Error] $($_.Exception.Message)") }
        }
        $ExitCode = 1
    }

    $HashJobs | Remove-Job -Force

    # If we're given a custom field, we'll attempt to save the results to it.
    if ($CustomField) {
        try {
            Write-Host "Attempting to set Custom Field '$CustomField'."
            Set-NinjaProperty -Name $CustomField -Value ($CustomFieldValue | Out-String)
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
