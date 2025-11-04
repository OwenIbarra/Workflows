# Search for DNS cache record names that match the specified keywords.
#Requires -Version 5.1

<#
.SYNOPSIS
    Search for DNS cache record names that match the specified keywords.
.DESCRIPTION
    Search for DNS cache record names that match the specified keywords.
    The DNS cache is a temporary database maintained by the operating system that contains records of all the recent visits and attempted visits to websites and other internet domains.
    This script searches the DNS cache for record names that match the specified keywords and outputs the results to the Activity Feed.
    Optionally, the results can be saved to a multiline custom field.

PARAMETER: -Keywords "ExampleInput"
    Comma separated list of keywords to search for in the DNS cache.
.EXAMPLE
    -Keywords "arpa"
    ## EXAMPLE OUTPUT WITH Keywords ##
    Entry: 1.80.19.172.in-addr.arpa, Record Name: 1.80.19.172.in-addr.arpa., Record Type: 12, Data: test.mshome.net, TTL: 598963

PARAMETER: -Keywords "arpa,mshome" -MultilineCustomField "ReplaceMeWithAnyMultilineCustomField"
    The name of the multiline custom field to save the results to.
.EXAMPLE
    -Keywords "arpa,mshome" -MultilineCustomField "ReplaceMeWithAnyMultilineCustomField"
    ## EXAMPLE OUTPUT WITH MultilineCustomField ##
    Entry: 1.80.19.172.in-addr.arpa, Record Name: 1.80.19.172.in-addr.arpa., Record Type: 12, Data: test.mshome.net, TTL: 598963
    Entry: test.mshome.net, Record Name: test.mshome.net., Record Type: 1, Data: 172.19.80.1, TTL: 598963

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String[]]$Keywords,
    [Parameter()]
    [String]$MultilineCustomField
)

begin {
    $ExitCode = 0
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
    # # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, the given value will be matched with a GUID. # Removed NinjaOne dependency
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
}
process {
    # Get the keywords to search for in the DNS cache
    $Keywords = if ($env:keywordsToSearch -and $env:keywordsToSearch -ne "null") {
        $env:keywordsToSearch -split "," | ForEach-Object { $_.Trim() }
    }
    else {
        $Keywords -split "," | ForEach-Object { $_.Trim() }
    }
    $Keywords = if ($Keywords -and $Keywords -ne "null") {
        $Keywords | ForEach-Object {
            Write-Host "[Info] Searching for DNS Cache Records Matching: $_"
            Write-Output "*$_*"
        }
    }
    else {
        # Exit if Keywords is empty
        Write-Host "[Error] No Keywords Provided"
        $ExitCode = 1
        exit $ExitCode
    }
    # Get the multiline custom field to save the results to
    $MultilineCustomField = if ($env:multilineCustomField -and $env:multilineCustomField -ne "null") {
        $env:multilineCustomField -split "," | ForEach-Object { $_.Trim() }
    }
    else {
        $MultilineCustomField -split "," | ForEach-Object { $_.Trim() }
    }

    Write-Host ""

    # Get the DNS cache entries that match the keywords
    $DnsCache = Get-DnsClientCache -Name $Keywords | Select-Object -Property Entry, Name, Type, Data, TimeToLive

    if ($null -eq $DnsCache) {
        Write-Host "[Warn] No DNS Cache Entries Found"
    }
    else {
        # Format the DNS cache entries
        $Results = $DnsCache | ForEach-Object {
            "Entry: $($_.Entry), Record Name: $($_.Name), Record Type: $($_.Type), Data: $($_.Data), TTL: $($_.TimeToLive)"
        }
        Write-Host "[Info] DNS Cache Entries Found"
        # Save the results to a multiline custom field if specified
        if ($MultilineCustomField -and $MultilineCustomField -ne "null") {
            Write-Host "[Info] Attempting to set Custom Field '$MultilineCustomField'."
            try {
    # Set-NinjaProperty -Name $MultilineCustomField -Value $($Results | Out-String) # Removed NinjaOne dependency
                Write-Host "[Info] Successfully set Custom Field '$MultilineCustomField'!"
            }
            catch {
                Write-Host "[Warn] Failed to set Custom Field '$MultilineCustomField'."
                $Results | Out-String | Write-Host
            }
        }
        else {
            # Output the results to the Activity Feed
            $Results | Out-String | Write-Host
        }
    }
    exit $ExitCode
}
end {
    
    
    
}
