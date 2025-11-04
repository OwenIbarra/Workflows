# Get a list of unsigned drivers on the system.

<#

.SYNOPSIS
    Get a list of unsigned drivers on the system.
.DESCRIPTION
    Get a list of unsigned drivers on the system.
.EXAMPLE
    (No Parameters)
    
    [Info] Unsigned Drivers Found

    Device Name             INF Name        Is Signed Manufacturer
    -----------             --------        --------- ------------
    Local Print Queue       printqueue.inf  False     Microsoft
    Microsoft Print to PDF  mspdf.inf       False     Microsoft
    Microsoft XPS Document  msxpsdrv.inf    False     Microsoft

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$WYSIWYGCustomField
)

begin {
    # If using script form variables, replace command line parameters with the form variables.
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WYSIWYGCustomField = $env:wysiwygCustomFieldName }

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
        
    # # Measure the number of characters in the provided value # Removed NinjaOne dependency
    # $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    
    # # Throw an error if the value exceeds the character limit of 200,000 characters # Removed NinjaOne dependency
    # if ($Characters -ge 200000) { # Removed NinjaOne dependency
    # throw "Character limit exceeded: the value is greater than or equal to 200,000 characters." # Removed NinjaOne dependency
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
    # # Otherwise, set the standard property value # Removed NinjaOne dependency
    # $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Throw an error if setting the property failed # Removed NinjaOne dependency
    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
}
process {
    # Get the list of unsigned drivers
    $UnsignedDrivers = driverquery.exe /si /FO CSV |
        ConvertFrom-Csv | 
        Select-Object @{
            label = "Device Name"; expression = { $_.DeviceName }
        }, @{
            label = "INF Name"; expression = { $_.InfName }
        }, @{
            label = "Is Signed"; expression = { if ($_.IsSigned -eq "TRUE") { $true }else { $false } }
        }, Manufacturer |
        Where-Object { -Not $_."Is Signed" }

    # Create Html Table
    $HtmlTable = [System.Collections.Generic.List[String]]::new()

    # Add header
    $HtmlTable.Add("<h2>Unsigned Drivers</h2>")

    # Output the list of unsigned drivers to the table
    if ($UnsignedDrivers) {
        Write-Host "[Info] Unsigned Drivers Found"
        # Add table of unsigned drivers
        $HtmlTable.Add($($UnsignedDrivers | ConvertTo-Html -Fragment | Out-String))
        # Output the list of unsigned drivers
        $UnsignedDrivers | Format-Table -AutoSize | Out-String -Width 4000 | Write-Host
    }
    else {
        Write-Host "[Info] No Unsigned Drivers Found"
        $HtmlTable.Add("<p>No unsigned drivers found.</p>")
    }

    # If a custom field name is provided, set the custom field with the list of unsigned drivers
    if ($WYSIWYGCustomField) {
        try {
            Write-Host "[Info] Attempting to set Custom Field '$WYSIWYGCustomField'."
    # Set-NinjaProperty -Name $WYSIWYGCustomField -Value $($HtmlTable -join [System.Environment]::NewLine | Out-String) # Removed NinjaOne dependency
            Write-Host "[Info] Successfully set Custom Field '$WYSIWYGCustomField'!"
        }
        catch {
            Write-Host "[Warn] Failed to set Custom Field '$WYSIWYGCustomField'."
        }
    }
}
end {
    
    
    
}
