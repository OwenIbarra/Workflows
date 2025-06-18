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
            Set-NinjaProperty -Name $WYSIWYGCustomField -Value $($HtmlTable -join [System.Environment]::NewLine | Out-String)
            Write-Host "[Info] Successfully set Custom Field '$WYSIWYGCustomField'!"
        }
        catch {
            Write-Host "[Warn] Failed to set Custom Field '$WYSIWYGCustomField'."
        }
    }
}
end {
    
    
    
}
