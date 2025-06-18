# Reports on the current volumes on the system. All volumes that are not the System Drive are considered data volumes. Raises an alert if one or more volumes have less than a specified percentage or data size.
#Requires -Version 2.0

<#
.SYNOPSIS
    Reports on the current volumes on the system. All volumes that are not the 'System Drive' are considered data volumes. Raises an alert if one or more volumes have less than a specified percentage or data size.
.DESCRIPTION
    Reports on the current volumes on the system. All volumes that are not the 'System Drive' are considered data volumes. Raises an alert if one or more volumes have less than a specified percentage or data size.
.EXAMPLE
    -SystemVolumeMinFreePercent "99%" -SystemVolumeMinFreeSize "100TB" -DataVolumeMinFreePercent "99%" -DataVolumeMinFreeSize "100TB" 
    -ExcludeDataVolumesFromAlert "WINRETOOLS, ESP, DELLSUPPORT, Windows RE Tools, SYSTEM, System Reserved"

    Retrieving the system volume 'C:'.
    Retrieving all data volumes.

    Converting the minimum free space percentage '99%' required for system volumes into bytes.
    Converting the minimum free space required '100TB' for system volumes into bytes.
    Converting the minimum free space percentage '99%' required into bytes for each data volume.
    Converting the minimum free space required '100TB' for data volumes into bytes.

    [Alert] The system volume exceeds the 'Minimum Percent Free' limit of '99%'.
    [Alert] The system volume exceeds the 'Minimum Free Size' limit of '100TB'.

    ### System Volume ###
    Name DriveLetter FileSystemType FreeSpace Total    PercentageFree
    ---- ----------- -------------- --------- -----    --------------
         C:          NTFS           115.26 GB 126.9 GB 90.83%

    ### Data Volumes ###
    Name           : System Reserved
    DriveLetter    : 
    FileSystemType : NTFS
    Path           : \\?\Volume{af2c6d55-e8c1-11ef-95b1-806e6f6e6963}\
    FreeSpace      : 71.87 MB
    Total          : 100 MB
    PercentageFree : 71.87%

.PARAMETER -SystemVolumeMinFreePercent "10%"
    Specifies the minimum percentage of free space that must remain available on the system volume to avoid triggering an alert.
    For example, if set to 10, an alert will be raised if the system volume has less than 10% free space.

.PARAMETER -SystemVolumeMinFreeSize "1TB"
    Specifies the minimum amount of free space that must remain available on the system volume to avoid triggering an alert.
    If no units are specified, gigabytes will be used.
    For example, if set to 10, an alert will be raised if the system volume has less than 10GB of free space.

.PARAMETER -DataVolumeMinFreePercent "10%"
    Specifies the minimum percentage of free space that must remain available on each data volume to avoid triggering an alert.
    For example, if set to 10, an alert will be raised if a data volume has less than 10% free space.

.PARAMETER -DataVolumeMinFreeSize "1TB"
    Specifies the minimum amount of free space that must remain available on each volume to avoid triggering an alert.
    If no units are specified, gigabytes will be used.
    For example, if set to 10, an alert will be raised if a data volume has less than 10GB of free space.

.PARAMETER -ExcludeDataVolumesFromAlert "WINRETOOLS, ESP, DELLSUPPORT, Windows RE Tools, SYSTEM, System Reserved"
    Allows you to specify a comma-separated list of data volumes you would like to exclude from the alert.
    You can specify either the volume label, path, or drive letter.

.PARAMETER -AlertOnlyForDataVolumes "E:\"
    If you would only like an alert for specific volume(s), specify the volume(s) you would like the alert to trigger for.
    You can specify either the volume label, path, or drive letter.

.PARAMETER -MultilineCustomField "ReplaceMeWithAnyMultilineCustomField"
    Stores a multiline report on the current volumes on the system.

.PARAMETER -WYSIWYGCustomField "ReplaceMeWithAnyWYSIWYGCustomField"
    Stores a WYSIWYG report on the current volumes on the system.

.PARAMETER -SystemVolumeMinFreePercentCustomField "ReplaceMeWithAnyTextCustomField"
    Optionally retrieves the 'SystemVolumeMinFreePercent' value from a custom field you specify if no value is currently set.

.PARAMETER -SystemVolumeMinFreeSizeCustomField "ReplaceMeWithAnyTextCustomField"
    Optionally retrieves the 'SystemVolumeMinFreeSize' value from a custom field you specify if no value is currently set.

.PARAMETER -DataVolumeMinFreePercentCustomField "ReplaceMeWithAnyTextCustomField"
    Optionally retrieves the 'DataVolumeMinFreePercent' value from a custom field you specify if no value is currently set.

.PARAMETER -DataVolumeMinFreeSizeCustomField "ReplaceMeWithAnyTextCustomField"
    Optionally retrieves the 'DataVolumeMinFreeSize' value from a custom field you specify if no value is currently set.

.PARAMETER -ExcludeDataVolumeCustomField "ReplaceMeWithAnyTextCustomField"
    Optionally retrieves the 'ExcludeDataVolumesFromAlert' value from a custom field you specify if no value is currently set.

.PARAMETER -AlertOnlyCustomField "ReplaceMeWithAnyTextCustomField"
    Optionally retrieves the 'AlertOnlyForDataVolumes' value from a custom field you specify if no value is currently set.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Improved parameter validation, added the ability to save to custom fields, enhanced reporting to include all volumes 
    (not just those triggering an alert), switched from drives to volumes, introduced an include option, added unit conversion, and 
    simplified exclude options.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$SystemVolumeMinFreePercent,
    [Parameter()]
    [String]$SystemVolumeMinFreeSize,
    [Parameter()]
    [String]$DataVolumeMinFreePercent,
    [Parameter()]
    [String]$DataVolumeMinFreeSize,
    [Parameter()]
    [String]$ExcludeDataVolumesFromAlert = "WINRETOOLS, ESP, DELLSUPPORT, Windows RE Tools, SYSTEM, System Reserved",
    [Parameter()]
    [String]$AlertOnlyForDataVolumes,
    [Parameter()]
    [String]$MultilineCustomField,
    [Parameter()]
    [String]$WYSIWYGCustomField,
    [Parameter()]
    [String]$SystemVolumeMinFreePercentCustomField,
    [Parameter()]
    [String]$SystemVolumeMinFreeSizeCustomField,
    [Parameter()]
    [String]$DataVolumeMinFreePercentCustomField,
    [Parameter()]
    [String]$DataVolumeMinFreeSizeCustomField,
    [Parameter()]
    [String]$ExcludeDataVolumeCustomField,
    [Parameter()]
    [String]$AlertOnlyCustomField
)

begin {
    # If script form variables are used, replace the command line parameters with their value.
    if ($env:systemVolumeMinimumPercentageFree) { $SystemVolumeMinFreePercent = $env:systemVolumeMinimumPercentageFree }
    if ($env:systemVolumeMinimumFreeSize) { $SystemVolumeMinFreeSize = $env:systemVolumeMinimumFreeSize }
    if ($env:dataVolumeMinimumPercentageFree) { $DataVolumeMinFreePercent = $env:dataVolumeMinimumPercentageFree }
    if ($env:dataVolumeMinimumFreeSize) { $DataVolumeMinFreeSize = $env:dataVolumeMinimumFreeSize }
    if ($env:excludeDataVolumesFromAlert) { $ExcludeDataVolumesFromAlert = $env:excludeDataVolumesFromAlert }
    if ($env:alertOnlyForDataVolumes) { $AlertOnlyForDataVolumes = $env:alertOnlyForDataVolumes }
    if ($env:multilineCustomFieldName) { $MultilineCustomField = $env:multilineCustomFieldName }
    if ($env:wysiwygCustomFieldName) { $WYSIWYGCustomField = $env:wysiwygCustomFieldName }
    if ($env:retrieveSystemVolumeMinimumPercentageFreeFromCustomField) { $SystemVolumeMinFreePercentCustomField = $env:retrieveSystemVolumeMinimumPercentageFreeFromCustomField }
    if ($env:retrieveSystemVolumeMinimumFreeSizeFromCustomField) { $SystemVolumeMinFreeSizeCustomField = $env:retrieveSystemVolumeMinimumFreeSizeFromCustomField }
    if ($env:retrieveDataVolumeMinimumPercentageFreeFromCustomField) { $DataVolumeMinFreePercentCustomField = $env:retrieveDataVolumeMinimumPercentageFreeFromCustomField }
    if ($env:retrieveDataVolumeMinimumFreeSizeFromCustomField) { $DataVolumeMinFreeSizeCustomField = $env:retrieveDataVolumeMinimumFreeSizeFromCustomField }
    if ($env:retrieveExcludeDataVolumesFromCustomField) { $ExcludeDataVolumeCustomField = $env:retrieveExcludeDataVolumesFromCustomField }
    if ($env:retrieveAlertOnlyForDataVolumesFromCustomField) { $AlertOnlyCustomField = $env:retrieveAlertOnlyForDataVolumesFromCustomField }


    # Define an array of custom fields to validate
    $CustomFields = @(
        $SystemVolumeMinFreePercentCustomField,
        $SystemVolumeMinFreeSizeCustomField,
        $DataVolumeMinFreePercentCustomField,
        $DataVolumeMinFreeSizeCustomField,
        $ExcludeDataVolumeCustomField,
        $AlertOnlyCustomField,
        $MultilineCustomField,
        $WYSIWYGCustomField
    )
    
    # Check if the PowerShell version is less than 3 and custom fields are being used
    if ($PSVersionTable.PSVersion.Major -lt 3 -and ($CustomFields | Where-Object { $_ })) {
        Write-Host -Object "[Error] Setting custom fields is not supported in PowerShell 2.0."
        Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/4405408656013-Custom-Fields-and-Documentation-CLI-and-Scripting"
        exit 1   
    }

    # Validate the 'System Volume Minimum Percentage Free' custom field
    if ($SystemVolumeMinFreePercentCustomField) {
        $SystemVolumeMinFreePercentCustomField = $SystemVolumeMinFreePercentCustomField.Trim()

        if (!($SystemVolumeMinFreePercentCustomField)) {
            Write-Host -Object "[Error] The 'Retrieve System Volume Minimum Percentage Free from Custom Field' is invalid."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'System Volume Minimum Percentage Free' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($SystemVolumeMinFreePercentCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'Retrieve System Volume Minimum Percentage Free from Custom Field' of '$SystemVolumeMinFreePercentCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'System Volume Minimum Percentage Free' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Validate the 'System Volume Minimum Free Size' custom field
    if ($SystemVolumeMinFreeSizeCustomField) {
        $SystemVolumeMinFreeSizeCustomField = $SystemVolumeMinFreeSizeCustomField.Trim()

        if (!($SystemVolumeMinFreeSizeCustomField)) {
            Write-Host -Object "[Error] The 'Retrieve System Volume Minimum Free Size from Custom Field' is invalid."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'System Volume Minimum Free Size' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($SystemVolumeMinFreeSizeCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'Retrieve System Volume Minimum Free Size from Custom Field' of '$SystemVolumeMinFreeSizeCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'System Volume Minimum Free Size' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Validate the 'Data Volume Minimum Percentage Free' custom field
    if ($DataVolumeMinFreePercentCustomField) {
        $DataVolumeMinFreePercentCustomField = $DataVolumeMinFreePercentCustomField.Trim()

        if (!($DataVolumeMinFreePercentCustomField)) {
            Write-Host -Object "[Error] The 'Retrieve Data Volume Minimum Percentage Free from Custom Field' is invalid."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Data Volume Minimum Percentage Free' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($DataVolumeMinFreePercentCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'Retrieve Data Volume Minimum Percentage Free from Custom Field' of '$DataVolumeMinFreePercentCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Data Volume Minimum Percentage Free' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Validate the 'Data Volume Minimum Free Size' custom field
    if ($DataVolumeMinFreeSizeCustomField) {
        $DataVolumeMinFreeSizeCustomField = $DataVolumeMinFreeSizeCustomField.Trim()

        if (!($DataVolumeMinFreeSizeCustomField)) {
            Write-Host -Object "[Error] The 'Retrieve Data Volume Minimum Free Size from Custom Field' is invalid."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Data Volume Minimum Free Size' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($DataVolumeMinFreeSizeCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'Retrieve Data Volume Minimum Free Size from Custom Field' of '$DataVolumeMinFreeSizeCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Data Volume Minimum Free Size' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Validate the 'Exclude Data Volumes from Alert' custom field
    if ($ExcludeDataVolumeCustomField) {
        $ExcludeDataVolumeCustomField = $ExcludeDataVolumeCustomField.Trim()

        if (!($ExcludeDataVolumeCustomField)) {
            Write-Host -Object "[Error] The 'Retrieve Exclude Data Volumes from Alert from Custom Field' is invalid."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Exclude Data Volumes from Alert' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($ExcludeDataVolumeCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'Retrieve Exclude Data Volumes from Alert from Custom Field' of '$ExcludeDataVolumeCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Exclude Data Volumes from Alert' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Validate the 'Alert Only for Data Volumes' custom field
    if ($AlertOnlyCustomField) {
        $AlertOnlyCustomField = $AlertOnlyCustomField.Trim()

        if (!($AlertOnlyCustomField)) {
            Write-Host -Object "[Error] The 'Retrieve Alert Only for Data Volumes from Custom Field' is invalid."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Alert Only for Data Volumes' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($AlertOnlyCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'Retrieve Alert Only for Data Volumes from Custom Field' of '$AlertOnlyCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid text custom field name to retrieve the 'Alert Only for Data Volumes' value from, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Validate the 'Multiline Custom Field Name'
    if ($MultilineCustomField) {
        $MultilineCustomField = $MultilineCustomField.Trim()

        if (!($MultilineCustomField)) {
            Write-Host -Object "[Error] The 'Multiline Custom Field Name' is invalid."
            Write-Host -Object "[Error] Please provide a valid multiline custom field name to save the results, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($MultilineCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'Multiline Custom Field Name' of '$MultilineCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid multiline custom field name to save the results, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Validate the 'WYSIWYG Custom Field Name'
    if ($WYSIWYGCustomField) {
        $WYSIWYGCustomField = $WYSIWYGCustomField.Trim()

        if (!($WYSIWYGCustomField)) {
            Write-Host -Object "[Error] The 'WYSIWYG Custom Field Name' is invalid."
            Write-Host -Object "[Error] Please provide a valid WYSIWYG custom field name to save the results, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }

        if ($WYSIWYGCustomField -match "[^0-9A-Z]") {
            Write-Host -Object "[Error] The 'WYSIWYG Custom Field Name' of '$WYSIWYGCustomField' is invalid as it contains invalid characters."
            Write-Host -Object "[Error] Please provide a valid WYSIWYG custom field name to save the results, or leave it blank."
            Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
            exit 1
        }
    }

    # Check for duplicate custom field names
    $DuplicateFields = ($CustomFields | Where-Object { $_ } | Group-Object | Where-Object { $_.Count -gt 1 }).Group
    if (($CustomFields | Where-Object { $_ } | Group-Object | Where-Object { $_.Count -gt 1 })) {
        Write-Host -Object "[Error] You must provide a unique name for each custom field you would like to either retrieve the value from or save to."
        Write-Host -Object "[Error] Or you can leave the value blank."
        Write-Host -Object "[Error] Duplicate Field Names Given: $($DuplicateFields -join ', ')"
        Write-Host -Object "[Error] https://ninjarmm.zendesk.com/hc/articles/360060920631-Custom-Field-Setup"
        exit 1
    }

    # Convert file size strings (e.g., "50 GB") into their equivalent numeric byte values.
    function ConvertTo-Bytes {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String[]]$FileSize,
            [Parameter()]
            [String]$DefaultTo
        )
        process {
            # Check if the input is null or an empty string.
            if ([String]::IsNullOrEmpty($FileSize)) {
                throw (New-Object System.ArgumentNullException("You must provide a file size string to convert into bytes."))
            }

            # Define an array of valid default unit options.
            $ValidDefaults = "PB", "TB", "GB", "MB", "KB", "B", "Bytes"

            # Check if $DefaultTo has a value and is not in the list of valid defaults.
            if ($DefaultTo -and $ValidDefaults -notcontains $DefaultTo) {
                throw (New-Object System.ArgumentOutOfRangeException("You cannot default to '$DefaultTo'. Valid default options include: 'PB', 'TB', 'GB', 'MB', 'KB', 'B', and 'Bytes'."))
            }

            # Create a generic list to store validated file size strings.
            $FileSizesToConvert = New-Object System.Collections.Generic.List[String]

            # Iterate over each provided file size string.
            $FileSize | ForEach-Object {
                # Store the trimmed input string for easier reference.
                $CurrentFileSizeObject = $_.Trim()

                if (!($CurrentFileSizeObject)) {
                    Write-Error -Category ObjectNotFound -Exception (New-Object System.ArgumentNullException("FileSize", "An empty file size string was given. Unable to convert null into bytes."))
                    return
                }

                # Validate the string for any characters not allowed.
                # This regex permits digits, the period, whitespace, dashes, and valid unit strings (PB, TB, GB, MB, KB, B, Bytes).
                if ($CurrentFileSizeObject -match "[^0-9. (PB|TB|GB|MB|KB|B|Bytes)-]") {
                    Write-Error -Category InvalidArgument -Exception (New-Object System.ArgumentException("The file size of '$CurrentFileSizeObject' is invalid; it contains invalid characters. Please specify a file size such as '50 GB'."))
                    return
                }
        
                # Validate the overall format of the file size string.
                if ($CurrentFileSizeObject -notmatch "^-?[0-9]+\.?[0-9]*\s*(PB|TB|GB|MB|KB|B|Bytes)?$") {
                    Write-Error -Category InvalidArgument -Exception (New-Object System.ArgumentException("The file size of '$CurrentFileSizeObject' is invalid; it's in an invalid format. Please specify a file size such as '50 GB'"))
                    return
                }

                # If the trimmed input does not end with one of the valid units (PB, TB, GB, MB, KB, B, or Bytes)
                if ($CurrentFileSizeObject -notmatch "(PB|TB|GB|MB|KB|B|Bytes)$") {

                    # Determine which unit to append based on the default unit ($DefaultTo)
                    $NewFileSize = switch ($DefaultTo) {
                        'PB' { "$CurrentFileSizeObject PB" }
                        'TB' { "$CurrentFileSizeObject TB" }
                        'GB' { "$CurrentFileSizeObject GB" }
                        'MB' { "$CurrentFileSizeObject MB" }
                        'KB' { "$CurrentFileSizeObject KB" }
                        default { "$CurrentFileSizeObject Bytes" }
                    }

                    # Add the newly formatted string to the list of file sizes to convert.
                    $FileSizesToConvert.Add($NewFileSize)
                
                    return
                }

                # Add the validated, trimmed file size string to our list.
                $FileSizesToConvert.Add($CurrentFileSizeObject)
            }

            # If no valid file sizes were found, throw an error.
            if ($FileSizesToConvert.Count -lt 1) {
                throw (New-Object System.ArgumentNullException("You must provide a file size string to convert into bytes."))
            }

            # Process each validated file size string and convert it into bytes.
            $FileSizesToConvert | ForEach-Object {
                $DigitCharacters = $Null

                try {
                    # Extract the numeric portion from the string (digits, decimal point, and optional minus sign)
                    # and convert it to a decimal.
                    [decimal]$DigitCharacters = $_ -replace '[^0-9.-]'
                }
                catch {
                    $_
                    return
                }
            
                # Determine the unit in the file size string using regex in a switch statement.
                # Multiply the numeric value by the corresponding byte constant.
                switch -regex ($_) {
                    'PB$' { $DigitCharacters * 1PB; break }
                    'TB$' { $DigitCharacters * 1TB; break }
                    'GB$' { $DigitCharacters * 1GB; break }
                    'MB$' { $DigitCharacters * 1MB; break }
                    'KB$' { $DigitCharacters * 1KB; break }
                    'B$' { $DigitCharacters * 1; break }
                    'Bytes$' { $DigitCharacters * 1; break }
                }
            }
        }
    }

    # Convert file sizes given in bytes to a human-friendly string format (e.g., "2.8 MB").
    function ConvertTo-FriendlySize {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline = $True)]
            [long[]]$Bytes,
            [Parameter()]
            [long]$RoundTo = 2
        )
        process {
            # Validate input: If $Bytes is null or an empty string set Bytes equal to 0.
            if ([String]::IsNullOrEmpty($Bytes)) {
                $Bytes = 0
            }

            # Process each file size in the input array.
            $Bytes | ForEach-Object {
                $ConvertedBytes = $Null

                # If the current file size is 0, immediately output "0 Bytes" and skip further processing.
                if ($_ -eq 0) {
                    "0 Bytes"
                    return
                }

                # Define an array of size units from Bytes to Zettabytes
                $DataSizes = 'Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','

                try {
                    # Initialize the conversion variable with the current byte value.
                    $ConvertedBytes = $_

                    # This loop repeats as long as the value is divisible by 1KB, incrementing the index by 1 each time. 
                    # The index is later used to select the appropriate unit for the human-friendly string.
                    for ( $Index = 0; ($ConvertedBytes -ge 1KB -or $ConvertedBytes -le -1KB) -and $Index -lt $DataSizes.Count; $Index++ ) {
                        $ConvertedBytes = $ConvertedBytes / 1KB
                    }
                }
                catch {
                    $_
                    return
                }

                # If conversion resulted in a null or false value, write an error message.
                if (!($ConvertedBytes)) {
                    Write-Error -Category ObjectNotFound -Exception (New-Object System.Data.ObjectNotFoundException("Failed to convert '$_' into a human-friendly string."))
                    return
                }

                # Format the converted value rounded to the specified number of decimal places,
                # and append the corresponding unit from the $DataSizes array.
                "$([System.Math]::Round($ConvertedBytes, $RoundTo)) $($DataSizes[$Index])"
            }
        }
    }

    function Set-CustomField {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [String]$Name,
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            $Value,
            [Parameter()]
            [String]$Type,
            [Parameter()]
            [String]$DocumentName,
            [Parameter()]
            [Switch]$Piped
        )
    
        if ($Type -eq "Date Time") { $Type = "DateTime" }
        if ($Type -match "[-]") { $Type = $Type -replace '-' }
        if ($Type -match "[/]") { $Type = $Type -replace '/' }
    
        # Remove the non-breaking space character
        if ($Type -eq "WYSIWYG") {
            $Value = $Value -replace ' ', '&nbsp;'
        }
    
        if ($Type -eq "DateTime" -or $Type -eq "Date") {
            $Type = "Date or Date Time"
        }
        
        # Measure the number of characters in the provided value
        $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters
    
        # Throw an error if the value exceeds the character limit of 200,000 characters
        if ($Piped -and $Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
    
        if (!$Piped -and $Characters -ge 45000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 45,000 characters.")
        }
        
        # Initialize a hashtable for additional documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # Define a list of valid field types
        $ValidFields = "Checkbox", "Date", "Date or Date Time", "DateTime", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", 
        "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
    
        # Warn the user if the provided type is not valid
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # Define types that require options to be retrieved
        $NeedsOptions = "Dropdown", "MultiSelect"
    
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
                [long]$NinjaValue = $TimeSpan.TotalSeconds
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
            "MultiSelect" {
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selections = New-Object System.Collections.Generic.List[String]
                if ($Value -match "[,]") {
                    $Value = $Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
                }
    
                $Value | ForEach-Object {
                    $GivenValue = $_
                    $Selection = $Options | Where-Object { $_.Name -eq $GivenValue } | Select-Object -ExpandProperty GUID
    
                    # Throw an error if the value is not present in the dropdown options
                    if (!($Selection)) {
                        throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                    }
    
                    $Selections.Add($Selection)
                }
    
                $NinjaValue = $Selections -join ","
            }
            "Time" {
                # Convert the value to a Unix timestamp for Date or Date Time type
                $LocalTime = (Get-Date $Value)
                $LocalTimeZone = [TimeZoneInfo]::Local
                $UtcTime = [TimeZoneInfo]::ConvertTimeToUtc($LocalTime, $LocalTimeZone)
    
                [long]$NinjaValue = ($UtcTime.TimeOfDay).TotalSeconds
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
            try {
                # Otherwise, set the standard property value
                if ($Piped) {
                    $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
                }
                else {
                    $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1
                }
            }
            catch {
                throw $_.Exception.Message
            }
        }
            
        # Throw an error if setting the property failed
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    function Get-CustomField {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter()]
            [String]$DocumentName
        )
        # Initialize a hashtable for documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
    
        if ($Type -eq "Date Time") { $Type = "DateTime" }
        if ($Type -match "[-]") { $Type = $Type -replace '-' }
        if ($Type -match "[/]") { $Type = $Type -replace '/' }
    
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "DateTime", "Decimal", "Device Dropdown", "Device MultiSelect", "Dropdown", 
        "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Organization Dropdown", "Organization Location Dropdown", 
        "Organization Location MultiSelect", "Organization MultiSelect", "Phone", "Secure", "Text", "Time", "WYSIWYG", "URL"
        if ($Type -and $ValidFields -notcontains $Type) {
            Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality"
        }
    
        # Define types that require options to be retrieved
        $NeedsOptions = "DropDown", "MultiSelect"
        
        # If a document name is provided, retrieve the property value from the document
        if ($DocumentName) {
        
            $NinjaPropertyValue = Ninja-Property-Docs-Get -AttributeName $Name @DocumentationParams 2>&1
        
            # If the property type requires options, retrieve them
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            # If no document name is provided, retrieve the property value directly
            $NinjaPropertyValue = Ninja-Property-Get -Name $Name 2>&1
    
            # If the property type requires options, retrieve them
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
        
        # Throw an exception if there was an error retrieving the property value or options
        if ($NinjaPropertyValue.Exception) { throw $NinjaPropertyValue }
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
        
        # Throw an error if the retrieved property value is null or empty
        if (!($NinjaPropertyValue)) {
            return
        }
        
        # Handle the property value based on its type
        switch ($Type) {
            "Attachment" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Checkbox" {
                # Convert the value to a boolean
                [System.Convert]::ToBoolean([int]$NinjaPropertyValue)
            }
            "Date" {
                # Convert a Unix timestamp to local date and time
                $UnixTimeStamp = $NinjaPropertyValue
                $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds($UnixTimeStamp)
                $TimeZone = [TimeZoneInfo]::Local
                $ConvertedDate = [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
    
                Get-Date $ConvertedDate -DisplayHint Date
            }
            "Date or Date Time" {
                # Convert a Unix timestamp to local date and time
                $UnixTimeStamp = $NinjaPropertyValue
                $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds($UnixTimeStamp)
                $TimeZone = [TimeZoneInfo]::Local
                [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
            }
            "DateTime" {
                # Convert a Unix timestamp to local date and time
                $UnixTimeStamp = $NinjaPropertyValue
                $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds($UnixTimeStamp)
                $TimeZone = [TimeZoneInfo]::Local
                $ConvertedDate = [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
    
                Get-Date $ConvertedDate -DisplayHint DateTime
            }
            "Decimal" {
                # Convert the value to a double (floating-point number)
                [double]$NinjaPropertyValue
            }
            "Device Dropdown" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Device MultiSelect" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Dropdown" {
                # Convert options to a CSV format and match the GUID to retrieve the display name
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Options | Where-Object { $_.GUID -eq $NinjaPropertyValue } | Select-Object -ExpandProperty Name
            }
            "Integer" {
                # Convert the value to an integer
                [int]$NinjaPropertyValue
            }
            "MultiSelect" {
                # Convert options to a CSV format, then match and return selected items
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = ($NinjaPropertyValue -split ',').trim()
        
                foreach ($Item in $Selection) {
                    $Options | Where-Object { $_.GUID -eq $Item } | Select-Object -ExpandProperty Name
                }
            }
            "Organization Dropdown" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location Dropdown" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location MultiSelect" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization MultiSelect" {
                # Convert JSON formatted property value to a PowerShell object
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Time" {
                $secondsSinceMidnightUTC = $NinjaPropertyValue
                # Get midnight for today in UTC
                $midnightUTC = [datetime]::UtcNow.Date
    
                # Add the seconds to midnight to get the UTC time
                $utcTime = $midnightUTC.AddSeconds($secondsSinceMidnightUTC)
    
                # Convert the UTC time to the local time zone
                $localTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($utcTime, [System.TimeZoneInfo]::Local)
    
                # Display the result
                Get-Date $localTime -DisplayHint Time
            }
            default {
                # For any other types, return the raw value
                $NinjaPropertyValue
            }
        }
    }
    

    function Test-IsElevated {
        [CmdletBinding()]
        param ()
        
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        
        # Create a WindowsPrincipal object based on the current identity
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        
        # Check if the current user is in the Administrator role
        # The function returns $True if the user has administrative privileges, $False otherwise
        # 544 is the value for the Built-In Administrators role
        # Reference: https://learn.microsoft.com/en-us/dotnet/api/system.security.principal.windowsbuiltinrole
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]'544')
    }

    if (!($ExitCode)) {
        $ExitCode = 0
    }
}
process {
    # Attempt to determine if the current session is running with Administrator privileges.
    try {
        $IsElevated = Test-IsElevated -ErrorAction Stop
    }
    catch {
        # Log an error if unable to determine admin privileges
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Unable to determine if the account '$env:Username' is running with Administrator privileges."
        exit 1
    }
    
    # Exit if the script is not running with Administrator privileges
    if (!($IsElevated)) {
        Write-Host -Object "[Error] Access Denied: Please run with Administrator privileges."
        exit 1
    }

    # Retrieve 'System Volume Minimum Percentage Free' from a custom field if specified and not already provided
    if ($SystemVolumeMinFreePercentCustomField -and !($SystemVolumeMinFreePercent)) {
        try {
            Write-Host -Object "Attempting to retrieve the 'System Volume Minimum Percentage Free' value from the field '$SystemVolumeMinFreePercentCustomField'."
            $SystemVolumeMinFreePercent = Get-CustomField -Name $SystemVolumeMinFreePercentCustomField -ErrorAction Stop
            Write-Host -Object "Successfully retrieved the custom field contents.`n"
        }
        catch {
            # Log an error if retrieval fails
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the 'System Volume Minimum Percentage Free' from the custom field '$SystemVolumeMinFreePercentCustomField'."
            exit 1
        }

        # Trim and validate the retrieved value
        if ($SystemVolumeMinFreePercent) {
            $SystemVolumeMinFreePercent = $SystemVolumeMinFreePercent.Trim()
        }

        if (!($SystemVolumeMinFreePercent)) {
            Write-Host -Object "[Error] The custom field '$SystemVolumeMinFreePercentCustomField' is empty."
            Write-Host -Object "[Error] Please save a value to the custom field or leave 'Retrieve System Volume Minimum Percentage Free from Custom Field' blank."
            exit 1
        }
    }

    # Retrieve 'System Volume Minimum Free Size' from a custom field if specified and not already provided
    if ($SystemVolumeMinFreeSizeCustomField -and !($SystemVolumeMinFreeSize)) {
        try {
            Write-Host -Object "Attempting to retrieve the 'System Volume Minimum Free Size' value from the field '$SystemVolumeMinFreeSizeCustomField'."
            $SystemVolumeMinFreeSize = Get-CustomField -Name $SystemVolumeMinFreeSizeCustomField -ErrorAction Stop
            Write-Host -Object "Successfully retrieved the custom field contents.`n"
        }
        catch {
            # Log an error if retrieval fails
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the 'System Volume Minimum Free Size' from the custom field '$SystemVolumeMinFreeSizeCustomField'."
            exit 1
        }

        # Trim and validate the retrieved value
        if ($SystemVolumeMinFreeSize) {
            $SystemVolumeMinFreeSize = $SystemVolumeMinFreeSize.Trim()
        }

        if (!($SystemVolumeMinFreeSize)) {
            Write-Host -Object "[Error] The custom field '$SystemVolumeMinFreeSizeCustomField' is empty."
            Write-Host -Object "[Error] Please save a value to the custom field or leave 'Retrieve System Volume Minimum Free Size from Custom Field' blank."
            exit 1
        }
    }

    # Retrieve 'Data Volume Minimum Percentage Free' from a custom field if specified and not already provided
    if ($DataVolumeMinFreePercentCustomField -and !($DataVolumeMinFreePercent)) {
        try {
            Write-Host -Object "Attempting to retrieve the 'Data Volume Minimum Percentage Free' value from the field '$DataVolumeMinFreePercentCustomField'."
            $DataVolumeMinFreePercent = Get-CustomField -Name $DataVolumeMinFreePercentCustomField -ErrorAction Stop
            Write-Host -Object "Successfully retrieved the custom field contents.`n"
        }
        catch {
            # Log an error if retrieval fails
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the 'Data Volume Minimum Percentage Free' from the custom field '$DataVolumeMinFreePercentCustomField'."
            exit 1
        }

        # Trim and validate the retrieved value
        if ($DataVolumeMinFreePercent) {
            $DataVolumeMinFreePercent = $DataVolumeMinFreePercent.Trim()
        }

        if (!($DataVolumeMinFreePercent)) {
            Write-Host -Object "[Error] The custom field '$DataVolumeMinFreePercentCustomField' is empty."
            Write-Host -Object "[Error] Please save a value to the custom field or leave 'Retrieve Data Volume Minimum Percentage Free from Custom Field' blank."
            exit 1
        }
    }

    # Retrieve 'Data Volume Minimum Free Size' from a custom field if specified and not already provided
    if ($DataVolumeMinFreeSizeCustomField -and !($DataVolumeMinFreeSize)) {
        try {
            Write-Host -Object "Attempting to retrieve the 'Data Volume Minimum Free Size' value from the field '$DataVolumeMinFreeSizeCustomField'."
            $DataVolumeMinFreeSize = Get-CustomField -Name $DataVolumeMinFreeSizeCustomField -ErrorAction Stop
            Write-Host -Object "Successfully retrieved the custom field contents.`n"
        }
        catch {
            # Log an error if retrieval fails
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the 'Data Volume Minimum Free Size' from the custom field '$DataVolumeMinFreeSizeCustomField'."
            exit 1
        }

        # Trim and validate the retrieved value
        if ($DataVolumeMinFreeSize) {
            $DataVolumeMinFreeSize = $DataVolumeMinFreeSize.Trim()
        }

        if (!($DataVolumeMinFreeSize)) {
            Write-Host -Object "[Error] The custom field '$DataVolumeMinFreeSizeCustomField' is empty."
            Write-Host -Object "[Error] Please save a value to the custom field or leave 'Retrieve Data Volume Minimum Free Size from Custom Field' blank."
            exit 1
        }
    }

    # Retrieve 'Exclude Data Volumes from Alert' from a custom field if specified and not already provided
    if ($ExcludeDataVolumeCustomField) {
        try {
            Write-Host -Object "Attempting to retrieve the 'Exclude Data Volumes from Alert' value from the field '$ExcludeDataVolumeCustomField'."
            $VolumesToExclude = Get-CustomField -Name $ExcludeDataVolumeCustomField -ErrorAction Stop
            Write-Host -Object "Successfully retrieved the custom field contents.`n"
        }
        catch {
            # Log an error if retrieval fails
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the 'Exclude Data Volumes from Alert' from the custom field '$ExcludeDataVolumeCustomField'."
            exit 1
        }

        # Trim and validate the retrieved value
        if ($VolumesToExclude) {
            $VolumesToExclude = $VolumesToExclude.Trim()
        }

        if (!($VolumesToExclude)) {
            Write-Host -Object "[Error] The custom field '$ExcludeDataVolumeCustomField' is empty."
            Write-Host -Object "[Error] Please save a value to the custom field or leave 'Retrieve Exclude Data Volumes from Alert from Custom Field' blank."
            exit 1
        }

        if($ExcludeDataVolumesFromAlert -match "[^, ]"){
            $ExcludeDataVolumesFromAlert = "$ExcludeDataVolumesFromAlert, $VolumesToExclude"
        }else{
            $ExcludeDataVolumesFromAlert = $VolumesToExclude
        }
    }

    # Retrieve 'Alert Only for Data Volumes' from a custom field if specified and not already provided
    if ($AlertOnlyCustomField -and !($AlertOnlyForDataVolumes)) {
        try {
            Write-Host -Object "Attempting to retrieve the 'Alert Only for Data Volumes' value from the field '$AlertOnlyCustomField'."
            $AlertOnlyForDataVolumes = Get-CustomField -Name $AlertOnlyCustomField -ErrorAction Stop
            Write-Host -Object "Successfully retrieved the custom field contents.`n"
        }
        catch {
            # Log an error if retrieval fails
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the 'Alert Only for Data Volumes' from the custom field '$AlertOnlyCustomField'."
            exit 1
        }

        # Trim and validate the retrieved value
        if ($AlertOnlyForDataVolumes) {
            $AlertOnlyForDataVolumes = $AlertOnlyForDataVolumes.Trim()
        }

        if (!($AlertOnlyForDataVolumes)) {
            Write-Host -Object "[Error] The custom field '$AlertOnlyCustomField' is empty."
            Write-Host -Object "[Error] Please save a value to the custom field or leave 'Retrieve Alert Only for Data Volumes from Custom Field' blank."
            exit 1
        }
    }

    # Retrieve the system volume based on the system drive
    Write-Host -Object "Retrieving the system volume '$env:SystemDrive'."
    try {
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            # Use WMI for PowerShell versions < 3
            $SystemVolume = Get-WmiObject -Class Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq "$env:SystemDrive" } | 
                Select-Object "DriveLetter", "Label", "Name", "FileSystem", "FreeSpace", "Capacity" | Sort-Object Label
        }
        else {
            # Use CIM for PowerShell versions >= 3
            $SystemVolume = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq "$env:SystemDrive" } | 
                Select-Object "DriveLetter", "Label", "Name", "FileSystem", "FreeSpace", "Capacity" | Sort-Object Label
        }

        # Validate the retrieved system volume
        if (!($SystemVolume)) {
            throw "No system volume with a drive letter that matches '$env:SystemDrive'."
        }

        if ($SystemVolume.Count -gt 1) {
            throw "Multiple volumes detected with the drive letter '$env:SystemDrive'."
        }
    }
    catch {
        # Log an error if retrieval fails
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to retrieve the system volume. Unable to calculate the free space remaining."
        exit 1
    }

    # Initialize a list to store system volume minimum free space data
    $SystemVolumeMinFree = New-Object System.Collections.Generic.List[object]

    # Retrieve all data volumes excluding the system drive
    Write-Host -Object "Retrieving all data volumes.`n"
    try {
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            # Use WMI for PowerShell versions < 3
            $DataVolumes = Get-WmiObject -Class Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 -and $_.DriveLetter -ne "$env:SystemDrive" -and $_.Capacity -gt 0 -and $_.FreeSpace -gt 0 } | 
                Select-Object "DriveLetter", "Label", "Name", "FileSystem", "FreeSpace", "Capacity" | Sort-Object Label
        }
        else {
            # Use CIM for PowerShell versions >= 3
            $DataVolumes = Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveType -eq 3 -and $_.DriveLetter -ne "$env:SystemDrive" -and $_.Capacity -gt 0 -and $_.FreeSpace -gt 0 } | 
                Select-Object "DriveLetter", "Label", "Name", "FileSystem", "FreeSpace", "Capacity" | Sort-Object Label
        }

        # Log a warning if no data volumes are detected
        if (!($DataVolumes)) {
            Write-Host -Object "[Warning] No data volumes detected."
        }
    }
    catch {
        # Log an error if retrieval fails
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to retrieve data volumes. Unable to calculate free space remaining."
        exit 1
    }

    # Initialize a list to store data volume minimum free space data
    $DataVolumeMinFree = New-Object System.Collections.Generic.List[object]

    # Process volumes to exclude from alerts
    if ($ExcludeDataVolumesFromAlert) {
        if (!($ExcludeDataVolumesFromAlert.Trim())) {
            Write-Host -Object "[Error] Please specify a valid volume label or drive letter or file path to exclude."
            exit 1
        }

        if (!($DataVolumeMinFreePercent) -and !($DataVolumeMinFreeSize)) {
            Write-Host -Object "[Warning] You must have a data volume limit in order to exclude it from the alert."
        }

        # Initialize a list to store volumes to exclude
        $VolumesToExclude = New-Object System.Collections.Generic.List[string]

        try {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                # Retrieve system volume labels using WMI for PowerShell versions < 3
                $SystemVolumeLabels = (Get-WmiObject -Class Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq "$env:SystemDrive" } | 
                        Select-Object -Property "Label" -ErrorAction SilentlyContinue).Label
            }
            else {
                # Retrieve system volume labels using CIM for PowerShell versions >= 3
                $SystemVolumeLabels = (Get-CimInstance -ClassName Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq "$env:SystemDrive" } | 
                        Select-Object -Property "Label" -ErrorAction SilentlyContinue).Label
            }
        }
        catch {
            # Log an error if retrieval fails
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to retrieve the system volume labels."
            exit 1
        }

        # Process each volume to exclude
        $ExcludeDataVolumesFromAlert -split "," | ForEach-Object {
            # Normalize the volume format
            $PotentialVolume = $_.Trim()

            if (!($PotentialVolume)) {
                Write-Host -Object "[Error] '$ExcludeDataVolumesFromAlert' contains an invalid volume to exclude. There is an empty item in the comma-separated list."
                exit 1
            }

            if ($PotentialVolume -match "^[A-Z]$") {
                $PotentialVolume = "$PotentialVolume" + ":"
            }

            # Prevent excluding the system volume
            $SystemVolumes = "$env:SystemDrive", "$($env:SystemDrive -replace '[^A-Z:]')", "$env:SystemDrive\"
            if ($SystemVolumes -contains $PotentialVolume) {
                Write-Host -Object "[Warning] The system volume '$PotentialVolume' cannot be excluded."
            }

            if ($SystemVolumeLabels -contains $PotentialVolume) {
                Write-Host -Object "[Warning] The system volume '$PotentialVolume' cannot be excluded."
            }

            if ($DataVolumes.DriveLetter -notcontains $PotentialVolume -and $DataVolumes.Label -notcontains $PotentialVolume -and $DataVolumes.Name -notcontains $PotentialVolume) {
                Write-Host -Object "[Warning] The volume '$PotentialVolume' is not the label, drive letter, or path of any data volume on this system."
                $AddAnExtraNewLine = $True
            }

            # Add the volume to the exclusion list
            $VolumesToExclude.Add($PotentialVolume)
        }
    }

    if($AddAnExtraNewLine){
        Write-Host -Object ""
    }

    # Process volumes to include in alerts
    if ($AlertOnlyForDataVolumes) {
        if (!($AlertOnlyForDataVolumes.Trim())) {
            Write-Host -Object "[Error] Please specify a valid volume label or drive letter or file path to alert on."
            exit 1
        }

        if (!($DataVolumeMinFreePercent) -and !($DataVolumeMinFreeSize)) {
            Write-Host -Object "[Warning] You must have a data volume limit in order to include it for the alert."
        }

        # Initialize a list to store volumes to include
        $VolumesToInclude = New-Object System.Collections.Generic.List[String]

        # Process each volume to include
        $AlertOnlyForDataVolumes -split "," | ForEach-Object {
            # Normalize the volume format
            $PotentialVolume = $_.Trim()

            if (!($PotentialVolume)) {
                Write-Host -Object "[Error] '$AlertOnlyForDataVolumes' contains an invalid volume to alert on. There is an empty item in the comma-separated list."
                exit 1
            }

            # Normalize the volume format
            $PotentialVolume = $_.Trim()

            if ($PotentialVolume -match "^[A-Z]$") {
                $PotentialVolume = "$PotentialVolume" + ":"
            }

            # Prevent including volumes that are also excluded
            if ($ExcludeDataVolumesFromAlert.Count -ge 1 -and $ExcludeDataVolumesFromAlert -contains $PotentialVolume) {
                Write-Host -Object "[Error] Cannot alert only on '$($_.Trim())' and exclude it from the alert."
                exit 1
            }

            if ($DataVolumes.DriveLetter -notcontains $PotentialVolume -and $DataVolumes.Label -notcontains $PotentialVolume -and $DataVolumes.Name -notcontains $PotentialVolume) {
                Write-Host -Object "[Warning] The volume '$PotentialVolume' is not the label, drive letter, or path of any data volume on this system.`n"
                $AddAnExtraNewLine = $True
            }

            # Add the volume to the inclusion list
            $VolumesToInclude.Add($PotentialVolume)
        }
    }

    if($AddAnExtraNewLine){
        Write-Host -Object ""
    }

    # Check if a minimum percentage of free space for the system volume is specified
    if ($SystemVolumeMinFreePercent) {
        $SystemVolumeMinFreePercent = $SystemVolumeMinFreePercent.Trim()

        # Validate that the percentage is not empty
        if (!($SystemVolumeMinFreePercent)) {
            Write-Host -Object "[Error] The minimum system volume free size percentage of '$SystemVolumeMinFreePercent' is invalid."
            Write-Host -Object "[Error] A percentage that is greater than 0 and less than 100 was expected."
            exit 1
        }

        # Validate that the percentage contains only valid characters
        if ($SystemVolumeMinFreePercent -match "[^0-9.% ]") {
            Write-Host -Object "[Error] The minimum system volume free size percentage of '$SystemVolumeMinFreePercent' is invalid."
            Write-Host -Object "[Error] It contains invalid characters. The only characters supported (besides whitespace) are '.','%' and numeric characters."
            exit 1
        }

        # Validate the format of the percentage
        if ($SystemVolumeMinFreePercent -notmatch "^\d{1,}(\.\d{1,})?\s?%?$") {
            Write-Host -Object "[Error] The minimum system volume free size percentage of '$SystemVolumeMinFreePercent' is invalid. It is in an invalid format."
            Write-Host -Object "[Error] A percentage was expected such as '33%', '77.23%' or '77.23 %'."
            exit 1
        }

        # Attempt to extract the numeric value from the percentage
        try {
            $SystemVolumeMinFreePercent = [decimal]$(($SystemVolumeMinFreePercent -replace '%').Trim())
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to extract the percentage from '$SystemVolumeMinFreePercent'"
            exit 1
        }

        # Ensure the percentage is within a valid range
        if ([decimal]$SystemVolumeMinFreePercent -le 0 -or [decimal]$SystemVolumeMinFreePercent -ge 100) {
            Write-Host -Object "[Error] The minimum system volume free size percentage of '$SystemVolumeMinFreePercent' is invalid."
            Write-Host -Object "[Error] A value between 0 and 100 is expected."
            exit 1
        }

        # Convert the percentage into bytes based on the system volume's capacity
        try {
            Write-Host -Object "Converting the minimum free space percentage '$($SystemVolumeMinFreePercent -replace "[^0-9.%]")%' required for system volumes into bytes."
            $SystemVolumeMinFreeBytes = $SystemVolume.Capacity * ([decimal]$($SystemVolumeMinFreePercent -replace "[^0-9.]") / 100)
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to convert the percentage into the minimum free space required in bytes using '$($SystemVolume.Used)' and '$($SystemVolume.Free)'."
            exit 1
        }

        # Add the calculated minimum free space requirement to the list
        $SystemVolumeMinFree.Add((
                New-Object PSObject -Property @{
                    Type           = "Minimum Percent Free"
                    Path           = $SystemVolume.Name
                    Limit          = "$($SystemVolumeMinFreePercent -replace '[^0-9.]')%"
                    MinimumInBytes = $SystemVolumeMinFreeBytes
                }
            ))
    }

    # Check if a minimum free size for the system volume is specified
    if ($SystemVolumeMinFreeSize) {
        $SystemVolumeMinFreeSize = $SystemVolumeMinFreeSize.Trim()

        # Validate that the size is not empty
        if (!($SystemVolumeMinFreeSize)) {
            Write-Host -Object "[Error] The minimum system volume free size of '$SystemVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] A value representing the amount of free space that needs to be available was expected. For example: '50GB', '50000MB', or '53687091200 Bytes'"
            exit 1
        }

        # Validate that the size contains only valid characters
        if ($SystemVolumeMinFreeSize -match "[^0-9. (PB|TB|GB|MB|KB|B|Bytes)]") {
            Write-Host -Object "[Error] The minimum system volume free size of '$SystemVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] It contains invalid characters. The only characters supported (besides whitespace) are '.', data size characters (PB, TB, GB, MB, KB, B, Bytes) and numeric characters."
            exit 1
        }

        # Validate the format of the size
        if ($SystemVolumeMinFreeSize -notmatch "^?[0-9]+\.?[0-9]*\s*(PB|TB|GB|MB|KB|B|Bytes)?$") {
            Write-Host -Object "[Error] The minimum system volume free size of '$SystemVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] It is in an invalid format. Please specify a data size such as '50GB', '50000MB', or '53687091200 Bytes'."
            exit 1
        }

        # Default to GB if no unit is specified
        if ($SystemVolumeMinFreeSize -match "^[0-9]+$") {
            $SystemVolumeMinFreeSize = "$SystemVolumeMinFreeSize" + "GB"
        }

        # Convert the size into bytes
        try {
            $SystemVolumeMinFreeBytes = ConvertTo-Bytes -FileSize $SystemVolumeMinFreeSize -DefaultTo "GB" -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to convert '$SystemVolumeMinFreeSize' to bytes. Unable to determine the minimum free space."
            exit 1
        }

        # Ensure the size is greater than 0
        if ($SystemVolumeMinFreeBytes -le 0) {
            Write-Host -Object "[Error] The minimum system volume free size of '$SystemVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] A value greater than 0 is expected."
            exit 1
        }

        # Add the calculated minimum free size requirement to the list
        Write-Host -Object "Converting the minimum free space required '$SystemVolumeMinFreeSize' for system volumes into bytes."
        $SystemVolumeMinFree.Add((
                New-Object PSObject -Property @{
                    Type           = "Minimum Free Size"
                    Path           = $SystemVolume.Name
                    Limit          = $SystemVolumeMinFreeSize
                    MinimumInBytes = $SystemVolumeMinFreeBytes
                }
            ))
    }

    # Check if a minimum percentage of free space for data volumes is specified
    if ($DataVolumeMinFreePercent) {
        $DataVolumeMinFreePercent = $DataVolumeMinFreePercent.Trim()

        # Validate that the percentage is not empty
        if (!($DataVolumeMinFreePercent)) {
            Write-Host -Object "[Error] The minimum data volume free size percentage of '$DataVolumeMinFreePercent' is invalid."
            Write-Host -Object "[Error] A percentage that is greater than 0 and less than 100 was expected."
            exit 1
        }

        # Validate that the percentage contains only valid characters
        if ($DataVolumeMinFreePercent -match "[^0-9.% ]") {
            Write-Host -Object "[Error] The minimum data volume free size percentage of '$DataVolumeMinFreePercent' is invalid."
            Write-Host -Object "[Error] It contains invalid characters. The only characters supported (besides whitespace) are '.','%' and numeric characters."
            exit 1
        }

        # Validate the format of the percentage
        if ($DataVolumeMinFreePercent -notmatch "^\d{1,}(\.\d{1,})?\s?%?$") {
            Write-Host -Object "[Error] The minimum data volume free size percentage of '$DataVolumeMinFreePercent' is invalid. It is in an invalid format."
            Write-Host -Object "[Error] A percentage was expected such as '33%', '77.23%' or '77.23 %'."
            exit 1
        }

        # Attempt to extract the numeric value from the percentage
        try {
            $DataVolumeMinFreePercent = [decimal]$(($DataVolumeMinFreePercent -replace '%').Trim())
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to extract the percentage from '$DataVolumeMinFreePercent'"
            exit 1
        }

        # Ensure the percentage is within a valid range
        if ([decimal]$DataVolumeMinFreePercent -le 0 -or [decimal]$DataVolumeMinFreePercent -ge 100) {
            Write-Host -Object "[Error] The minimum data volume free size percentage of '$DataVolumeMinFreePercent' is invalid."
            Write-Host -Object "[Error] A value between 0 and 100 is expected."
            exit 1
        }

        # Convert the percentage into bytes for each data volume
        try {
            Write-Host -Object "Converting the minimum free space percentage '$($DataVolumeMinFreePercent -replace '[^0-9.]')%' required into bytes for each data volume."
            $DataVolumes | ForEach-Object {
                # Skip volumes that are excluded
                if ($VolumesToExclude.Count -ge 1) {
                    if ($VolumesToExclude -contains $_.DriveLetter) {
                        return
                    }
    
                    if ($VolumesToExclude -contains $_.Label) {
                        return
                    }
    
                    if ($VolumesToExclude -contains $_.Name) {
                        return
                    }
                }
    
                # Skip volumes that are not included
                if ($VolumesToInclude.Count -ge 1) {
                    if ($VolumesToInclude -notcontains $_.DriveLetter -and $VolumesToInclude -notcontains $_.Label -and $VolumesToInclude -notcontains $_.Name) {
                        return
                    }
                }

                # Calculate the minimum free space in bytes for the current volume
                Write-Verbose -Message "Converting the minimum free space percentage '$($DataVolumeMinFreePercent -replace '[^0-9.]')%' required into bytes for the volume '$($_.Label)'."
                $DataVolumeMinFreeBytes = $_.Capacity * ([decimal]$($DataVolumeMinFreePercent -replace "[^0-9.]") / 100)

                # Add the calculated minimum free space requirement to the list
                $DataVolumeMinFree.Add((
                        New-Object PSObject -Property @{
                            Name           = $_.Label
                            DriveLetter    = $_.DriveLetter
                            Path           = $_.Name
                            FreeSpace      = $_.FreeSpace
                            Total          = $_.Capacity
                            Type           = "Minimum Percent Free"
                            Limit          = "$($DataVolumeMinFreePercent -replace '[^0-9.]')%"
                            MinimumInBytes = $DataVolumeMinFreeBytes
                        }
                    ))
            }
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to convert the percentage into the minimum data volume free space required in bytes."
            exit 1
        }
    }

    # Check if a minimum free size for data volumes is specified
    if ($DataVolumeMinFreeSize) {
        $DataVolumeMinFreeSize = $DataVolumeMinFreeSize.Trim()

        # Validate that the size is not empty
        if (!($DataVolumeMinFreeSize)) {
            Write-Host -Object "[Error] The minimum data volume free size of '$DataVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] A value representing the amount of free space that needs to be available was expected. For example: '50GB', '50000MB', or '53687091200 Bytes'"
            exit 1
        }

        # Validate that the size contains only valid characters
        if ($DataVolumeMinFreeSize -match "[^0-9. (PB|TB|GB|MB|KB|B|Bytes)]") {
            Write-Host -Object "[Error] The minimum data volume free size of '$DataVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] It contains invalid characters. The only characters supported (besides whitespace) are '.', data size characters (PB, TB, GB, MB, KB, B, Bytes) and numeric characters."
            exit 1
        }

        # Validate the format of the size
        if ($DataVolumeMinFreeSize -notmatch "^?[0-9]+\.?[0-9]*\s*(PB|TB|GB|MB|KB|B|Bytes)?$") {
            Write-Host -Object "[Error] The minimum data volume free size of '$DataVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] It is in an invalid format. Please specify a data size such as '50GB', '50000MB', or '53687091200 Bytes'."
            exit 1
        }

        # Default to GB if no unit is specified
        if ($DataVolumeMinFreeSize -match "^[0-9]+$") {
            $DataVolumeMinFreeSize = "$DataVolumeMinFreeSize" + "GB"
        }

        # Convert the size into bytes
        Write-Host -Object "Converting the minimum free space required '$DataVolumeMinFreeSize' for data volumes into bytes."
        try {
            $DataVolumeMinFreeBytes = ConvertTo-Bytes -FileSize $DataVolumeMinFreeSize -DefaultTo "GB" -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to convert '$DataVolumeMinFreeSize' to bytes. Unable to determine the minimum free space."
            exit 1
        }

        # Ensure the size is greater than 0
        if ($DataVolumeMinFreeBytes -le 0) {
            Write-Host -Object "[Error] The minimum data volume free size of '$DataVolumeMinFreeSize' is invalid."
            Write-Host -Object "[Error] A value greater than 0 is expected."
            exit 1
        }

        # Add the calculated minimum free size requirement to the list for each data volume
        $DataVolumes | ForEach-Object {
            # Skip volumes that are excluded
            if ($VolumesToExclude.Count -ge 1) {
                if ($VolumesToExclude -contains $_.DriveLetter) {
                    return
                }

                if ($VolumesToExclude -contains $_.Label) {
                    return
                }

                if ($VolumesToExclude -contains $_.Name) {
                    return
                }
            }

            # Skip volumes that are not included
            if ($VolumesToInclude.Count -ge 1) {
                if ($VolumesToInclude -notcontains $_.DriveLetter -and $VolumesToInclude -notcontains $_.Label -and $VolumesToInclude -notcontains $_.Name) {
                    return
                }
            }

            # Add the calculated minimum free size requirement to the list
            $DataVolumeMinFree.Add((
                    New-Object PSObject -Property @{
                        Name           = $_.Label
                        DriveLetter    = $_.DriveLetter
                        Path           = $_.Name
                        FreeSpace      = $_.FreeSpace
                        Total          = $_.Capacity
                        Type           = "Minimum Free Size"
                        Limit          = $DataVolumeMinFreeSize
                        MinimumInBytes = $DataVolumeMinFreeBytes
                    }
                ))
        }
    }

    # Check if there are any alerts for system or data volumes
    if ($SystemVolumeMinFree.Count -gt 0 -or $DataVolumeMinFree.Count -gt 0) {
        Write-Host -Object ""
    }

    # Process alerts for the system volume
    if ($SystemVolumeMinFree.Count -gt 0) {
        $SystemVolumeMinFree | ForEach-Object {
            if ($SystemVolume.FreeSpace -lt $_.MinimumInBytes) {
                # Alert if the system volume free space is below the specified limit
                Write-Host -Object "[Alert] The system volume exceeds the '$($_.Type)' limit of '$($_.Limit)'."
            }
        }
    }

    # Process alerts for data volumes
    if ($DataVolumeMinFree.Count -gt 0) {
        $DataVolumeMinFree | ForEach-Object {
            if ($_.FreeSpace -lt $_.MinimumInBytes) {
                # Alert if a data volume free space is below the specified limit
                Write-Host -Object "[Alert] The data volume labeled '$($_.Name)' exceeds the '$($_.Type)' limit of '$($_.Limit)'."
            }
        }
    }

    # Display system volume details in a human-readable format
    Write-Host -Object "`n### System Volume ###"
    try {
        # Convert system volume metrics to friendly sizes and calculate percentages
        $SystemVolumeFreeSpace = ConvertTo-FriendlySize -Bytes $SystemVolume.FreeSpace -RoundTo 2 -ErrorAction Stop
        $SystemVolumeTotal = ConvertTo-FriendlySize -Bytes $SystemVolume.Capacity -RoundTo 2 -ErrorAction Stop
        $SystemVolumeUsed = ConvertTo-FriendlySize -Bytes $($SystemVolume.Capacity - $SystemVolume.FreeSpace) -RoundTo 2 -ErrorAction Stop
        $SystemPercentFree = [System.Math]::Round((($SystemVolume.FreeSpace / $SystemVolume.Capacity) * 100), 2)
        $SystemPercentUsed = [System.Math]::Round((100 - $SystemPercentFree), 2)

        # Create a formatted object for system volume details
        $FormattedSystemVolume = New-Object PSObject -Property @{
            Name           = $SystemVolume.Label
            DriveLetter    = $SystemVolume.DriveLetter
            FileSystemType = $SystemVolume.FileSystem
            Path           = $SystemVolume.Name
            FreeSpace      = $SystemVolumeFreeSpace
            UsedSpace      = $SystemVolumeUsed
            Total          = $SystemVolumeTotal
            PercentageFree = "$SystemPercentFree%"
            PercentageUsed = "$SystemPercentUsed%"
        }

        # Output the formatted system volume details as a table
        ($FormattedSystemVolume | Format-Table -Property Name, DriveLetter, FileSystemType, FreeSpace, Total, PercentageFree -AutoSize | Out-String).Trim() | Write-Host
    }
    catch {
        # Handle errors during system volume formatting
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] Failed to convert the system volume into a human-readable table."
        exit 1
    }

    # Display data volume details in a human-readable format
    if ($DataVolumes) {
        Write-Host -Object "`n### Data Volumes ###"
        try {
            # Convert data volume metrics to friendly sizes and calculate percentages
            $FormattedDataVolumes = $DataVolumes | ForEach-Object {
                $DataVolumeFreeSpace = ConvertTo-FriendlySize -Bytes $_.FreeSpace -RoundTo 2 -ErrorAction Stop
                $DataVolumeTotal = ConvertTo-FriendlySize -Bytes $_.Capacity -RoundTo 2 -ErrorAction Stop
                $DataVolumeUsed = ConvertTo-FriendlySize -Bytes $($_.Capacity - $_.FreeSpace) -RoundTo 2 -ErrorAction Stop
                $DataVolumePercentFree = [System.Math]::Round((($_.FreeSpace / $_.Capacity) * 100), 2)
                $DataVolumePercentUsed = [System.Math]::Round((100 - $DataVolumePercentFree), 2)

                # Create a formatted object for each data volume
                New-Object PSObject -Property @{
                    Name           = $_.Label
                    DriveLetter    = $_.DriveLetter
                    FileSystemType = $_.FileSystem
                    Path           = $_.Name
                    FreeSpace      = $DataVolumeFreeSpace
                    UsedSpace      = $DataVolumeUsed
                    Total          = $DataVolumeTotal
                    PercentageFree = "$DataVolumePercentFree%"
                    PercentageUsed = "$DataVolumePercentUsed%"
                }
            }

            # Output the formatted data volume details as a list
            ($FormattedDataVolumes | Format-List -Property Name, DriveLetter, FileSystemType, Path, FreeSpace, Total, PercentageFree | Out-String).Trim() | Write-Host
        }
        catch {
            # Handle errors during data volume formatting
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to convert the data volumes into a human-readable table."
            exit 1
        }
    }

    # Update a multiline custom field with volume details and alerts
    if ($MultilineCustomField) {
        $CustomFieldValue = New-Object System.Collections.Generic.List[String]
    
        # Add system volume alerts to the custom field
        if ($SystemVolumeMinFree.Count -gt 0) {
            $SystemVolumeMinFree | ForEach-Object {
                if ($SystemVolume.FreeSpace -lt $_.MinimumInBytes) {
                    $CustomFieldValue.Add("[Alert] The system volume exceeds the '$($_.Type)' limit of '$($_.Limit)'.`n")
                }
            }
        }

        # Add data volume alerts to the custom field
        if ($DataVolumeMinFree.Count -gt 0) {
            $DataVolumeMinFree | ForEach-Object {
                if ($_.FreeSpace -lt $_.MinimumInBytes) {
                    $CustomFieldValue.Add("[Alert] The data volume labeled '$($_.Name)' exceeds the '$($_.Type)' limit of '$($_.Limit)'.`n")
                }
            }
        }

        # Add formatted volume details to the custom field
        if ($SystemVolumeMinFree.Count -gt 0 -or $DataVolumeMinFree.Count -gt 0) {
            $CustomFieldValue.Add("`n`n")
        }

        $CustomFieldValue.Add(($FormattedSystemVolume | Format-List -Property Name, DriveLetter, FileSystemType, Path, FreeSpace, Total, PercentageFree | Out-String).Trim())
        $CustomFieldValue.Add("`n`n")
        $CustomFieldValue.Add(($FormattedDataVolumes | Format-List -Property Name, DriveLetter, FileSystemType, Path, FreeSpace, Total, PercentageFree | Out-String).Trim())
    
        try {
            # Attempt to set the multiline custom field
            Write-Host -Object "`nAttempting to set Custom Field '$MultilineCustomField'."
            Set-CustomField -Name $MultilineCustomField -Value $CustomFieldValue
            Write-Host -Object "Successfully set Custom Field '$MultilineCustomField'!"
        }
        catch {
            # Handle errors during custom field update
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to set the multiline custom field."
            $ExitCode = 1
        }
    }

    # Update a WYSIWYG custom field with volume details and alerts
    if ($WYSIWYGCustomField) {
        $CustomFieldValue = New-Object System.Collections.Generic.List[object]

        # Create WYSIWYG cards for the system volume
        $FormattedSystemVolume | ForEach-Object {

            $SystemCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-hard-drive'></i>&nbsp;&nbsp;$($_.Name)</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        <div class='container'>
            <div class='row' style='flex-wrap: nowrap;'>
                <div class='col-sm'>
                    <p class='card-text'>Drive Letter: $($_.DriveLetter)</p>
                    <p class='card-text' style='white-space: nowrap;'>Path: $($_.Path)</p>
                </div>
                <div class='col-sm text-end' style='text-align: right;'>
                    <p class='card-text'>File System: $($_.FileSystemType)</p>
                </div>
            </div>
            <div class='row'>
                <div class='p-2 linechart'>
                    <div style='width: $($_.PercentageUsed); background-color: #09344F;'></div>
                    <div style='width: $($_.PercentageFree); background-color: #04FF48;'></div>
                </div>
                <ul class='unstyled p-2' style='display: flex; justify-content: space-between; '>
                    <li style='white-space: nowrap;'>
                        <span class='chart-key' style='background-color: #09344F;'></span>
                        <span>Used Space ($($_.UsedSpace) | $($_.PercentageUsed))</span>
                    </li>
                    <li style='white-space: nowrap;'>
                        <span class='chart-key' style='background-color: #04FF48;'></span>
                        <span>Free Space ($($_.FreeSpace) | $($_.PercentageFree))</span>
                    </li>
                </ul>
            </div>
            <div class='row'>
                <p class='card-text'>Total Space: $($_.Total)</p>
            </div>
        </div>
    </div>
</div>`n"

            # Highlight the card if the system volume exceeds limits
            foreach ($Volume in $SystemVolumeMinFree) {
                if ($Volume.Path -eq $_.Path -and $Volume.FreeSpace -lt $Volume.MinimumInBytes) {
                    $SystemCard = $SystemCard -replace "class='fa-solid fa-hard-drive'", "class='fa-solid fa-circle-exclamation' style='color: #C6313A;'"
                    $SystemCard = $SystemCard -replace "class='card flex-grow-1'", "class='card flex-grow-1' style='background-color: #FBEBED;'"
                }
            }

            $CustomFieldValue.Add($SystemCard)
        }

        # Create WYSIWYG cards for data volumes
        $FormattedDataVolumes | ForEach-Object {

            $DataCard = "<div class='card flex-grow-1'>
    <div class='card-title-box'>
        <div class='card-title'><i class='fa-solid fa-hard-drive'></i>&nbsp;&nbsp;$($_.Name)</div>
    </div>
    <div class='card-body' style='white-space: nowrap'>
        <div class='container'>
            <div class='row' style='flex-wrap: nowrap;'>
                <div class='col-sm'>
                    <p class='card-text'>Drive Letter: $($_.DriveLetter)</p>
                    <p class='card-text' style='white-space: nowrap;'>Path: $($_.Path)</p>
                </div>
                <div class='col-sm text-end' style='text-align: right;'>
                    <p class='card-text'>File System: $($_.FileSystemType)</p>
                </div>
            </div>
            <div class='row'>
                <div class='p-2 linechart'>
                    <div style='width: $($_.PercentageUsed); background-color: #09344F;'></div>
                    <div style='width: $($_.PercentageFree); background-color: #04FF48;'></div>
                </div>
                <ul class='unstyled p-2' style='display: flex; justify-content: space-between; '>
                    <li style='white-space: nowrap;'>
                        <span class='chart-key' style='background-color: #09344F;'></span>
                        <span>Used Space ($($_.UsedSpace) | $($_.PercentageUsed))</span>
                    </li>
                    <li style='white-space: nowrap;'>
                        <span class='chart-key' style='background-color: #04FF48;'></span>
                        <span>Free Space ($($_.FreeSpace) | $($_.PercentageFree))</span>
                    </li>
                </ul>
            </div>
            <div class='row'>
                <p class='card-text'>Total Space: $($_.Total)</p>
            </div>
        </div>
    </div>
</div>`n"

            # Highlight the card if the data volume exceeds limits
            foreach ($Volume in $DataVolumeMinFree) {
                if ($Volume.Path -eq $_.Path -and $Volume.FreeSpace -lt $Volume.MinimumInBytes) {
                    $DataCard = $DataCard -replace "class='fa-solid fa-hard-drive'", "class='fa-solid fa-circle-exclamation' style='color: #C6313A;'"
                    $DataCard = $DataCard -replace "class='card flex-grow-1'", "class='card flex-grow-1' style='background-color: #FBEBED;'"
                }
            }

            $CustomFieldValue.Add($DataCard)
        }

        try {
            # Attempt to set the WYSIWYG custom field
            Write-Host -Object "`nAttempting to set Custom Field '$WYSIWYGCustomField'."
            Set-CustomField -Name $WYSIWYGCustomField -Value $CustomFieldValue
            Write-Host -Object "Successfully set Custom Field '$WYSIWYGCustomField'!"
        }
        catch {
            # Handle errors during custom field update
            Write-Host -Object "[Error] $($_.Exception.Message)"
            Write-Host -Object "[Error] Failed to set the WYSIWYG custom field."
            $ExitCode = 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}
