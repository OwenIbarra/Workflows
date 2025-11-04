# Checks if the workstation currently allows access to USB storage devices and optionally saves the results to a custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Checks if the workstation currently allows access to USB storage devices and optionally saves the results to a custom field.
.DESCRIPTION
    Checks if the workstation currently allows access to USB storage devices and optionally saves the results to a custom field.
    
.EXAMPLE
    -CustomField "usbStorageStatus"
    
    Checking if the USB Mass Storage Driver service is enabled.
    Checking if the USB Mass Storage Driver is disabled via the registry.
    Checking if USB is disabled via group policy.

    USB is currently disabled.

    Attempting to set Custom Field 'usbStorageStatus'.
    Successfully set Custom Field 'usbStorageStatus'!

.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomField
)

begin {
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }

    if ($CustomField) {
        $CustomField = $CustomField.Trim()
    }

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
    # [String]$DocumentName, # Removed NinjaOne dependency
    # [Parameter()] # Removed NinjaOne dependency
    # [Switch]$Piped # Removed NinjaOne dependency
    # ) # Removed NinjaOne dependency
    # # Remove the non-breaking space character # Removed NinjaOne dependency
    # if ($Type -eq "WYSIWYG") { # Removed NinjaOne dependency
    # $Value = $Value -replace 'Â ', '&nbsp;' # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
        
    # # Measure the number of characters in the provided value # Removed NinjaOne dependency
    # $Characters = $Value | ConvertTo-Json | Measure-Object -Character | Select-Object -ExpandProperty Characters # Removed NinjaOne dependency
    
    # # Throw an error if the value exceeds the character limit of 200,000 characters # Removed NinjaOne dependency
    # if ($Piped -and $Characters -ge 200000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.") # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    
    # if (!$Piped -and $Characters -ge 45000) { # Removed NinjaOne dependency
    # throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 45,000 characters.") # Removed NinjaOne dependency
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
    # try { # Removed NinjaOne dependency
    # # Otherwise, set the standard property value # Removed NinjaOne dependency
    # if ($Piped) { # Removed NinjaOne dependency
    # $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # catch { # Removed NinjaOne dependency
    # Write-Host -Object "[Error] Failed to set custom field." # Removed NinjaOne dependency
    # throw $_.Exception.Message # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
            
    # # Throw an error if setting the property failed # Removed NinjaOne dependency
    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated (Administrator) privileges.
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Notify that the script is checking if the USB Mass Storage Driver service is enabled.
    Write-Host -Object "Checking if the USB Mass Storage Driver service is enabled."

    try {
        $USBService = Get-Service -Name "USBStor" -ErrorAction Stop
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    # If the USB Mass Storage Driver service was not found, print an error message and exit.
    if (!$USBService) {
        Write-Host -Object "[Error] Accessing the 'USB Mass Storage Driver' service status."

        if ($CustomField) {
            try {
                Write-Host -Object "Attempting to set Custom Field '$CustomField'."
    # Set-NinjaProperty -Name $CustomField -Value "Unable to Determine" # Removed NinjaOne dependency
                Write-Host -Object "Successfully set Custom Field '$CustomField'!"
            }
            catch {
                Write-Host "[Error] $($_.Exception.Message)"
            }
        }
        exit 1
    }

    # Notify that the script is checking if the USB Mass Storage Driver is disabled via the registry.
    Write-Host -Object "Checking if the USB Mass Storage Driver is disabled via the registry."

    # Check if the registry path for the USB Mass Storage Driver exists.
    if (!(Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\USBSTOR")) {
        Write-Host -Object "[Error] The 'USB Mass Storage Driver' Service is missing it's registry key."

        if ($CustomField) {    
            try {
                Write-Host -Object "Attempting to set Custom Field '$CustomField'."
    # Set-NinjaProperty -Name $CustomField -Value "Unable to Determine" # Removed NinjaOne dependency
                Write-Host -Object "Successfully set Custom Field '$CustomField'!"
            }
            catch {
                Write-Host "[Error] $($_.Exception.Message)"
            }
        }
        exit 1
    }

    # Get the registry value for the USB Mass Storage Driver service start type.
    $USBRegKey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\USBSTOR" -Name "Start" | Select-Object -ExpandProperty Start

    # Notify that the script is checking if USB is disabled via group policy.
    Write-Host -Object "Checking if USB is disabled via group policy."

    # Check if the group policy registry path for removable usb devices exists.
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" -ErrorAction SilentlyContinue) {
        $USBPolicyRegKey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}"

        # If all group policy settings deny read, write, and execute access, set the USB policy status to "Disabled".
        if ($USBPolicyRegKey.Deny_Read -eq 1 -and $USBPolicyRegKey.Deny_Write -eq 1 -and $USBPolicyRegKey.Deny_Execute -eq 1) {
            $USBPolicy = "Disabled"
        }
    
    }

    # Check if the group policy registry path for all removable storage devices exists.
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices" -ErrorAction SilentlyContinue) {
        $USBPolicyRegKey = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\RemovableStorageDevices"

        # If group olicy is set to deny all removable devices, set the USB policy status to "Disabled".
        if ($USBPolicyRegKey.Deny_All -eq 1) {
            $USBPolicy = "Disabled"
        }
    
    }

    try {
        # If the USB service is disabled, the registry value indicates it is disabled, or the group policy disables it, set the custom field to "Disabled".
        if ($USBService.StartType -eq "Disabled" -or $USBRegKey -eq 4 -or $USBPolicy -eq "Disabled") {
            Write-Host -Object "`nUSB is currently disabled.`n"

            if ($CustomField) {
                Write-Host -Object "Attempting to set Custom Field '$CustomField'."
    # Set-NinjaProperty -Name $CustomField -Value "Disabled" # Removed NinjaOne dependency
                Write-Host -Object "Successfully set Custom Field '$CustomField'!"
            }
        }
        else {
            # If none of the conditions indicate the USB is disabled, set the custom field to "Enabled".
            Write-Host -Object "`nUSB is currently enabled.`n"

            if ($CustomField) {
                Write-Host -Object "Attempting to set Custom Field '$CustomField'."
    # Set-NinjaProperty -Name $CustomField -Value "Enabled" # Removed NinjaOne dependency
                Write-Host -Object "Successfully set Custom Field '$CustomField'!"
            }
        }
    }
    catch {
        # Catch any exceptions that occur and print an error message.
        Write-Host "[Error] $($_.Exception.Message)"
        $ExitCode = 1
    }

    # Exit the script with the appropriate exit code.
    exit $ExitCode
}
end {
    
    
    
}
