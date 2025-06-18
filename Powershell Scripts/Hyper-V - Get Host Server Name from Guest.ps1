# Reports on the hypervisor hostname of a guest VM. Must be ran on a Hyper-V guest VM.
#Requires -Version 3

<#
.SYNOPSIS
    Reports on the hypervisor hostname of a guest VM. Must be ran on a Hyper-V guest VM.
.DESCRIPTION
    Reports on the hypervisor hostname of a guest VM. Must be ran on a Hyper-V guest VM.

.PARAMETER -TextCustomFieldName
    Enter the text custom field name where the hypervisor hostname will be saved.

.EXAMPLE
    (No Parameters)
    
    [Info] WIN11-EDUCATION is hosted on: HYPERV-HOST-1

.EXAMPLE
    -TextCustomFieldName "text"
    
    [Info] Attempting to set Ninja custom field 'text'...
    [Info] Successfully set Ninja custom field 'text' to value 'HYPERV-HOST-1'.

    [Info] WIN11-EDUCATION is hosted on: HYPERV-HOST-1

.NOTES
    Minimum OS Architecture Supported: Windows 8, Windows Server 2012
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$TextCustomFieldName
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsVM {
        try {
            # first test via model. Hyper-V and VMWare sets these properties automatically and they are read-only
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                $model = (Get-WmiObject -Class Win32_ComputerSystem -Property Model -ErrorAction Stop).Model
            }
            else {
                $model = (Get-CimInstance -ClassName Win32_ComputerSystem -Property Model -ErrorAction Stop).Model
            }

            # Hyper-V uses "Virtual Machine" VMWare uses "VM"
            if ($model -match "Virtual|VM"){
                return $true
            }
            else{
                # Proxmox can be identified via the manufacturer
                if ($PSVersionTable.PSVersion.Major -lt 3) {
                    $manufacturer = (Get-WmiObject -Class Win32_BIOS -Property Manufacturer -ErrorAction Stop).Manufacturer
                }
                else {
                    $manufacturer = (Get-CimInstance -Class Win32_BIOS -Property Manufacturer -ErrorAction Stop).Manufacturer
                }

                if ($manufacturer -match "Proxmox"){
                    return $true
                }
                else{
                    return $false
                }
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a VM."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    if (-not (Test-IsVM)){
        Write-Host "[Error] Host is not a virtual machine."
        exit 1
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
            [String]$DocumentName,
            [Parameter()]
            [Switch]$Piped
        )
        # Remove the non-breaking space character
        if ($Type -eq "WYSIWYG") {
            $Value = $Value -replace ' ', '&nbsp;'
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
                Write-Host -Object "[Error] Failed to set custom field."
                throw $_.Exception.Message
            }
        }
            
        # Throw an error if setting the property failed
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    if ($env:TextCustomFieldName -and $env:TextCustomFieldName -notlike ''){
        $TextCustomFieldName = $env:TextCustomFieldName
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    $ExitCode = 0

    $regPath = "HKLM:\Software\Microsoft\Virtual Machine\Guest\Parameters"

    Write-Host ""

    # if regPath is not present, error out
    if (-not (Test-Path $regPath)){
        Write-Host "[Error] Registry key cannot be found. This either means that $env:computername is not a Hyper-V guest, or the 'Data Exchange' integration is disabled in the VM settings."
        exit 1
    }

    # if registry key exists, get value of property
    $HyperVHost = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).PhysicalHostName

    if ([string]::IsNullOrWhiteSpace($HyperVHost)){
        Write-Host "[Error] Registry key exists but the value is blank.`n"
        exit 1
    }
    else{
        Write-Host "[Info] $env:computername is hosted on: $HyperVHost"
    }

    # write to custom field if value is supplied
    if ($TextCustomFieldName){

        # attempt custom field write
        try {
            Write-Host "[Info] Attempting to set Ninja custom field '$TextCustomFieldName'..."
            Set-NinjaProperty -Name $TextCustomFieldName -Type "Text" -Value $HyperVHost -ErrorAction Stop
            Write-Host "[Info] Successfully set Ninja custom field '$TextCustomFieldName' to value '$HyperVHost'.`n"
        }
        catch {
            Write-Host "[Error] Error setting custom field '$TextCustomFieldName' to value '$HyperVHost'."
            Write-Host "$($_.Exception.Message)"
            Write-Host ""
            $ExitCode = 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}
