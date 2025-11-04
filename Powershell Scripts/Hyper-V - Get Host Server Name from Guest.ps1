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
    # $Value = $Value -replace ' ', '&nbsp;' # Removed NinjaOne dependency
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
    # Set-NinjaProperty -Name $TextCustomFieldName -Type "Text" -Value $HyperVHost -ErrorAction Stop # Removed NinjaOne dependency
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
