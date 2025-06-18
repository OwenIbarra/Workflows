# Reports on whether Credential Guard is configured and running on a given device.
#Requires -Version 5.1

<#
.SYNOPSIS
    Reports on whether Credential Guard is configured and running on a given device.
.DESCRIPTION
    Reports on whether Credential Guard is configured and running on a given device.

.EXAMPLE
    (No Parameters)

    CredentialGuardConfiguration CredentialGuardRunning
    ---------------------------- ----------------------
    Enabled without UEFI lock    Running

.EXAMPLE
    -TextCustomFieldName "Test"

    [Info] Attempting to set Ninja custom field Text...
    [Info] Successfully set Ninja custom field Text to value 'Enabled without UEFI lock | Running'.

    CredentialGuardConfiguration CredentialGuardRunning
    ---------------------------- ----------------------
    Enabled without UEFI lock    Running

.PARAMETER -TextCustomFieldName
    Name of the text custom field where Credential Guard information will be stored.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows 11, Windows Server 2016+
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$TextCustomFieldName
)

begin {
    if ($env:TextCustomFieldName -and $TextCustomFieldName -ne 'null'){
        $TextCustomFieldName = $env:TextCustomFieldName
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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

    function Test-IsCredentialGuardRunning {
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            $CGRunning = (Get-WmiObject -Class Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning
        }
        else {
            $CGRunning = (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue).SecurityServicesRunning
        }

        # if 1 is present, Credential Guard is running per https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=security
        if ($CGRunning -contains 1){
            return $true
        }
        else{
            return $false
        }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }
    
    $ExitCode = 0

    # check if running on supported OS
    $OS = try{
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        }
        else {
            Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        }   
    }
    catch{
        Write-Host "[Error] Error retrieving operating system information."
        Write-Host "$($_.Exception.Message)"
        exit 1
    }

    # assume supported OS, below checks will be used to negate it if needed
    $supportedOS = $true

    if ($OS.Caption -match "Windows (10|11)" -and $OS.Caption -notmatch "Enterprise|Education"){
        # if this registry value is not null on Windows 10/11 Pro, then this may have been a downgrade from Enterprise/Education, and the OS is supported in that case
        # see the note here: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
        $regKeyValue = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -ErrorAction SilentlyContinue).IsolatedCredentialsRootSecret

        if ([string]::IsNullOrWhiteSpace($regKeyValue)){
            $supportedOS = $false
        }
    }
    elseif ($OS.Caption -notmatch "Windows.+(Enterprise|Education|Server (2016|2019|[2-9]0[2-9][0-9]))"){
        # otherwise, if device is not Enterprise/Education/Server 2016+, the OS is not supported
        $supportedOS = $false
    }

    # error if not running on supported OS
    if (-not $supportedOS){
        Write-Host "[Error] Credential Guard is not supported on this OS."
        Write-Host "Script supports:"
        Write-Host " - Windows 10 and 11, Enterprise or Education edition"
        Write-Host " - Windows Server 2016 and above"
        Write-Host "See more info on prerequisites here: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/"

        # write to custom field if specified
        if ($TextCustomFieldName){
            $value = "Incompatible with System"
            # attempt custom field write
            try {
                Write-Host "`n[Info] Attempting to set Ninja custom field $TextCustomFieldName..."
                Set-NinjaProperty -Name $TextCustomFieldName -Type "Text" -Value $value -ErrorAction Stop
                Write-Host "[Info] Successfully set Ninja custom field $TextCustomFieldName to value '$value'."
            }
            catch {
                Write-Host "[Error] Error setting custom field $TextFieldCustomName to value '$value'."
                Write-Host "$($_.Exception.Message)"
                $ExitCode = 1
            }
        }
        exit $ExitCode
    }

    # if OS is supported, continue with checks
    # check if Credential Guard is running
    try {
        if (Test-IsCredentialGuardRunning){
            $CGRunningStatus = "Running"
        }
        else{
            $CGRunningStatus = "Not running"
        }
    }
    catch {
        Write-Host "[Error] Error getting Credential Guard running status."
        Write-Host "$($_.Exception.Message)"
        $CGRunningStatus = "Error"
        $ExitCode = 1
    }

    # check if Credential Guard is configured
    try {
        $CGConfiguration = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop).LsaCfgFlags

        # if nothing present for custom regkey, check default regkey
        if ($null -eq $CGConfiguration){
            $CGConfiguration = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction Stop).LsaCfgFlagsDefault
        }
    }
    catch{
        Write-Host "[Error] Error when testing if Credential Guard is enabled in the registry."
        Write-Host "$($_.Exception.Message)"
        $ExitCode = 1
    }
    
    # translate value into readable text for output
    $CGConfigurationStatus = switch ($CGConfiguration){
        0 { "Disabled" }
        1 { "Enabled with UEFI lock" }
        2 { "Enabled without UEFI lock" }
        default { "Unable to Determine" }
    }

    # write result to custom field if specified
    if ($TextCustomFieldName){
        $value = "$CGConfigurationStatus | $CGRunningStatus"
        # attempt custom field write
        try {
            Write-Host "`n[Info] Attempting to set Ninja custom field $TextCustomFieldName..."
            Set-NinjaProperty -Name $TextCustomFieldName -Type "Text" -Value $value -ErrorAction Stop
            Write-Host "[Info] Successfully set Ninja custom field $TextCustomFieldName to value '$value'."
        }
        catch {
            Write-Host "[Error] Error setting custom field $TextFieldCustomName to value '$value'."
            Write-Host "$($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # warn if CG is configured to be disabled but is still running
    if ($CGConfigurationStatus -eq "Disabled" -and $CGRunningStatus -eq "Running"){
        Write-Host "`n[Warning] Credential Guard is disabled in the registry but currently running."
        Write-Host "You may need to restart $env:computername, or Credential Guard is UEFI locked and needs to be reset."
        Write-Host "See more information here: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=intune#disable-credential-guard-with-uefi-lock"
    }

    [PSCustomObject]@{
        "CredentialGuardConfiguration" = $CGConfigurationStatus
        "CredentialGuardRunning" = $CGRunningStatus
    } | Format-Table -AutoSize | Out-String | Write-Host

    exit $ExitCode
}
end {
    
    
    
}
