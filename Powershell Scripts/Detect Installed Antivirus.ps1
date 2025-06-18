# Detect the antivirus software currently installed and set the relevant custom fields accordingly. This script is a best effort and should be treated as such; we recommend verifying any results. Supports 19 antivirus solutions on Windows Server.
#Requires -Version 5.1

<#
.SYNOPSIS
    Detect the antivirus software currently installed and set the relevant custom fields accordingly. This script is a best effort and should be treated as such; we recommend verifying any results. Supports 19 antivirus solutions on Windows Server.
.DESCRIPTION
    Detect the antivirus software currently installed and set the relevant custom fields accordingly. This script is a best effort and should be treated as such; we recommend verifying any results. Supports 19 antivirus solutions on Windows Server.
.EXAMPLE
    Attempting to set the custom field 'WYSIWYG'.
    Successfully set the custom field 'WYSIWYG'!

    Attempting to set the custom field 'antivirusName'.
    Successfully set the custom field 'antivirusName'!

    Attempting to set the custom field 'definitionDateAndStatus'.
    Successfully set the custom field 'definitionDateAndStatus'!

    Antivirus Name   Status  Definition Status Definition Date
    --------------   ------  ----------------- ---------------
    MalwareBytes     Running Up-To-Date        11/13/2024     
    Windows Defender Running Up-To-Date        11/13/2024

Supported Antivirus Detections: Avast Antivirus, AVG Antivirus Business Edition, Bitdefender Endpoint Security Antimalware, CrowdStrike, Cylance,
Elastic Defend, ESET Security, F-Secure, Huntress, Kaspersky Endpoint Security for Windows, Kaspersky Small Office Security, MalwareBytes, Sentinel
Agent, Sophos Intercept X, Trend Micro Maximum Security, Trend Micro Security Agent, VIPRE Business Agent, Webroot SecureAnywhere, and Windows Defender.

PARAMETER: -DaysUntilConsideredOutdated "7"
    Specify the number of days until the definitions are considered 'out-of-date'.

PARAMETER: -WYSIWYGCustomField "ReplaceMeWithNameOfWYSIWYGCustomField"
    Name of the WYSIWYG custom field to export all results to.

PARAMETER: -NameCustomField "ReplaceMeWithNameOfTextCustomField"
    Name of the text custom field to export the names of the detected antiviruses.

PARAMETER: -StatusCustomField "ReplaceMeWithNameOfTextCustomField"
    Name of the text custom field to export the current antivirus status.

PARAMETER: -DefinitionDateAndStatusCustomField "ReplaceMeWithNameOfTextCustomField"
    Name of the text custom field to export the antivirus definition date and indicate if they are 'Up-To-Date'.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Enhanced detection of installed antivirus software, simplified script options, and streamlined custom field settings. Removed the detection of Carbon Black.
#>

[CmdletBinding()]
param (
    [Parameter()]
    $DaysUntilConsideredOutdated = "7",
    [Parameter()]
    [String]$WYSIWYGCustomField,
    [Parameter()]
    [String]$NameCustomField,
    [Parameter()]
    [String]$StatusCustomField,
    [Parameter()]
    [String]$DefinitionDateAndStatusCustomField
)

begin {
    # If script form variables are used, replace the command line parameters with their value.
    if ($env:daysConsideredOutdated -and $env:daysConsideredOutdated -notlike "null") { $DaysUntilConsideredOutdated = $env:daysConsideredOutdated }
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $WYSIWYGCustomField = $env:wysiwygCustomFieldName }
    if ($env:antivirusNameCustomField -and $env:antivirusNameCustomField -notlike "null") { $NameCustomField = $env:antivirusNameCustomField }
    if ($env:statusCustomFieldName -and $env:statusCustomFieldName -notlike "null") { $StatusCustomField = $env:statusCustomFieldName }
    if ($env:definitionDateAndStatusCustomField -and $env:definitionDateAndStatusCustomField -notlike "null") { $DefinitionDateAndStatusCustomField = $env:definitionDateAndStatusCustomField }

    # Trim leading and trailing whitespace from each specified variable, if it is set
    if($DaysUntilConsideredOutdated) { $DaysUntilConsideredOutdated = $DaysUntilConsideredOutdated.Trim() }
    if($WYSIWYGCustomField){ $WYSIWYGCustomField = $WYSIWYGCustomField.Trim() }
    if($NameCustomField){ $NameCustomField = $NameCustomField.Trim() }
    if($StatusCustomField){ $StatusCustomField = $StatusCustomField.Trim() }
    if($DefinitionDateAndStatusCustomField){ $DefinitionDateAndStatusCustomField = $DefinitionDateAndStatusCustomField.Trim() }

    # Check if the $DaysUntilConsideredOutdated variable is not set or null
    # Display an error message and exit if it is not set
    if (!$DaysUntilConsideredOutdated) {
        Write-Host -Object "[Error] Please specify a valid definition age limit that is a positive whole number greater than 0."
        exit 1
    }

    # Validate that $DaysUntilConsideredOutdated contains only numeric characters
    if ($DaysUntilConsideredOutdated -match "[^0-9]") {
        Write-Host -Object "[Error] An invalid definition age limit of '$DaysUntilConsideredOutdated' was specified. Please specify a positive whole number greater than 0."
        exit 1
    }

    # Attempt to convert $DaysUntilConsideredOutdated to a long integer
    try {
        $ErrorActionPreference = "Stop"
        $DaysUntilConsideredOutdated = [long]$DaysUntilConsideredOutdated
        $ErrorActionPreference = "Continue"
    }
    catch {
        Write-Host -Object "[Error] $($_.Exception.Message)"
        Write-Host -Object "[Error] An invalid definition age limit of '$DaysUntilConsideredOutdated' was specified. Unable to convert '$DaysUntilConsideredOutdated' to an integer."
        exit 1
    }

    # Check if the value of $DaysUntilConsideredOutdated is less than 1
    if ([long]$DaysUntilConsideredOutdated -lt 1) {
        Write-Host -Object "[Error] An invalid definition age limit of '$DaysUntilConsideredOutdated' was specified. Please specify a positive whole number greater than 0."
        exit 1
    }

    # Define a function to check if the current system is a server
    function Test-IsServer {
        # Determine the method to retrieve the operating system information based on PowerShell version
        try {
            $OS = if ($PSVersionTable.PSVersion.Major -lt 3) {
                Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            }
            else {
                Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a server."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    
        # Check if the ProductType is "2", which indicates that the system is a domain controller or is a server
        if ($OS.ProductType -eq "2" -or $OS.ProductType -eq "3") {
            return $true
        }
    }

    # Define a function to check if the script is running with elevated privileges
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Define a function to find the installation key of a specified program
    function Find-InstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString,
            [Parameter()]
            [String]$UserBaseKey
        )
        process {
            # Initialize a list to store found installation keys
            $InstallList = New-Object System.Collections.Generic.List[Object]
    
            # If no custom user base key is provided, search in the standard HKLM paths
            if (!$UserBaseKey) {
                $ErrorActionPreference = "Stop"
                # Search in the 32-bit uninstall registry key and add results to the list
                try {
                    $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at 'HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }
    
                # Search in the 64-bit uninstall registry key and add results to the list
                try {
                    $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }

                $ErrorActionPreference = "Continue"
            }
            else {
                $ErrorActionPreference = "Stop"
                # If a custom user base key is provided, search in the corresponding Wow6432Node path and add results to the list
                try {
                    $Result = Get-ChildItem -Path "$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at '$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }

                try {
                    # Search in the custom user base key for the standard uninstall path and add results to the list
                    $Result = Get-ChildItem -Path "$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                    if ($Result) { $InstallList.Add($Result) }
                }
                catch {
                    Write-Host -Object "[Error] $($_.Exception.Message)"
                    Write-Host -Object "[Error] Failed to retrieve registry keys at '$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'."
                    exit 1
                }

                $ErrorActionPreference = "Continue"
            }
    
            # If the UninstallString switch is set, return only the UninstallString property of the found keys
            if ($UninstallString) {
                $InstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $InstallList
            }
        }
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
            $Value = $Value -replace 'Â ', '&nbsp;'
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

    # Define an array of custom objects representing different antivirus software to check
    $AVsToCheck = @(
        [PSCustomObject]@{ Name = "Avast Antivirus" ; ControlPanelName = "Avast Free Antivirus" ; InstallPath = "$env:ProgramFiles\Avast Software\Avast" ; RelevantProcesses = "AvastSvc", "aswEngSrv" ; RelevantServices = 'avast! Antivirus' }
        [PSCustomObject]@{ Name = "AVG Antivirus Business Edition" ; ControlPanelName = "AVG Business Security" ; InstallPath = "$env:ProgramFiles\AVG\Antivirus" ; RelevantProcesses = "AVGSvc", "avgToolsSvc", "bcc", "bccavsvc" ; RelevantServices = "AVG Antivirus", "avgBcc", "AVG Business Console Client Antivirus Service" }
        [PSCustomObject]@{ Name = "Bitdefender Endpoint Security Antimalware" ; ControlPanelName = "Bitdefender Endpoint Security Tools", "Bitdefender Agent" ; InstallPath = "$env:ProgramFiles\Bitdefender\Endpoint Security" ; RelevantProcesses = "EPSecurityService", "EPProtectedService" ; RelevantServices = "EPSecurityService", "EPProtectedService" }
        [PSCustomObject]@{ Name = "CrowdStrike" ; ControlPanelName = "CrowdStrike Windows Sensor" ; InstallPath = "$env:ProgramFiles\CrowdStrike" ; RelevantProcesses = "CSFalconService" ; RelevantServices = "CSFalconService" }
        [PSCustomObject]@{ Name = "Cylance"; ControlPanelName = "Cylance OPTICS", "Cylance Smart Antivirus", "Cylance PROTECT"; InstallPath = "$env:ProgramFiles\Cylance" }
        [PSCustomObject]@{ Name = "Elastic Defend" ; ControlPanelName = "Elastic Agent" ; RelevantProcesses = "elastic-agent", "elastic-endpoint" ; RelevantServices = "Elastic Agent", "ElasticEndpoint" }
        [PSCustomObject]@{ Name = "ESET Security" ; ControlPanelName = "ESET Security", "ESET Server Security" ; InstallPath = "$env:ProgramFiles\ESET\ESET Security" ; RelevantProcesses = "ekrn" ; RelevantServices = "ekrn", "efwd" }
        [PSCustomObject]@{ Name = "F-Secure" ; ControlPanelName = "F-Secure" ; InstallPath = "$env:ProgramFiles\F-Secure" ; RelevantProcesses = "fshoster64" ; RelevantServices = "fshoster" }
        [PSCustomObject]@{ Name = "Huntress" ; ControlPanelName = "Huntress Agent" ; InstallPath = "$env:ProgramFiles\Huntress" ; RelevantProcesses = "HuntressAgent", "HuntressRio" ; RelevantServices = "HuntressAgent", "HuntressRio" }
        [PSCustomObject]@{ Name = "Kaspersky Endpoint Security for Windows" ; ControlPanelName = "Kaspersky Endpoint Security" ; InstallPath = "${env:ProgramFiles(x86)}\Kaspersky Lab\KES*" ; RelevantProcesses = "avp" ; RelevantServices = "AVP.KES*" }
        [PSCustomObject]@{ Name = "Kaspersky Small Office Security" ; ControlPanelName = "Kaspersky Small Office Security" ; InstallPath = "${env:ProgramFiles(x86)}\Kaspersky Lab\Kaspersky Small Office Security*" ; RelevantProcesses = "avp" ; RelevantServices = "AVP*.*" }
        [PSCustomObject]@{ Name = "MalwareBytes" ; InstallPath = "$env:ProgramFiles\Malwarebytes\Anti-Malware" ; ControlPanelName = "Malwarebytes" ; RelevantProcesses = "Malwarebytes" ; RelevantServices = "MBAMService" }
        [PSCustomObject]@{ Name = "Sentinel Agent" ; ControlPanelName = "Sentinel Agent" ; InstallPath = "$env:ProgramFiles\SentinelOne" ; RelevantProcesses = "SentinelServiceHost", "SentinelStaticEngine", "SentinelStaticEngineScanner" ; RelevantServices = "SentinelAgent", "SentinelHelperService", "SentinelStaticEngine" }
        [PSCustomObject]@{ Name = "Sophos Intercept X" ; ControlPanelName = "Sophos Endpoint Agent", "Sophos Endpoint Defense" ; InstallPath = "$env:ProgramFiles\Sophos\Sophos Endpoint Agent", "$env:ProgramFiles\Sophos\Endpoint Defense" ; RelevantProcesses = "SophosFileScanner", "SophosFS" ; RelevantServices = "Sophos Endpoint Defense Service", "Sophos System Protection Service" }
        [PSCustomObject]@{ Name = "Trend Micro Maximum Security" ; ControlPanelName = "Trend Micro Maximum Security" ; InstallPath = "$env:ProgramFiles\Trend Micro" ; RelevantProcesses = "coreServiceShell" ; RelevantServices = "Amsp" }
        [PSCustomObject]@{ Name = "Trend Micro Security Agent" ; ControlPanelName = "Trend Micro Worry-Free Business Security Agent" ; InstallPath = "${env:ProgramFiles(x86)}\Trend Micro\Security Agent" ; RelevantProcesses = "NTRTScan", "TmListen" ; RelevantServices = "ntrtscan", "TmCCSF" }
        [PSCustomObject]@{ Name = "VIPRE Business Agent" ; ControlPanelName = "VIPRE Business Agent" ; InstallPath = "$env:ProgramFiles\VIPRE Business Agent" ; RelevantProcesses = "SBAMSvc" ; RelevantServices = "SBAMSvc" }
        [PSCustomObject]@{ Name = "Webroot SecureAnywhere"; DisplayName = "Webroot SecureAnywhere" ; InstallPath = "$env:ProgramFiles\Webroot" ; RelevantProcesses = "WRSA" ; RelevantServices = "WRCoreService", "WRSkyClient", "WRSVC" }
        [PSCustomObject]@{ Name = "Windows Defender" ; RelevantProcesses = "MsMpEng" ; RelevantServices = "WinDefend" }
    )

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Create a new list to store detected antivirus information
    $DetectedAVs = New-Object System.Collections.Generic.List[object]

    # Check if the current system is not a server
    if (!(Test-IsServer)) {
        # Get antivirus products from the Security Center namespace based on PowerShell version
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            $AVsInSecurityCenter = Get-WmiObject -Namespace root/SecurityCenter2 -Class AntivirusProduct
        }
        else {
            $AVsInSecurityCenter = Get-CimInstance -Namespace root/SecurityCenter2 -Class AntivirusProduct
        }

        # Iterate over each antivirus product found
        $AVsInSecurityCenter | ForEach-Object {
            $AVsToSkip = "Kaspersky SmallÂ OfficeÂ Security", "AVG Antivirus"
            if ($AVsToSkip -contains $_.displayName -or $AVsToCheck.Name -contains $_.displayName) {
                return
            }

            # Define enumerations with flag attributes for product states, signature statuses, product owners, and product flags
            [Flags()] enum ProductState {
                Off = 0x0000
                On = 0x1000
                Snoozed = 0x2000
                Expired = 0x3000
                CustomState = 0x4000 
            }

            [Flags()] enum SignatureStatus {
                UpToDate = 0x00
                OutOfDate = 0x10
            }

            [Flags()] enum ProductOwner {
                NonMs = 0x000
                Windows = 0x100
            }

            [Flags()] enum ProductFlags {
                SignatureStatus = 0x00F0
                ProductOwner = 0x0F00
                ProductState = 0xF000
            }

            # Get the current product state
            [UInt32]$CurrentState = $_.ProductState

            try {
                # Decode the product state and signature status by masking the relevant bits and converting
                $ProductState = [ProductState]($CurrentState -band [ProductFlags]::ProductState)
                $SignatureStatus = [SignatureStatus]($CurrentState -band [ProductFlags]::SignatureStatus)
            }
            catch {
                Write-Host "[Error] Translating the product state for '$($_.DisplayName)' with a product state of '$CurrentState'."
            }

            # Determine the running status based on the product state
            $RunningStatus = switch ($ProductState) {
                "On" { "Running" }
                default { "Not Running" }
            }

            # Determine if the definitions are up to date based on the hexadecimal value
            $UpToDateWMI = switch ($SignatureStatus) {
                "UpToDate" { $True }
                default { $False }
            }

            # Get the date of the last definition update
            $DefinitionsDate = Get-Date $_.timestamp -ErrorAction SilentlyContinue

            # Determine if the antivirus definitions are up to date based on the date and WMI status
            $UpToDate = if ($DefinitionsDate -and $DefinitionsDate -gt (Get-Date).AddDays(-$DaysUntilConsideredOutdated) -and ($UpToDateWMI -like "True")) {
                "Up To Date"
            }
            else {
                "Outdated"
            }

            # Add the antivirus information to the detected list as a custom object
            if ($Installed) {
                $DetectedAVs.Add(
                    [PSCustomObject]@{
                        "Antivirus Name"    = $_.DisplayName
                        Status              = $RunningStatus
                        "Definition Status" = $UpToDate
                        "Definition Date"   = if ($DefinitionsDate) { "$($DefinitionsDate.ToShortDateString())" }
                    }
                )
            }
        }
    }

    # Iterate through each antivirus in the $AVsToCheck array
    foreach ($AntiVirus in $AVsToCheck) {
        $InstallationKey = $null
        $InstallPathExists = $null
        $RunningServices = $null
        $RunningProcesses = $null
        $DefinitionStatus = $null
        $DefinitionDate = $null
        $installed = $Null

        # Find installation key based on ControlPanelName if available
        if ($AntiVirus.ControlPanelName) {
            $InstallationKey = $AntiVirus.ControlPanelName | ForEach-Object { Find-InstallKey -DisplayName $_ }
        }

        # Check if the install path exists for the antivirus
        if ($AntiVirus.InstallPath) {
            $InstallPathExists = $AntiVirus.InstallPath | ForEach-Object { 
                if (Test-Path -Path $_ -ErrorAction SilentlyContinue) { 
                    $InstallPathInfo = (Get-Item -Path $_ -ErrorAction SilentlyContinue)

                    if (!$InstallPathInfo.PSIsContainer) {
                        $True
                    }
                    else {
                        if ((Get-ChildItem -Path $_ | Measure-Object).Count -gt 0) {
                            $True
                        }
                    }
                } 
            }
        }

        # Check if relevant services are running
        if ($AntiVirus.RelevantServices) {
            $RunningServices = $AntiVirus.RelevantServices | ForEach-Object {
                if (!(Get-Service -Name $_ -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" })) {
                    "Not Running"
                }
            }

            if (!$RunningServices) {
                $RunningServices = "Running"
            }
        }

        # Check if relevant processes are running
        if ($AntiVirus.RelevantProcesses) {
            $RunningProcesses = $AntiVirus.RelevantProcesses | ForEach-Object {
                if (!(Get-Process -Name $_ -ErrorAction SilentlyContinue)) {
                    "Not Running"
                }
            }

            if (!$RunningProcesses) {
                $RunningProcesses = "Running"
            }
        }

        # Check specific antivirus products for their definition status and date
        switch ($AntiVirus.Name) {
            "Avast Antivirus" {
                if (Test-Path -Path "$env:ProgramFiles\Avast Software\Avast\defs\aswdefs.ini" -ErrorAction SilentlyContinue) {
                    $DefinitionFile = Get-Content -Path "$env:ProgramFiles\Avast Software\Avast\defs\aswdefs.ini" -ErrorAction SilentlyContinue
                    $DefinitionFileDate = $DefinitionFile -replace '[^0-9]' | Where-Object { $_ }

                    if ($DefinitionFileDate) {
                        $DefinitionDate = [datetime]::parseexact($DefinitionFileDate, 'yyMMddHH', $null)
                        $DefinitionDate = [System.TimeZoneInfo]::ConvertTimeFromUtc($DefinitionDate, [System.TimeZoneInfo]::Local)
                    }
                }
            }
            "AVG Antivirus Business Edition" {
                if (Test-Path -Path "$env:ProgramFiles\AVG\Antivirus\defs\aswdefs.ini" -ErrorAction SilentlyContinue) {
                    $DefinitionFile = Get-Content -Path "$env:ProgramFiles\AVG\Antivirus\defs\aswdefs.ini" -ErrorAction SilentlyContinue
                    $DefinitionFileDate = $DefinitionFile -replace '[^0-9]' | Where-Object { $_ }

                    if ($DefinitionFileDate) {
                        $DefinitionDate = [datetime]::parseexact($DefinitionFileDate, 'yyMMddHH', $null)
                        $DefinitionDate = [System.TimeZoneInfo]::ConvertTimeFromUtc($DefinitionDate, [System.TimeZoneInfo]::Local)
                    }
                }
            }
            "Bitdefender Endpoint Security Antimalware" {
                if (Test-Path -Path "$env:ProgramFiles\Bitdefender\Bitdefender Endpoint Security\update_statistics.xml" -ErrorAction SilentlyContinue) {
                    $UpdateStatistics = New-Object -TypeName XML
                    $UpdateStatistics.Load("$env:ProgramFiles\Bitdefender\Bitdefender Endpoint Security\update_statistics.xml")
                }

                if ($UpdateStatistics) {
                    [datetime]$UnixStart = '1970-01-01 00:00:00'
                    $BitDefenderUpdateDate = $UnixStart.AddSeconds($UpdateStatistics.UpdateStatistics.Antivirus.Update.succtime)

                    if ($BitDefenderUpdateDate) {
                        $DefinitionDate = Get-Date ($BitDefenderUpdateDate.ToLocalTime())
                    }
                }
            }
            "Crowdstrike" {
                $DefinitionStatus = "Not Applicable"
            }
            "Elastic Defend" {
                $DefinitionStatus = "Not Applicable"
            }
            "ESET Security" {
                if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ESET\ESET Security\CurrentVersion\Info" -ErrorAction SilentlyContinue) {
                    $ScannerVersion = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\ESET\ESET Security\CurrentVersion\Info" -Name "ScannerVersion" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ScannerVersion -ErrorAction SilentlyContinue
                }

                if ($ScannerVersion) {
                    $ScannerDateString = $ScannerVersion -replace '^.*\(' -replace '\)'
                    if ($ScannerDateString) { 
                        $DefinitionDate = [datetime]::parseexact($ScannerDateString, 'yyyyMMdd', $null) 
                    }
                }
            }
            "F-Secure" {
                if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\F-Secure\Ultralight\updates" -ErrorAction SilentlyContinue) {
                    $FSecureEngines = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\F-Secure\Ultralight\updates" -ErrorAction SilentlyContinue
                    
                    $LatestFSecureEngines = New-Object System.Collections.Generic.List[String]
                    $FSecureEngines | ForEach-Object {
                        $FSecureEngineVersions = Get-ChildItem -Path "Registry::$($_.Name)" -ErrorAction SilentlyContinue

                        $LatestEngine = $FsecureEngineVersions | Sort-Object Name -Descending | Select-Object -First 1
                        $LatestEngine = ($LatestEngine | Select-Object -ExpandProperty Name) | ForEach-Object { $_ -replace "^.*\\" }

                        if ($LatestEngine) {
                            $LatestFSecureEngines.Add($LatestEngine)
                        }
                    }

                    $LatestFSecureEngine = $LatestFSecureEngines | Sort-Object -Descending | Select-Object -First 1

                    if ($LatestFSecureEngine) {
                        [datetime]$UnixStart = '1970-01-01 00:00:00'
                        $FSecureUpdateDate = $UnixStart.AddSeconds($LatestFSecureEngine)
                        $DefinitionDate = Get-Date ($FSecureUpdateDate.ToLocalTime())
                    }
                }
            }
            "Huntress" {
                $DefinitionStatus = "Not Applicable"
            }
            "Kaspersky Endpoint Security for Windows" {
                $KESConsole = Get-ChildItem "${env:ProgramFiles(x86)}\Kaspersky Lab\KES.*\kescli.exe" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1 -ErrorAction SilentlyContinue

                if ($KESConsole) {
                    $KESprocess = Start-Process -FilePath $KESConsole -ArgumentList "--opswat", "GetDefinitionState" -RedirectStandardOutput "$env:TEMP\KESdata.txt" -NoNewWindow -Wait -PassThru

                    if ($KESprocess.ExitCode -ne 0) {
                        Write-Host "Exit Code: $($KESprocess.ExitCode)"
                        Write-Host "[Error] Exit Code does not indicate success!"
                    }

                    $KESdata = Get-Content -Path "$env:TEMP\KESdata.txt"
                }

                if ($KESdata -match '\d+/\d+/\d{4}') {
                    $DefinitionDate = [datetime]::parseexact($KESdata, 'M/d/yyyy H:m:s', $null)
                    $DefinitionDate = $DefinitionDate.ToLocalTime()

                    Remove-Item -Path "$env:TEMP\KESdata.txt"
                }
                else {
                    if (!$InstallPathExists -or !$InstallationKey -and ($RunningProcesses -or $RunningServices)) {
                        $RunningProcesses = $null
                        $RunningServices = $null
                    }
                }
            }
            "Kaspersky Small Office Security" {
                $AVPConsole = Get-ChildItem "${env:ProgramFiles(x86)}\Kaspersky Lab\Kaspersky Small Office Security *\avp.com" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1 -ErrorAction SilentlyContinue

                if ($AVPConsole) {
                    $KSOprocess = Start-Process -FilePath $AVPConsole -ArgumentList "STATISTICS", "Updater" -RedirectStandardOutput "$env:TEMP\KSOdata.txt" -NoNewWindow -Wait -PassThru

                    if ($KSOprocess.ExitCode -ne 0) {
                        Write-Host "Exit Code: $($KSOprocess.ExitCode)"
                        Write-Host "[Error] Exit Code does not indicate success!"
                    }

                    $KSOdata = Get-Content -Path "$env:TEMP\KSOdata.txt"
                }

                if ($KSOdata) {
                    $KsoTimeFinish = $KSOdata | Where-Object { $_ -match "Time Finish" }
                    if ($KsoTimeFinish) {
                        $KsoTimeFinish = ($KsoTimeFinish -replace "Time Finish:").Trim()

                        $UpdateSucceeded = $KSOdata | Where-Object { $_ -match "Update succeeded" }

                        if ($UpdateSucceeded) {
                            $DefinitionDate = [datetime]::parseexact($KsoTimeFinish, 'yyyy-MM-dd HH:mm:ss', $null)
                        }
                    }

                    Remove-Item -Path "$env:TEMP\KSOdata.txt"
                }
                else {
                    if (!$InstallPathExists -or !$InstallationKey -and ($RunningProcesses -or $RunningServices)) {
                        $RunningProcesses = $null
                        $RunningServices = $null
                    }
                }
            }
            "MalwareBytes" {
                if (Test-Path -Path "$env:ProgramData\Malwarebytes\MBAMService\config\UpdateControllerConfig.json" -ErrorAction SilentlyContinue) {
                    $UpdateConfigFile = Get-Content -Path "$env:ProgramData\Malwarebytes\MBAMService\config\UpdateControllerConfig.json" | Select-Object -Skip 1 | ConvertFrom-Json
                }

                if ($UpdateConfigFile) {
                    [datetime]$UnixStart = '1970-01-01 00:00:00'
                    $MalwarebytesUpdateDate = $UnixStart.AddSeconds($UpdateConfigFile.db_pub_date)

                    if ($MalwarebytesUpdateDate) {
                        $DefinitionDate = Get-Date ($MalwarebytesUpdateDate.ToLocalTime())
                    }
                }
            }
            "Sentinel Agent" {
                $DefinitionStatus = "Not Applicable"
            }
            "Sophos Intercept X" {
                if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Sophos\EndpointDefense\Acknowledged" -ErrorAction SilentlyContinue) {
                    $SophosVirusData = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Sophos\EndpointDefense\Acknowledged" -Name "VirusDataVersion" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty VirusDataVersion -ErrorAction SilentlyContinue
                }

                if ($SophosVirusData) {
                    $DefinitionDate = [datetime]::parseexact($SophosVirusData, 'yyyyMMddHH', $null)
                }
            }
            "Trend Micro Maximum Security" {
                if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\TrendMicro\AMSP" -ErrorAction SilentlyContinue) {
                    $MaximumSecurityInstallTime = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\TrendMicro\AMSP" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty InstallTime -ErrorAction SilentlyContinue
                    
                }

                if ($MaximumSecurityInstallTime) {
                    [datetime]$UnixStart = '1970-01-01 00:00:00'
                    $MaximumSecurityUnixDate = $UnixStart.AddSeconds($MaximumSecurityInstallTime)

                    if ($MaximumSecurityUnixDate) {
                        $DefinitionDate = Get-Date ($MaximumSecurityUnixDate.ToLocalTime())
                    }
                }
            }
            "Trend Micro Security Agent" {
                if (Test-Path -Path "${env:ProgramFiles(x86)}\Trend Micro\Security Agent\ofcscan.ini" -ErrorAction SilentlyContinue) {
                    $ofcscanFile = Get-Content -Path "${env:ProgramFiles(x86)}\Trend Micro\Security Agent\ofcscan.ini"
                    
                }

                if ($ofcscanFile) {
                    $ofcscanFile | ForEach-Object {
                        if ($_ -match '^\[(.+)\]') {
                            $Section = $_
                        }

                        if ($Section -match 'INI_PROGRAM_VERSION_SECTION' -and $_ -match '^Pattern_Last_Update') {
                            $ofcscanDateString = ($_ -replace 'Pattern_Last_Update=' -replace '').Trim()
                            $ofcscanDateString = $ofcscanDateString -replace "[^0-9]"
                        }
                    }

                    if ($ofcscanDateString) {
                        $DefinitionDate = [datetime]::parseexact($ofcscanDateString, 'yyyyMMddHHmmss', $null)
                    }
                }
            }
            "VIPRE Business Agent" {
                if (Test-Path -Path "$env:ProgramFiles\VIPRE Business Agent\Definitions\DefVer.txt") {
                    $DefVerFile = Get-Content -Path "$env:ProgramFiles\VIPRE Business Agent\Definitions\DefVer.txt"
                }

                if ($DefVerFile) {
                    $VipreDateString = ($DefVerFile -replace '.*,').Trim()

                    if ($VipreDateString) {
                        $DefinitionDate = Get-Date $VipreDateString
                    }
                }
            }
            "Webroot SecureAnywhere" {
                $DefinitionStatus = "Not Applicable"
            }
            "Windows Defender" {
                if ((Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue).Count -ne 0) {
                    try { 
                        Get-MpComputerStatus -ErrorAction Stop | Out-Null
                        $Installed = $True
                    }
                    catch { 
                        $Installed = $False
                    }
                }

                if ($Installed) {
                    if (!((Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled)) {
                        $RunningValue = "Not Running"
                    }
                    else {
                        $RunningValue = "Running"
                    }

                    if ((Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureLastUpdated) {
                        $DefinitionDate = (Get-MpComputerStatus).AntivirusSignatureLastUpdated
                    }
                    else {
                        $DefinitionStatus = "Outdated"
                    }
                }
            }
        }

        # Determine if the antivirus is installed based on various check
        if (!$Installed -and ($InstallPathExists -or $InstallationKey -or $RunningProcesses -eq "Running" -or $RunningServices -eq "Running")) {

            $RequireInstallationKey = "Trend Micro Maximum Security", "Trend Micro Security Agent", "Trend Micro Apex One Antivirus"
            if ($RequireInstallationKey -contains $AntiVirus.Name -and !$InstallationKey) {
                $Installed = $False
            }
            else {
                $Installed = $True
            }
        }
        elseif (!$Installed) {
            $Installed = $False
        }

        # Determine the running status based on process and service status
        if ($RunningProcesses -eq "Running" -and $RunningServices -eq "Running") {
            $RunningValue = "Running"
        }
        elseif (!$RunningProcesses -or !$RunningServices) {
            $RunningValue = "Unable to Determine"
        }
        else {
            $RunningValue = "Not Running"
        }

        # Determine the definition status based on the date
        if ($DefinitionDate) {
            if ((Get-Date).AddDays(-$DaysUntilConsideredOutdated) -ge $DefinitionDate) {
                $DefinitionStatus = "Outdated"
            }
            elseif ((Get-Date).AddDays(-$DaysUntilConsideredOutdated) -lt $DefinitionDate) {
                $DefinitionStatus = "Up To Date"
            }
            else {
                $DefinitionStatus = "Unable to Determine"
            }
        }
        elseif (!$DefinitionStatus) {
            $DefinitionStatus = "Unable to Determine"
        }

        # Add the antivirus information to the list
        if ($Installed) {
            $DetectedAVs.Add(
                [PSCustomObject]@{
                    "Antivirus Name"    = $AntiVirus.Name
                    Status              = $RunningValue
                    "Definition Status" = $DefinitionStatus
                    "Definition Date"   = if ($DefinitionDate) { "$($DefinitionDate.ToShortDateString())" }
                }
            )
        }
    }

    # Check if no antivirus products were detected
    if ($DetectedAVs.Count -eq 0) {
        Write-Host "[Alert] No antivirus was detected."
    }

    if ($WYSIWYGCustomField) {
        try {
            Write-Host "`nAttempting to set Custom Field '$WYSIWYGCustomField'."

            if ($DetectedAVs.Count -eq 0) {
                $AntivirusTable = "<h1 style='color: #D53948'>[Alert] No antivirus was detected.</h1>"
            }
            else {
                $AntivirusTable = $DetectedAVs | ConvertTo-Html -Fragment
                $AntivirusTable = $AntivirusTable -replace "<th>", "<th><b>" -replace "</th>", "</b></th>"
                $AntivirusTable = $AntivirusTable -replace "<table>", "<table><caption style='border-top: 1px; border-left: 1px; border-right: 1px; border-style: solid; border-color: #CAD0D6'><b>Detected Antivirus Details</b></caption>"
            }

            # Set the custom field with the combined antivirus names
            Set-NinjaProperty -Name $WYSIWYGCustomField -Value $AntivirusTable
            Write-Host "Successfully set Custom Field '$WYSIWYGCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    if ($NameCustomField) {
        # Attempt to set the custom field for the antivirus names
        try {
            Write-Host "`nAttempting to set Custom Field '$NameCustomField'."

            # Combine all antivirus names into a single string, separated by commas
            $NameString = $DetectedAVs."Antivirus Name" -join ", "

            if ($DetectedAVs.Count -eq 0) {
                $NameString = "[Alert] No antivirus was detected."
            }

            # Set the custom field with the combined antivirus names
            Set-NinjaProperty -Name $NameCustomField -Value $NameString
            Write-Host "Successfully set Custom Field '$NameCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    if ($StatusCustomField) {
        # Attempt to set the custom field for the antivirus running status
        try {
            Write-Host "`nAttempting to set Custom Field '$StatusCustomField'."

            # Combine all antivirus running statuses into a single string, separated by commas
            $StatusString = $DetectedAVs.Status -join ", "

            if ($DetectedAVs.Count -eq 0) {
                $StatusString = "[Alert] No antivirus was detected."
            }

            # Set the custom field with the combined running statuses
            Set-NinjaProperty -Name $StatusCustomField -Value $StatusString
            Write-Host "Successfully set Custom Field '$StatusCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    if ($DefinitionDateAndStatusCustomField) {
        # Attempt to set the custom field for the antivirus definition status
        try {
            Write-Host "`nAttempting to set Custom Field '$DefinitionDateAndStatusCustomField'."

            # Combine all antivirus running statuses into a single string, separated by commas
            $DefinitionStrings = $DetectedAVs | ForEach-Object {
                if ($_."Definition Date") {
                    "$($_."Definition Date") | $($_."Definition Status")"
                }
                else {
                    $_."Definition Status"
                }
            }

            $CustomFieldValue = $DefinitionStrings -join ", "

            if ($DetectedAVs.Count -eq 0) {
                $CustomFieldValue = "[Alert] No antivirus was detected."
            }

            # Set the custom field with the combined running statuses
            Set-NinjaProperty -Name $DefinitionDateAndStatusCustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$DefinitionDateAndStatusCustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    if ($DetectedAVs.Count -gt 0) {
        Write-Host -Object ""
        ($DetectedAVs | Sort-Object "Antivirus Name" | Format-Table -AutoSize | Out-String).Trim() | Write-Host
    }

    exit $ExitCode
}end {
    
    
    
}
