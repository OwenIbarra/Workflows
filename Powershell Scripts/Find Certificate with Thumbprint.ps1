# Returns a list of system certificates that have the specified thumbprints or Removes the certificates with matching thumbprints.
#Requires -Version 5.1

<#
.SYNOPSIS
    Returns a list of system certificates that have the specified thumbprints or Removes the certificates with matching thumbprints.
.DESCRIPTION
    Returns a list of system certificates that have the specified thumbprints or Removes the certificates with matching thumbprints.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    Does nothing.

.EXAMPLE
PARAMETER: -Thumbprint "AE68D0ADAD2345B48E507320B695D386080E5B25", "BE68D0ADAA2145B48E507320B695D386080E5B25"
    Returns the found thumbprints matching the input.
    ## EXAMPLE OUTPUT WITH Thumbprint ##
    [Alert] Found certificates:
    AE68D0ADAD2345B48E507320B695D386080E5B25
    BE68D0ADAA2145B48E507320B695D386080E5B25
    [Alert] Certificates found

.EXAMPLE
PARAMETER: -Thumbprint "BE68D0ADAA2145B48E507320B695D386080E5B25" -RemoveMatchingCertificates
    Returns the found thumbprints matching the input and Removes the certificates.
    ## EXAMPLE OUTPUT WITH RemoveMatchingCertificates ##
    [Alert] Found certificates:
    BE68D0ADAA2145B48E507320B695D386080E5B25
    [Info] Removing certificates
    [Info] Removing certificate with thumbprint: BE68D0ADAA2145B48E507320B695D386080E5B25
    [Info] Removed certificate with thumbprint: BE68D0ADAA2145B48E507320B695D386080E5B25
    [Alert] Certificates found
.EXAMPLE
PARAMETER: -Thumbprint "BE68D0ADAA2145B48E507320B695D386080E5B25" -CustomField "Thumbprints"
    Returns the found thumbprints matching the input and Removes the certificates.
    ## EXAMPLE OUTPUT WITH RemoveMatchingCertificates ##
    [Alert] Found certificates:
    BE68D0ADAA2145B48E507320B695D386080E5B25
    [Info] Saving thumbprints to custom field: Thumbprints
    [Alert] Certificates found
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated checkbox script variables.
.COMPONENT
    Generic-Security
#>

[CmdletBinding()]
param (
    [string[]]$Thumbprint,
    [switch]$RemoveMatchingCertificates,
    [string]$CertRevokeList,
    [string]$GetCrlFromCustomField,
    [string]$CustomField
)

begin {
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
            [String]$DocumentName
        )

        # If we're requested to set the field value for a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }

        # This is a list of valid fields we can set. If no type is given we'll assume the input doesn't have to be changed in any way.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }

        # The below field requires additional information in order to set
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

        # If we received some sort of error it should have an exception property and we'll exit the function with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }

        # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli is expecting the time to be representing as a Unix Epoch string. So we'll convert what we were given into that format.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID

                if (-not $Selection) {
                    throw "Value is not present in dropdown"
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
    # This function is to make it easier to parse Ninja Custom Fields.
    function Get-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter()]
            [String]$DocumentName
        )
    
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            throw "PowerShell 3.0 or higher is required to retrieve data from custom fields. https://ninjarmm.zendesk.com/hc/en-us/articles/4405408656013"
        }
    
        # If we're requested to get the field value from a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
    
        # These two types require more information to parse.
        $NeedsOptions = "DropDown", "MultiSelect"
    
        # Grabbing document values requires a slightly different command.
        if ($DocumentName) {
            # Secure fields are only readable when they're a device custom field
            if ($Type -Like "Secure") { throw "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
    
            # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
            Write-Host "Retrieving value from Ninja Document..."
            $NinjaPropertyValue = Ninja-Property-Docs-Get -AttributeName $Name @DocumentationParams 2>&1
    
            # Certain fields require more information to parse.
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            # We'll redirect error output to the success stream to make it easier to error out if nothing was found or something else went wrong.
            $NinjaPropertyValue = Ninja-Property-Get -Name $Name 2>&1
    
            # Certain fields require more information to parse.
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
    
        # If we received some sort of error it should have an exception property and we'll exit the function with that error information.
        if ($NinjaPropertyValue.Exception) { throw $NinjaPropertyValue }
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
    
        # This switch will compare the type given with the quoted string. If it matches, it'll parse it further; otherwise, the default option will be selected.
        switch ($Type) {
            "Attachment" {
                # Attachments come in a JSON format this will convert it into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Checkbox" {
                # Checkbox's come in as a string representing an integer. We'll need to cast that string into an integer and then convert it to a more traditional boolean.
                [System.Convert]::ToBoolean([int]$NinjaPropertyValue)
            }
            "Date or Date Time" {
                # In Ninja Date and Date/Time fields are in Unix Epoch time in the UTC timezone the below should convert it into local time as a datetime object.
                $UnixTimeStamp = $NinjaPropertyValue
                $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds($UnixTimeStamp)
                $TimeZone = [TimeZoneInfo]::Local
                [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
            }
            "Decimal" {
                # In ninja decimals are strings that represent a decimal this will cast it into a double data type.
                [double]$NinjaPropertyValue
            }
            "Device Dropdown" {
                # Device Drop-Downs Fields come in a JSON format this will convert it into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Device MultiSelect" {
                # Device Multi-Select Fields come in a JSON format this will convert it into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Dropdown" {
                # Drop-Down custom fields come in as a comma-separated list of GUIDs; we'll compare these with all the options and return just the option values selected instead of a GUID.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Options | Where-Object { $_.GUID -eq $NinjaPropertyValue } | Select-Object -ExpandProperty Name
            }
            "Integer" {
                # Cast's the Ninja provided string into an integer.
                [int]$NinjaPropertyValue
            }
            "MultiSelect" {
                # Multi-Select custom fields come in as a comma-separated list of GUID's we'll compare these with all the options and return just the option values selected instead of a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = ($NinjaPropertyValue -split ',').trim()
    
                foreach ($Item in $Selection) {
                    $Options | Where-Object { $_.GUID -eq $Item } | Select-Object -ExpandProperty Name
                }
            }
            "Organization Dropdown" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location Dropdown" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization Location MultiSelect" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Organization MultiSelect" {
                # Turns the Ninja provided JSON into a PowerShell Object.
                $NinjaPropertyValue | ConvertFrom-Json
            }
            "Time" {
                # Time fields are given as a number of seconds starting from midnight. This will convert it into a datetime object.
                $Seconds = $NinjaPropertyValue
                $UTC = ([timespan]::fromseconds($Seconds)).ToString("hh\:mm\:ss")
                $TimeZone = [TimeZoneInfo]::Local
                $ConvertedTime = [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
    
                Get-Date $ConvertedTime -DisplayHint Time
            }
            default {
                # If no type was given or not one that matches the above types just output what we retrieved.
                $NinjaPropertyValue
            }
        }
    }
    # Utility function for downloading files.
    function Invoke-Download {
        param(
            [Parameter()]
            [String]$URL,
            [Parameter()]
            [String]$Path,
            [Parameter()]
            [int]$Attempts = 3,
            [Parameter()]
            [Switch]$SkipSleep
        )
        Write-Host "URL given, Downloading the file..."

        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Not everything requires TLS 1.2, but we'll try anyway.
            Write-Warning "TLS 1.2 and or TLS 1.3 are not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        $i = 1
        While ($i -le $Attempts) {
            # Some cloud services have rate-limiting
            if (-not ($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
        
            if ($i -ne 1) { Write-Host "" }
            Write-Host "Download Attempt $i"

            try {
                # Invoke-WebRequest is preferred because it supports links that redirect, e.g., https://t.ly
                if ($PSVersionTable.PSVersion.Major -lt 4) {
                    # Downloads the file
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($URL, $Path)
                }
                else {
                    # Standard options
                    $WebRequestArgs = @{
                        Uri                = $URL
                        OutFile            = $Path
                        MaximumRedirection = 10
                        UseBasicParsing    = $true
                    }

                    # Downloads the file
                    Invoke-WebRequest @WebRequestArgs
                }

                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch {
                Write-Warning "An error has occurred while downloading!"
                Write-Warning $_.Exception.Message

                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }

                $File = $False
            }

            if ($File) {
                $i = $Attempts
            }
            else {
                Write-Warning "File failed to download."
                Write-Host ""
            }

            $i++
        }

        if (-not (Test-Path $Path)) {
            Write-Warning "Failed to download file!"
        }
        else {
            return $Path
        }
    }

    function Revoke-Certificate {
        param (
            $Object,
            $Loop = 0
        )
        $CrlPath = "$TEMP\CertRevokeListScript-$(Get-Date -Format FileDate).crl"
        Write-Host "[Info] Revoking certificates with CRL file from Path, URL, or custom field: $Object"
        if ($Object -like "http*") {
            Write-Host "[Info] Downloading CRL file"
            try {
                # Download the CRL file
                Invoke-Download -URL $Object -Path $CrlPath -SkipSleep -ErrorAction Stop
                Write-Host "[Info] Downloaded CRL file to $CrlPath"
                # Revoke the certificates
                certutil.exe -addstore CA $CrlPath
                Write-Host "[Info] Added CRL to the list of revoked certificates"
            }
            catch {
                Write-Host "[Error] Failed to download CRL file"
                exit 1
            }
            # Remove the temporary CRL file
            try {
                Remove-Item -Path $CrlPath -Force -Confirm:$false -ErrorAction Stop
            }
            catch {
                Write-Host "[Error] Failed to remove temporary CRL file"
                exit 1
            }
        }
        elseif ($(Test-Path -Path $Object -ErrorAction SilentlyContinue)) {
            # Revoke the certificates
            Write-Host "[Info] Adding CRL to the list of revoked certificates"
            try {
                $Object | Set-Content -Path $CrlPath -Force -ErrorAction Stop
                # Revoke the certificates
                certutil.exe -addstore CA $CrlPath
                Write-Host "[Info] Added CRL to the list of revoked certificates"
            }
            catch {
                Write-Host "[Error] Failed to revoke certificates with CRL file"
                exit 1
            }
            # Remove the temporary CRL file
            try {
                Remove-Item -Path $CrlPath -Force -Confirm:$false -ErrorAction Stop
            }
            catch {
                Write-Host "[Error] Failed to remove temporary CRL file"
                exit 1
            }
        }
        else {
            $ValueFromCf = Get-NinjaProperty -Name $Object
            if (
                # Check if Loop is 0 and the value from the custom field is a path or URL
                $Loop -eq 0 -and (
                    $(Test-Path -Path $ValueFromCf -ErrorAction SilentlyContinue) -or
                    $ValueFromCf -like "http*"
                )
            ) {
                # Call Revoke-Certificate if the Custom Field value is a path or URL
                # We'll only call Revoke-Certificate once to prevent an infinite loop via $Loop variable
                Revoke-Certificate -Object $ValueFromCf -Loop $($Loop + 1)
                return
            }
            $ValueFromCf | Set-Content -Path $CrlPath -Force -ErrorAction Stop
            
            # Revoke the certificates
            certutil.exe -addstore CA $CrlPath
            if ($LASTEXITCODE -ne 0) {
                Write-Host "[Error] Failed to revoke certificates with CRL file"
                exit 1
            }
            Write-Host "[Info] Added CRL to the list of revoked certificates"
            # Remove the temporary CRL file
            try {
                Remove-Item -Path $CrlPath -Force -Confirm:$false -ErrorAction Stop
            }
            catch {
                Write-Host "[Error] Failed to remove temporary CRL file"
                exit 1
            }
        }
        
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    if ($PSSenderInfo) {
        Write-Host "[Error] This script cannot be run in a PSSession. Please run it locally or via Ninja RMM."
        exit 1
    }

    $CertificatesFound = $false
    $RemoveError = $false

    # Get a list of thumbprints from the environment variable
    if ($env:Thumbprints -and $env:Thumbprints -ne "null") {
        $Thumbprint = $env:Thumbprints -split ',' | ForEach-Object { "$_".Trim() }
    }
    elseif ($Thumbprint) {
        # Remove any commas from the thumbprint and trim any whitespace
        $Thumbprint = $Thumbprint | ForEach-Object { "$($_ -split ',')".Trim() }
    }
    if ($env:getCrlFromCustomField -and $env:getCrlFromCustomField -ne "null") {
        $GetCrlFromCustomField = $env:getCrlFromCustomField
    }

    # Get crl file path from the environment variable
    if ($env:certificateRevokeListPath -and $env:certificateRevokeListPath -ne "null") {
        $CertRevokeList = $env:certificateRevokeListPath
    }

    # Check that Thumbprint or CertRevokeList where specified
    if ($Thumbprint) {}
    elseif ($CertRevokeList) {}
    elseif ($GetCrlFromCustomField) {}
    else {
        Write-Host "[Error] Thumbprint or CertRevokeList or GetCrlFromCustomField where not specified. Please specify at least one of them."
        exit 2
    }

    # Check if the RemoveMatchingCertificates switch/checkbox was selected
    if ($env:removeMatchingCertificates -eq "true") {
        $RemoveMatchingCertificates = $true
    }

    # Get the custom field name from the Script Variable
    if ($env:customField) {
        $CustomField = $env:customField
    }

    if ($Thumbprint) {
        $Thumbprint = $Thumbprint | ForEach-Object {
            if ($_.Length -eq 40 -and $_ -match "^[0-9a-fA-F]{40}$") {
                Write-Host "[Info] Thumbprint($_) is valid and will be processed."
                $_
            }
            else {
                Write-Host "[Warn] Thumbprint($_) is not valid and will be skipped."
            }
        }
    
        # Loop through all certificates installed on the system
        $FoundCertificates = Get-ChildItem -Path Cert:\LocalMachine\ -Recurse | Where-Object { $_.Thumbprint -and $_.Thumbprint -in $Thumbprint }
    
        # Output the found certificates
        $OutputThumbprints = if ($FoundCertificates) {
            $CertificatesFound = $true
            Write-Host "[Alert] Found certificates:"
            $FoundCertificates = $FoundCertificates | ForEach-Object {
                [PSCustomObject]@{
                    Thumbprint = $_.Thumbprint
                    PSPath     = $_.PSPath
                    ExpiryDate = if ($_.NotAfter) { $_.NotAfter.ToShortDateString() }else { "No Expiry Date" }
                }
            }
            if ($FoundCertificates) {
                $thumbprint = "Thumbprint"
                $path = "Path"
                $padding = 40

                $centeredThumbprint = $thumbprint.PadLeft(($thumbprint.Length + $padding) / 2).PadRight($padding)
                $centeredPath = $path

                Write-Host "$centeredThumbprint - $centeredPath - Expires"
            }
            $FoundCertificates | ForEach-Object {
                $CertPath = $_
                $CertificatePath = $CertPath.PSPath
                # Convert PSPath to how certmgr.mmc formats the path
                $CertificatePath = $CertificatePath -replace 'LocalMachine\\', 'Local Computer\'
                $CertificatePath = $CertificatePath -replace '\\My\\', '\Personal\'
                $CertificatePath = $CertificatePath -replace '\\CA\\', '\Intermediate Certification Authorities\'
                $CertificatePath = $CertificatePath -replace '\\Root\\', '\Trusted Root Certification Authorities\'
                $CertificatePath = $CertificatePath -replace '\\Disallowed\\', '\Untrusted Certificates\'
                $CertificatePath = $CertificatePath -replace '\\AuthRoot\\', '\Third-Party Root Certification Authorities\'
                $CertificatePath = $CertificatePath -replace '\\TrustedPublisher\\', '\Trusted Publishers\'
                $CertificatePath = $CertificatePath -replace '\\ClientAuthIssuer\\', '\Client Authentication Issuers\'
                $CertificatePath = $CertificatePath -replace '\\Remote Desktop\\', '\Remote Desktop\'
                $CertificatePath = $CertificatePath -replace '\\SmartCardRoot\\', '\Smart Card Trusted Roots\'
                $CertificatePath = $CertificatePath -replace '\\TrustedPeople\\', '\Trusted People\'
                $CertificatePath = $CertificatePath -replace '\\Trust\\', '\Enterprise Trust\'
                $CertificatePath = $CertificatePath -replace '\\REQUEST\\', '\Certificate Enrollment Requests\'
                $CertificatePath = $CertificatePath -replace '\\AddressBook\\', '\Other People\'
                $CertificatePath = $CertificatePath -replace '\\UserdDS\\', '\Active Directory User Object\'
                # Output with the formatted path
                "$($CertPath.Thumbprint) - $($CertificatePath -replace 'Microsoft.PowerShell.Security\\Certificate::') - $($CertPath.ExpiryDate)"
            }
        }
        else {
            Write-Host "[Info] No certificates found"
        }
        if ($OutputThumbprints) {
            $OutputThumbprints | Out-String | Write-Host
        }
    
        # Remove the certificates if we should
        if ($RemoveMatchingCertificates) {
            Write-Host "[Info] Removing certificates"
            # Loop through all the found certificates
            $FoundCertificates | ForEach-Object {
                $Certificate = $_
                # Remove the certificate
                Write-Host "[Info] Removing certificate with path: $($Certificate.PSPath -replace 'Microsoft.PowerShell.Security\\Certificate::')"
                try {
                    # Remove the certificate and its private key
                    # More Info: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/about/about_certificate_provider?view=powershell-5.1#deleting-certificates-and-private-keys
                    if ($IsLinux) {
                        # Only used for testing purposes
                        Remove-Item -Path $Certificate.PSPath -Force -Confirm:$false -ErrorAction Stop
                    }
                    else {
                        Remove-Item -Path $Certificate.PSPath -DeleteKey -Force -Confirm:$false -ErrorAction Stop
                    }
                    Write-Host "[Info] Removed certificate with path: $($Certificate.PSPath -replace 'Microsoft.PowerShell.Security\\Certificate::')"
                }
                catch {
                    # Only error if there is only one certificate
                    # More than one certificate with the same thumbprint is likely already removed
                    if ($($FoundCertificates | Where-Object { $_ -like $Certificate.Thumbprint }).Count -eq 1) {
                        Write-Host "[Error] Failed to Remove certificate with thumbprint: $($Certificate.Thumbprint)"
                        $RemoveError = $true
                    }
                    else {
                        Write-Host "[Info] Removed certificate with path: $($Certificate.PSPath -replace 'Microsoft.PowerShell.Security\\Certificate::')"
                    }
                }
            }
        }
        else {
            Write-Host "[Info] Removing certificates is not enabled. Doing nothing."
        }
        if ($CustomField) {
            # Save the found thumbprints to a NinjaRMM custom field
            Write-Host "[Info] Saving thumbprints to custom field: $CustomField"
            try {
                if ($RemoveMatchingCertificates) {
                    Set-NinjaProperty -Name $CustomField -Value $($OutputThumbprints | ForEach-Object {
                            # Output just the path
                            "$("$_" -split ' - ' | Select-Object -Skip 1 -First 1) - Removed from system"
                        } | Out-String) -Type "MultiLine"
                }
                else {
                    Set-NinjaProperty -Name $CustomField -Value $($OutputThumbprints | ForEach-Object {
                            # Output just the path
                            "$("$_" -split ' - ' | Select-Object -Skip 1 -First 1)"
                        } | Out-String) -Type "MultiLine"
                }
            }
            catch {
                # If we ran into some sort of error we'll output it here.
                Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
                exit 1
            }
        }
    
        # Exit with an error when we failed to remove a certificate
        if ($RemoveError) {
            Write-Host "[Error] Failed to Remove one or more certificates"
            exit 1
        }
    
        # Exit with an error when we found certificates and we shouldn't remove them
        if ($CertificatesFound -and -not $RemoveMatchingCertificates) {
            Write-Host "[Alert] Certificates found"
            exit 1
        }
    }

    if ($CertRevokeList) {
        Revoke-Certificate -Object $CertRevokeList
    }
    if ($GetCrlFromCustomField) {
        Revoke-Certificate -Object $GetCrlFromCustomField
    }

    # Exit with a success when no certificates were found
    exit 0
}
end {
    
    
    
}

