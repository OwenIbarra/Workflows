# Installs a given certificate to the selected location.
#Requires -Version 5.1

<#
.SYNOPSIS
    Installs a given certificate to the selected location.

.DESCRIPTION
    Installs a given certificate to the selected location.
    Running this script as SYSTEM will install the certificate to the LocalMachine certificate store.
    Running this script as a user will install the certificate to the CurrentUser certificate store of that user.

    Note that this will install ALL certificates in a collection to the specified store. If you need to install
    specific certificates to different stores, you will need to break apart the collection and
    install each certificate individually.

.PARAMETER CertificatePath
    The file path or URL to the certificate file.

.PARAMETER CertificateStore
    The certificate store to install the certificate to.
    Supported values:
        "Personal"
        "Trusted Root Certification Authorities"
        "Third-Party Root Certification Authorities"
        "Trusted Publisher"
        "Intermediate Certification Authorities"
        "Untrusted Certificates"
        "Trusted People"
        "Other People"

.PARAMETER CertificatePassword
    The password for the certificate.
    Running from NinjaRMM, this can be stored in a custom field and retrieved using the "Certificate Password Custom Field Name" Script Variable.

.PARAMETER OverwriteCertificateIfExisting
    Overwrite the certificate if it already exists.
    This removes any certificates that have a matching Thumbprint in the specified certificate store,
     e.g. Cert was installed in Personal, but needs to be replaced.

.EXAMPLE
    -CertificatePath 'C:\certs\mycert.pfx' -CertificateStore 'Personal' -CertificatePassword 'password'

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial release
#>

[CmdletBinding()]
param (
    [string]$CertificatePath,
    [string]$CertificateStore,
    [string]$CertificatePassword,
    [switch]$OverwriteCertificateIfExisting
)

begin {

    function Test-IsSystem {
        # Get the current Windows identity of the user running the script
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    
        # Check if the current identity's name matches "NT AUTHORITY*"
        # or if the identity represents the SYSTEM account
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }
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
    
        # Display the URL being used for the download
        Write-Host -Object "URL '$URL' was given."
        Write-Host -Object "Downloading the file..."
    
        # Determine the supported TLS versions and set the appropriate security protocol
        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Warn the user if TLS 1.2 and 1.3 are not supported, which may cause the download to fail
            Write-Warning "TLS 1.2 and/or TLS 1.3 are not supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }
    
        # Initialize the attempt counter
        $i = 1
        While ($i -le $Attempts) {
            # If SkipSleep is not set, wait for a random time between 3 and 15 seconds before each attempt
            if (!($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 15
                Write-Host "Waiting for $SleepTime seconds."
                Start-Sleep -Seconds $SleepTime
            }
            
            # Provide a visual break between attempts
            if ($i -ne 1) { Write-Host "" }
            Write-Host "Download Attempt $i"
    
            # Temporarily disable progress reporting to speed up script performance
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                if ($PSVersionTable.PSVersion.Major -lt 4) {
                    # For older versions of PowerShell, use WebClient to download the file
                    $WebClient = New-Object System.Net.WebClient
                    $WebClient.DownloadFile($URL, $Path)
                }
                else {
                    # For PowerShell 4.0 and above, use Invoke-WebRequest with specified arguments
                    $WebRequestArgs = @{
                        Uri                = $URL
                        OutFile            = $Path
                        MaximumRedirection = 10
                        UseBasicParsing    = $true
                    }
    
                    Invoke-WebRequest @WebRequestArgs
                }
    
                # Verify if the file was successfully downloaded
                $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            }
            catch {
                # Handle any errors that occur during the download attempt
                Write-Warning "An error has occurred while downloading!"
                Write-Warning $_.Exception.Message
    
                # If the file partially downloaded, delete it to avoid corruption
                if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
                    Remove-Item $Path -Force -Confirm:$false -ErrorAction SilentlyContinue
                }
    
                $File = $False
            }
    
            # Restore the original progress preference setting
            $ProgressPreference = $PreviousProgressPreference
            # If the file was successfully downloaded, exit the loop
            if ($File) {
                $i = $Attempts
            }
            else {
                # Warn the user if the download attempt failed
                Write-Warning "File failed to download."
                Write-Host ""
            }
    
            # Increment the attempt counter
            $i++
        }
    
        # Final check: if the file still doesn't exist, report an error and exit
        if (!(Test-Path $Path)) {
            Write-Host -Object "[Error] Failed to download file."
            Write-Host -Object "Please verify the URL of '$URL'."
            exit 1
        }
        else {
            # If the download succeeded, return the path to the downloaded file
            return $Path
        }
    }

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
        
        # Initialize a hashtable for documentation parameters
        $DocumentationParams = @{}
    
        # If a document name is provided, add it to the documentation parameters
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
    
        # Define types that require options to be retrieved
        $NeedsOptions = "DropDown", "MultiSelect"
        
        # If a document name is provided, retrieve the property value from the document
        if ($DocumentName) {
            # Throw an error if the type is "Secure", as it's not a valid type in this context
            if ($Type -Like "Secure") { throw [System.ArgumentOutOfRangeException]::New("$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality") }
        
            # Notify the user that the value is being retrieved from a Ninja document
            Write-Host "Retrieving value from Ninja Document..."
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
            throw "The Custom Field '$Name' is empty!"
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
            "Date or Date Time" {
                # Convert a Unix timestamp to local date and time
                $UnixTimeStamp = $NinjaPropertyValue
                $UTC = (Get-Date "1970-01-01 00:00:00").AddSeconds($UnixTimeStamp)
                $TimeZone = [TimeZoneInfo]::Local
                [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
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
                # Convert the value from seconds to a time format in the local timezone
                $Seconds = $NinjaPropertyValue
                $UTC = ([timespan]::fromseconds($Seconds)).ToString("hh\:mm\:ss")
                $TimeZone = [TimeZoneInfo]::Local
                $ConvertedTime = [TimeZoneInfo]::ConvertTimeFromUtc($UTC, $TimeZone)
        
                Get-Date $ConvertedTime -DisplayHint Time
            }
            default {
                # For any other types, return the raw value
                $NinjaPropertyValue
            }
        }
    }

    $CertPassword = ""

    # Get the certificate password from the parameter
    if ($CertificatePassword) {
        $CertPassword = $CertificatePassword
    }

    if ($env:urlOrPathToCertificate) {
        $CertificatePath = "$env:urlOrPathToCertificate".Trim()
    }

    # Get the certificate password from the custom field
    if ($env:certificatePasswordCustomFieldName) {
        if (-not (Test-IsSystem)) {
            # Running as a user from NinjaRMM. Normal users don't have access to read from customfields.
            Write-Host "[Error] Must be ran as SYSTEM to install certificates with a password"
            exit 1
        }
        try {
            $CertPassword = Get-NinjaProperty -Name "$env:certificatePasswordCustomFieldName".Trim() -Type "Text"
        }
        catch {
            Write-Host "[Error] Failed to get the certificate password from the custom field: ($($env:certificatePasswordCustomFieldName))"
            exit 1
        }
    }

    if ($env:overwriteCertificateIfExisting -like "true") {
        $OverwriteCertificateIfExisting = $true
    }

    if ($env:certificateStore) {
        $CertificateStore = $env:certificateStore
    }

    # Select the certificate store based on the input
    $CertStore = switch ($CertificateStore) {
        "Personal" { [System.Security.Cryptography.X509Certificates.StoreName]::My }
        "Trusted Root Certification Authorities" { [System.Security.Cryptography.X509Certificates.StoreName]::Root }
        "Third-Party Root Certification Authorities" { [System.Security.Cryptography.X509Certificates.StoreName]::AuthRoot }
        "Trusted Publisher" { [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPublisher }
        "Intermediate Certification Authorities" { [System.Security.Cryptography.X509Certificates.StoreName]::CertificateAuthority }
        "Untrusted Certificates" { [System.Security.Cryptography.X509Certificates.StoreName]::Disallowed }
        "Trusted People" { [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople }
        "Other People" { [System.Security.Cryptography.X509Certificates.StoreName]::AddressBook }
        Default {
            Write-Host "[Error] Invalid or unsupported certificate store: ($CertificateStore)"
            Write-Host "[Info] Supported certificate stores:"
            Write-Host " Personal,"
            Write-Host " Trusted Root Certification Authorities,"
            Write-Host " Third-Party Root Certification Authorities,"
            Write-Host " Trusted Publisher,"
            Write-Host " Intermediate Certification Authorities,"
            Write-Host " Untrusted Certificates,"
            Write-Host " Trusted People,"
            Write-Host " Other People"
            exit 1
        }
    }

    # Check if the certificate store exists based on the object type or path
    if ($CertStore.GetType() -ne [System.Security.Cryptography.X509Certificates.StoreName] -and -not (Test-Path cert:\$CertStore -ErrorAction SilentlyContinue)) {
        Write-Host "[Error] Certificate store ($CertificateStore) does not exist"
        exit 1
    }
}
process {
    # Generate a unique identifier for the certificate temporary file
    $CertUID = New-Guid | Select-Object -ExpandProperty Guid
    $CertPath = "$env:TEMP\cert$($CertUID)"

    # Determine the file type of the certificate
    if ($CertificatePath -like "*.*") {
        switch ($CertificatePath.Split(".")[-1]) {
            "pfx" { $CertPath += ".pfx" }
            "cer" { $CertPath += ".cer" }
            "sst" { $CertPath += ".sst" }
            "p7b" { $CertPath += ".p7b" }
            "pem" { $CertPath += ".pem" }
            Default {
                Write-Host "[Error] Invalid certificate file type (pfx, cer, pem, sst, p7b supported): $CertificatePath"
                exit 1
            }
        }
    }
    else {
        Write-Host "[Error] Certificate file missing extenstion (pfx, cer, pem, sst, p7b supported): $CertificatePath"
        exit 1
    }

    if ($CertificatePath -like "http*") {
        # Check if the $CertificatePath is a URL
        if ($CertificatePath -notmatch "^http(s)?://") {
            Write-Host "[Error] Invalid URL format: $CertificatePath"
            exit 1
        }

        # Warn if http is used
        if ($CertificatePath -match "^http://") {
            Write-Host "[Warn] The certificate is being downloaded over an insecure connection. Ensure the certificate is from a trusted source."
        }

        # Download the certificate if it is a URL
        Invoke-Download -URL $CertificatePath -Path $CertPath
    }
    else {
        # Copy the certificate to the temp directory
        if (-not (Test-Path $CertificatePath)) {
            Write-Host "[Error] Certificate path does not exist"
            exit 1
        }
        try {
            Copy-Item -Path $(Resolve-Path -Path $CertificatePath) -Destination $CertPath -Force
        }
        catch {
            Write-Host "[Error] Failed to copy certificate from path ($CertificatePath)"
            exit 1
        }
    }

    # Initialize the certificate object and load the certificate
    $Certificate = if ($CertPassword) {
        $FailedImport = $false
        try {
            # Get the certificate type
            Write-Host "[Info] Getting certificate type"
            $CertType = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($CertPath)
            Write-Host "[Info] Certificate type: $CertType"

            # Set the flags based on context
            $Flags = if (Test-IsSystem) {
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            }
            else {
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet -bor
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
            }

            # Load the certificate based on the type
            switch ($CertType) {
                "Unknown" {
                    Write-Host "[Error] Certificate file is empty or invalid: $CertPath"
                    exit 1
                }
                { "$_" -in @("Cert", "SerializedCert") } {
                    Write-Host "[Info] Loading$(if($CertType){$CertType}) Certificate"
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
                    Write-Host "[Info] Loaded$(if($CertType){$CertType}) Certificate"
                }
                { "$_" -in @("Pfx", "Pkcs12", "SerializedStore", "Pkcs7", "Authenticode") } {
                    Write-Host "[Info] Loading $CertType Certificate"
                    $Cc = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
                    $Cc.Import($CertPath)
                    Write-Host "[Info] Loaded $CertType Certificate"
                    $Cc
                }
                default {
                    throw "Invalid certificate type: $CertType"
                }
            }
        }
        catch {
            $FailedImport = $true
        }
        if ($FailedImport) {
            try {
                # Try to load the certificate with out flags
                [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath, $CertPassword)
            }
            catch {
                Write-Host "[Error] Failed to load certificate from path ($CertificatePath)"
                if ($_.Exception.Message -like "") {
                    Write-Host "[Error] Certificate file is empty or invalid: $CertificatePath"
                }
                else {
                    switch -Regex ($_.Exception.Message) {
                        "Cannot find the original signer" {
                            Write-Host "[Error] Cannot find the original signer"
                        }
                        "Invalid certificate type" {
                            Write-Host "[Error] Invalid certificate type: $CertType"
                        }
                        default {
                            Write-Host "[Error] $($_)"
                        }
                    }
                }
                Remove-Item -Path $CertPath -Force -ErrorAction SilentlyContinue
                exit 1
            }
        }
    }
    else {
        $FailedImport = $false
        try {
            # Get the certificate type
            Write-Host "[Info] Getting certificate type"
            $CertType = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($CertPath)
            Write-Host "[Info] Certificate type: $CertType"

            # Load the certificate based on the type
            switch ($CertType) {
                "Unknown" {
                    Write-Host "[Error] Certificate file is empty or invalid: $CertPath"
                    exit 1
                }
                { "$_" -in @("Cert", "SerializedCert") } {
                    Write-Host "[Info] Loading$(if($CertType -like "SerializedCert"){" $CertType"}) Certificate"
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
                    Write-Host "[Info] Loaded$(if($CertType -like "SerializedCert"){" $CertType"}) Certificate"
                }
                { "$_" -in @("Pfx", "Pkcs12", "SerializedStore", "Pkcs7", "Authenticode") } {
                    Write-Host "[Info] Loading $CertType Certificate"
                    $Cc = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
                    $Cc.Import($CertPath)
                    Write-Host "[Info] Loaded $CertType Certificate"
                    $Cc
                }
                default {
                    throw "Invalid certificate type: $CertType"
                }
            }
        }
        catch {
            Write-Host "[Error] Failed to load certificate from path ($CertificatePath)"
            if ($_.Exception.Message -like "") {
                Write-Host "[Error] Certificate file is empty or invalid: $CertificatePath"
            }
            else {
                switch -Regex ($_.Exception.Message) {
                    "Cannot find the original signer" {
                        Write-Host "[Error] Cannot find the original signer"
                    }
                    "Invalid certificate type" {
                        Write-Host "[Error] Invalid certificate type: $CertType"
                    }
                    default {
                        Write-Host "[Error] $($_)"
                    }
                }
            }
            Remove-Item -Path $CertPath -Force -ErrorAction SilentlyContinue
            exit 1
        }
    }

    # Create a new X509Store object
    try {
        $Store = if (Test-IsSystem) {
            # X509Store: https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store?view=netframework-4.8.1
            [System.Security.Cryptography.X509Certificates.X509Store]::new($CertStore, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        }
        else {
            [System.Security.Cryptography.X509Certificates.X509Store]::new($CertStore, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
        }
    }
    catch {
        Write-Host "[Error] Failed to create certificate store object"
        Write-Host "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Open the certificate store
    try {
        $Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
        Write-Host "[Info] Certificate store ($CertificateStore) opened with Read/Write access"
    }
    catch {
        Write-Host "[Error] Failed to open certificate store with read and write access"
        Write-Host "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Check if the certificate is already installed
    if ($Certificate -and (
            # Check if the certificate is a collection
            $Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2Collection] -or
            $Certificate -is [System.Object[]]
        )
    ) {
        # Check if any certificates in the collection are already installed
        $Certificate | Where-Object {
            $Store.Certificates.Thumbprint -contains $_.Thumbprint
        } | ForEach-Object {
            $cert = $_
            if ($OverwriteCertificateIfExisting) {
                # Remove existing certificate with the same thumbprint
                Write-Output "[Info] Overwriting existing certificate"
                $RemoveErrors = [System.Collections.Generic.List[String]]::new()
                $Store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | ForEach-Object {
                    try {
                        Write-Host "[Info] Removing existing certificate: $($_.FriendlyName)(Thumbprint: $($_.Thumbprint))"
                        $Store.Remove($_)
                        Write-Host "[Info] Certificate removed"
                    }
                    catch {
                        Write-Host "[Error] Failed to remove existing certificate"
                        Write-Host "[Error] $($_.Exception.Message)"
                        $RemoveErrors.Add(
                            [PSCustomObject]@{
                                Error       = $_.Exception.Message
                                Certificate = $_.FriendlyName
                                thumbprint  = $_.Thumbprint
                            }
                        )
                    }
                }
    
                # Check if any errors occurred while removing certificates
                if ($RemoveErrors.Count -gt 0) {
                    # Display the errors and exit
                    Write-Host "[Error] Failed to remove the following certificates:"
                    $RemoveErrors | ForEach-Object {
                        Write-Host "[Error] Certificate: $($_.Certificate)(Thumbprint: $($_.thumbprint))"
                    }
                    exit 1
                }
            }
        }
    }
    elseif ($Certificate -and $Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        # Check if the certificate is already installed
        if ($Store.Certificates.Thumbprint -contains $Certificate.Thumbprint) {
            if ($OverwriteCertificateIfExisting) {
                # Remove existing certificate with the same thumbprint
                Write-Output "[Info] Overwriting existing certificate"
                $RemoveErrors = [System.Collections.Generic.List[String]]::new()
                $Store.Certificates | Where-Object { $_.Thumbprint -eq $Certificate.Thumbprint } | ForEach-Object {
                    try {
                        Write-Host "[Info] Removing existing certificate: $($_.FriendlyName)(Thumbprint: $($_.Thumbprint))"
                        $Store.Remove($_)
                        Write-Host "[Info] Certificate removed"
                    }
                    catch {
                        Write-Host "[Error] Failed to remove existing certificate"
                        Write-Host "[Error] $($_.Exception.Message)"
                        $RemoveErrors.Add(
                            [PSCustomObject]@{
                                Error       = $_.Exception.Message
                                Certificate = $_.FriendlyName
                                thumbprint  = $_.Thumbprint
                            }
                        )
                    }
                }

                # Check if any errors occurred while removing certificates
                if ($RemoveErrors.Count -gt 0) {
                    # Display the errors and exit
                    Write-Host "[Error] Failed to remove the following certificates:"
                    $RemoveErrors | ForEach-Object {
                        Write-Host "[Error] Certificate: $($_.Certificate)(Thumbprint: $($_.thumbprint))"
                    }
                    exit 1
                }
            }
            else {
                Write-Output "[Info] Certificate already installed"
                exit 0
            }
        }
    }
    else {
        Write-Host "[Error] Check: Invalid certificate object type (X509Certificate2 or X509Certificate2Collection expected)"
        if ($Certificate) {
            Write-Host "[Error] Certificate type: $($Certificate.GetType())"
            Write-Host "[Error] Certificate:"
            $($Certificate) | Out-String | Write-Host
        }
        else {
            Write-Host "[Error] Certificate object is null"
        }
        exit 1
    }

    # Install the certificate to the specified store
    if ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2Collection] -or $Certificate -is [System.Object[]]) {
        # Install each certificate in the collection
        try {
            if ($Certificate -is [System.Object[]]) {
                $Certificate | ForEach-Object {
                    $Store.Add($_)
                    Write-Host "[Info] Certificate added to store: $($_.FriendlyName)(Thumbprint: $($_.Thumbprint))"
                }
            }
            else {
                $Store.AddRange($Certificate)
                $Certificate | ForEach-Object {
                    Write-Host "[Info] Certificate added to store: $($_.FriendlyName)(Thumbprint: $($_.Thumbprint))"
                }
            }
        }
        catch {
            Write-Host "[Error] Failed to add certificates to store"
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
    elseif ($Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
        # Install the certificate
        try {
            $Store.Add($Certificate)
            Write-Host "[Info] Certificate added to store: $($Certificate.FriendlyName)(Thumbprint: $($Certificate.Thumbprint))"
        }
        catch {
            Write-Host "[Error] Failed to add certificate to store"
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
    else {
        Write-Host "[Error] Add: Invalid certificate object type (X509Certificate2 or X509Certificate2Collection expected)"
        exit 1
    }

    # Close the certificate store
    try {
        $Store.Close()
        Write-Host "[Info] Certificate store($CertificateStore) closed"
    }
    catch {
        Write-Host "[Warn] Failed to close certificate store"
        Write-Host "[Error] $($_.Exception.Message)"
    }

    Write-Output "[Info] Certificate installed successfully"

    exit 0
}
end {
    
    
    
}
