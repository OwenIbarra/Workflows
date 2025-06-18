# Run the Microsoft Safety Scanner, collect the results, and optionally save the results to a multiline custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Run the Microsoft Safety Scanner, collect the results, and optionally save the results to a multiline custom field.
.DESCRIPTION
    Run the Microsoft Safety Scanner, collect the results, and optionally save the results to a multiline custom field.
.EXAMPLE
    (No Parameters)
    
    Downloading MSERT from https://go.microsoft.com/fwlink/?LinkId=212732
    Waiting for 3 seconds.
    Download Attempt 1
    Download Successful!
    Initiating Scan
    Exit Code: 7
    [Critical] Infections found!

    ---------------------------------------------------------------------------------------
    Microsoft Safety Scanner v1.405, (build 1.405.445.0)
    Started On Thu Feb 22 13:33:34 2024

    Engine: 1.1.24010.10
    Signatures: 1.405.445.0
    MpGear: 1.1.16330.1
    Run Mode: Scan Run in Quiet Mode

    Quick Scan Results:
    -------------------
    Threat Detected: Virus:DOS/EICAR_Test_File, not removed.
        Action: NoAction, Result: 0x00000000
            file://C:\Windows\system32\eicarcom2.zip->eicar_com.zip->eicar.com
                SigSeq: 0x00000555DC2DDDB0
            file://C:\Windows\system32\eicar.com
                SigSeq: 0x00000555DC2DDDB0
            file://C:\Windows\eicar.com
                SigSeq: 0x00000555DC2DDDB0
            containerfile://C:\Windows\system32\eicarcom2.zip

    Results Summary:
    ----------------
    Found Virus:DOS/EICAR_Test_File, not removed.
    Successfully Submitted MAPS Report
    Successfully Submitted Heartbeat Report
    Microsoft Safety Scanner Finished On Thu Feb 22 13:35:58 2024


    Return code: 7 (0x7)

PARAMETER: -ScanType "Full"
    Specifies the type of scan to perform. "Full" for a complete disk scan, or "Quick" for a scan of common exploit locations.

PARAMETER: -Timeout "ReplaceMeWithANumber"
    Sets a time limit for the scan in minutes. If the scan exceeds this duration, it is canceled, and an error is output. Replace "ReplaceMeWithANumber" with the desired time limit in minutes.

PARAMETER: -CustomField "ReplaceWithNameOfCustomField"
    Specifies the name of the multiline custom field where scan results are optionally saved. Enter the field name to enable this feature.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$ScanType = "Quick",
    [Parameter()]
    [Int]$Timeout = 30,
    [Parameter()]
    [String]$CustomField,
    [Parameter()]
    [String]$DownloadURL = "https://go.microsoft.com/fwlink/?LinkId=212732"
)

begin {
    # Set parameters using dynamic script variables.
    if($env:scanType -and $env:scanType -notlike "null"){ $ScanType = $env:scanType }
    if($env:scanTimeoutInMinutes -and $env:scanTimeoutInMinutes -notlike "null"){ $Timeout = $env:scanTimeoutInMinutes }
    if($env:customFieldName -and $env:customFieldName -notlike "null"){ $CustomField = $env:customFieldName }

    # If a timeout is specified, check that it's in the valid range.
    if($Timeout -lt 1 -or $Timeout -ge 120){
        Write-Host "[Error] Timeout must be greater than or equal to 1 minute and less than 120 minutes."
        exit 1
    }

    # If we're not given a scan type, error out.
    if(-not $ScanType){
        Write-Host "[Error] Please select a scan type (Quick or Full)."
        exit 1
    }

    # Check that the scan type is valid.
    switch($ScanType){
        "Quick" { Write-Verbose "Quick Scan Selected!"}
        "Full" { Write-Verbose "Full Scan Selected!" }
        default { 
            Write-Host "[Error] Invalid scan type selected!"
            exit 1
        }
    } 

    # Checks for local administrator rights.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
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

            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
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

                $ProgressPreference = $PreviousProgressPreference
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

        if (-not (Test-Path -Path $Path)) {
            [PSCustomObject]@{
                ExitCode = 1
            }
        }
        else {
            [PSCustomObject]@{
                ExitCode = 0
            }
        }
    }

    # Utility function to help set custom fields
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
    
        $Characters = $Value | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if($Characters -ge 10000){
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than 10,000 characters.")
        }
        
        # If we're requested to set the field value for a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
        
        # This is a list of valid fields that can be set. If no type is given, it will be assumed that the input doesn't need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
        
        # The field below requires additional information to be set
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
        
        # If an error is received it will have an exception property, the function will exit with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
        
        # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the  Date-Time to be in Unix Epoch time so we'll convert it here.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
        
                if (-not $Selection) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown")
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
    
    $ExitCode = 0

    # If the log file already exists remove it.
    if(Test-Path -Path "$env:SYSTEMROOT\debug\msert.log"){
        Remove-Item -Path "$env:SYSTEMROOT\debug\msert.log" -Force -ErrorAction SilentlyContinue
    }
}
process {
    # Error out if we don't have local admin permissions.
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Download MSERT.
    Write-Host "Downloading MSERT from $DownloadURL"
    $MSERTPath = "$env:TEMP\MSERT.exe"
    $Download = Invoke-Download -Path $MSERTPath -URL $DownloadURL
    if($Download.ExitCode -ne 0){
        Write-Host "[Error] Failed to download MSERT please check that $DownloadURL is reachable!"
        exit 1
    }

    Write-Host "Download Successful!"

    # Start the MSERT Scan with the parameters given.
    Write-Host "Initiating Scan"
    $Arguments = New-Object System.Collections.Generic.List[string]
    if($ScanType -eq "Full"){
        $Arguments.Add("/F")
    }
    $Arguments.Add("/Q")
    $Arguments.Add("/N")

    try{
        # Run it with our specified timeout.
        $TimeoutInSeconds = $Timeout * 60
        $MSERTProcess = Start-Process -FilePath $MSERTPath -ArgumentList $Arguments -NoNewWindow -PassThru
        $MSERTProcess | Wait-Process -Timeout $TimeoutInSeconds -ErrorAction Stop
    }catch{
        Write-Host "[Alert] The Microsoft Safety Scanner exceeded the specified timeout of $Timeout minutes, and the script is now terminating."
        $MSERTProcess | Stop-Process -Force
        $TimedOut = $True
        $ExitCode = 1
    }
    Write-Host "Exit Code: $($MSERTProcess.ExitCode)"

    # If the report is missing, something has clearly gone wrong.
    if(-not (Test-Path -Path $env:SYSTEMROOT\debug\msert.log)){
        Write-Host "[Error] The report from MSERT.exe is missing?"
        exit 1
    }

    # Get the contents of the MSERT log and error out if it's blank.
    $Report = Get-Content -Path "$env:SYSTEMROOT\debug\msert.log"
    if(-not $Report){
        Write-Host "[Error] The report from MSERT.exe is empty?"
        exit 1
    }

    # If threats are detected, send out the alert.
    $Report | ForEach-Object {
        if($_ -match "No infection found"){
            $NoInfectionFoundTextPresent = $True
        }

        if($_ -match "Threat Detected" ){
            $ThreatDetectedTextPresent = $True
        }
    }

    
    if(($ThreatDetectedTextPresent -or -not $NoInfectionFoundTextPresent) -and -not $TimedOut){
        Write-Host "[Critical] Infections found!"
    }elseif($ExitCode -ne 1 -and -not $TimedOut){
        Write-Host "[Success] Scan has completed no infections detected."
    }

    # Save to a custom field upon request.
    if($CustomField){
        try {
            Write-Host "Attempting to set Custom Field '$CustomField'."
            Set-NinjaProperty -Name $CustomField -Value ($Report | Out-String)
            Write-Host "Successfully set Custom Field '$CustomField'!"
        }
        catch {
            if($_.Exception.Message){
                Write-Host "[Error] $($_.Exception.Message)"
            }

            if($_.Message){
                Write-Host "[Error] $($_.Message)"
            }

            $ExitCode = 1
        }
    }

    # Send out the report to the activity log.
    $Report | Write-Host

    # Remove the old log file.
    if(Test-Path -Path "$env:SYSTEMROOT\debug\msert.log"){
        Remove-Item -Path "$env:SYSTEMROOT\debug\msert.log" -Force -ErrorAction SilentlyContinue
    }

    # Exit.
    exit $ExitCode
}
end {
    
    
     
}
