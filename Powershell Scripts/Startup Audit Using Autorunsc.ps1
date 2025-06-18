# Runs Autorunsc with your selected options and outputs the results to the activity log and optionally a WYSIWYG custom field. Please note that there is a limit to the number of results that can be set in Custom Fields or viewed in the Activity Log.
#Requires -Version 4

<#
.SYNOPSIS
    Runs Autorunsc with your selected options and outputs the results to the activity log and optionally a WYSIWYG custom field. Please note that there is a limit to the number of results that can be set in Custom Fields or viewed in the Activity Log.
.DESCRIPTION
    Runs Autorunsc with your selected options and outputs the results to the activity log and optionally a WYSIWYG custom field. Please note that there is a limit to the number of results that can be set in Custom Fields or viewed in the Activity Log.
.EXAMPLE
    (No Parameters)
    URL Given, Downloading the file...
    Download Attempt 1
    HKCU:\SOFTWARE\Sysinternals\AutoRuns\EulaAccepted changed from 1 to 1

    Sysinternals Autoruns v14.10 - Autostart program viewer
    Copyright (C) 2002-2023 Mark Russinovich
    Sysinternals - www.sysinternals.com

    WARNING: Script must be elevated in order to write to custom field.
    
    Entry          : C:\Windows\system32\userinit.exe
    Entry Location : HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
    Image Path     : c:\windows\system32\userinit.exe
    Signer         : (Verified) Microsoft Windows
    MD5            : 9C4C281156040CF01EA35D759092F540

    Entry          : cmd.exe
    Entry Location : HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell
    Image Path     : c:\windows\system32\cmd.exe
    Signer         : (Verified) Microsoft Windows
    MD5            : 8A2122E8162DBEF04694B9C3E0B6CDEE

PARAMETER: -CustomField "ReplaceWithAMultilineCustomField"
    The name of the multiline custom field you would like to save the results to.

PARAMETER: -Startup
    Applications or scripts configured to run automatically after a user logs into their account. This is the default option for Autoruns. 
    E.g. Applications in the 'Startup' folder.

PARAMETER: -Boot
    Programs or commands that are set to execute during the system's boot-up sequence before a user logs in.

PARAMETER: -WinLogon
    Items that are configured to run during the Windows logon process. Often these items are critical to the logon UI.

PARAMETER: -AppInit
    DLLs that are automatically loaded by every process that calls the User32.dll file (anything with a GUI).

PARAMETER: -Explorer
    Plugins or extensions that integrate into the Windows Explorer shell.

PARAMETER: -Sidebar
    Mini applications or gadgets that load into the desktop sidebar in earlier versions of Windows (introduced in Windows Vista).

PARAMETER: -ImageHijacks
    Registry modifications that redirect the execution of specific executable files to a different program.

PARAMETER: -IEAddons
    Browser extensions or toolbars that Internet Explorer will load automatically when it starts.

PARAMETER: -KnownDLLs
    Crucial system DLLs that Windows will load into memory at startup.

PARAMETER: -WMIentries
    Entries related to WMI scripts or providers that are set to execute automatically.

PARAMETER: -WinSockProtocols
    Modules or services meant to load up with the Windows network stack.

PARAMETER: -Codecs
    Software components meant to be used for encoding or decoding digital media streams (often set to run at system startup).

PARAMETER: -PrinterMonitor
    DLL's associated with printer drivers.

PARAMETER: -LSAProviders
    Plugins that integrate with the Local Security Authority subsystem.

PARAMETER: -Services
    Windows Services set to start Automatically.

PARAMETER: -ScheduledTasks
    These are tasks set in Task Scheduler to do something automatically at a specified interval.

PARAMETER: -HideMicrosoftEntries
    Hides Signed Microsoft Entries from the results.

PARAMETER: -DestinationFolder
    By default this script downloads autorunsc to the temp folder.

PARAMETER: -DownloadUrl
    URL to download Autoruns from.

PARAMETER: -SkipSleep
    Skips sleeping prior to downloading autorunsc.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2012
    Release Notes: Added support for WYSIWYG new character limit; now truncates results if results are too long.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomField,
    [Parameter()]
    [Switch]$Startup = [System.Convert]::ToBoolean($env:checkLogonStartupEntries),
    [Parameter()]
    [Switch]$Boot = [System.Convert]::ToBoolean($env:checkBootEntries),
    [Parameter()]
    [Switch]$WinLogon = [System.Convert]::ToBoolean($env:checkWinlogonEntries),
    [Parameter()]
    [Switch]$AppInit = [System.Convert]::ToBoolean($env:checkAppinitEntries),
    [Parameter()]
    [Switch]$Explorer = [System.Convert]::ToBoolean($env:checkExplorerAddons),
    [Parameter()]
    [Switch]$Sidebar = [System.Convert]::ToBoolean($env:checkSidebarGadgets),
    [Parameter()]
    [Switch]$ImageHijacks = [System.Convert]::ToBoolean($env:checkImageHijacks),
    [Parameter()]
    [Switch]$IEAddons = [System.Convert]::ToBoolean($env:checkInternetExplorerAddons),
    [Parameter()]
    [Switch]$KnownDLLs = [System.Convert]::ToBoolean($env:checkKnownDlls),
    [Parameter()]
    [Switch]$WMIentries = [System.Convert]::ToBoolean($env:checkWmiEntries),
    [Parameter()]
    [Switch]$WinSockProtocols = [System.Convert]::ToBoolean($env:checkWinsockProtocol),
    [Parameter()]
    [Switch]$Codecs = [System.Convert]::ToBoolean($env:checkCodecs),
    [Parameter()]
    [Switch]$PrinterMonitor = [System.Convert]::ToBoolean($env:checkPrinterMonitorDlls),
    [Parameter()]
    [Switch]$LSAProviders = [System.Convert]::ToBoolean($env:checkLsaSecurityProviders),
    [Parameter()]
    [Switch]$Services = [System.Convert]::ToBoolean($env:checkAutostartServices),
    [Parameter()]
    [Switch]$ScheduledTasks = [System.Convert]::ToBoolean($env:checkScheduledTasks),
    [Parameter()]
    [Switch]$HideMicrosoftEntries = [System.Convert]::ToBoolean($env:hideMicrosoftEntries),
    [Parameter()]
    [String]$DestinationFolder = "$env:Temp",
    [Parameter()]
    [String]$DownloadUrl = "https://download.sysinternals.com/files/Autoruns.zip",
    [Parameter()]
    [Switch]$SkipSleep = [System.Convert]::ToBoolean($env:skipSleep)
)

begin {

    # If Script Forms are used replace the parameters
    if ($env:destinationFolder -and $env:DestinationFolder -notlike "null") { $DestinationFolder = $env:destinationFolder }
    if ($env:downloadUrl -and $env:downloadUrl -notlike "null") { $DownloadUrl = $env:downloadUrl }
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        function Expand-Archive {
            [CmdletBinding()]
            param(
                [Parameter()]
                [String]$Path,
                [Parameter()]
                [String]$DestinationPath,
                [Parameter()]
                [Switch]$Force
            )
            begin {
                Add-Type -assembly "System.IO.Compression.FileSystem"
            }
            process {
                if ($Force -and (Test-Path $DestinationPath)) {
                    $ZipFile = [System.IO.Compression.ZipFile]::OpenRead($Path)

                    $ZipFile.Entries | ForEach-Object {
                        $Destination = [System.IO.Path]::Combine($DestinationPath, $_.FullName)
                        $DestinationDir = [System.IO.Path]::GetDirectoryName($Destination)
                        if (-not (Test-Path $DestinationDir)) {
                            New-Item -ItemType Directory -Path $DestinationDir -Force
                        }
                        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $Destination, $True)
                    }
                    $ZipFile.Dispose()
                }
                else {
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($Path, $DestinationPath)
                }
            }
        }
    }

    # Handy download function
    function Invoke-Download {
        param(
            [Parameter()]
            [String]$URL,
            [Parameter()]
            [String]$Path,
            [Parameter()]
            [Switch]$SkipSleep
        )

        Write-Host "URL Given, Downloading the file..."

        $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
        if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
        }
        elseif ( $SupportedTLSversions -contains 'Tls12' ) {
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        }
        else {
            # Not everything requires TLS 1.2, but we'll try anyways.
            Write-Warning "TLS 1.2 and or TLS 1.3 isn't supported on this system. This download may fail!"
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
            }
        }

        $i = 1
        While ($i -lt 4) {
            if (-not ($SkipSleep)) {
                $SleepTime = Get-Random -Minimum 3 -Maximum 60
                Start-Sleep -Seconds $SleepTime
            }

            Write-Host "Download Attempt $i"

            try {
                $WebClient = New-Object System.Net.WebClient
                $WebClient.DownloadFile($URL, $Path)
            }
            catch {
                Write-Warning "An error has occurred while downloading!"
            }

            $File = Test-Path -Path $Path -ErrorAction SilentlyContinue
            if ($File) {
                $i = 4
            }
            else {
                $i++
            }
        }

        if (-not $File) { 
            Write-Error -Message "File failed to download!" -Category DeviceError -Exception (New-Object System.Exception)
            Exit 1 
        }
    }

    # Need to set Regkey to accept EULA
    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
        if (-not $(Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            New-Item -Path $Path -Force | Out-Null
        }
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error -Message "[Error] Unable to Set registry key for $Name please see below error!" -Category DeviceError -Exception (New-Object System.Exception)
                Write-Error $_
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error -Message "[Error] Unable to Set registry key for $Name please see below error!" -Category DeviceError -Exception (New-Object System.Exception)
                Write-Error $_
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
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
            [String]$DocumentName
        )

        $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded, value is greater than or equal to 200,000 characters.")
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
                # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, the given value will be matched with a GUID.
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
            $CustomField = $NinjaValue | Ninja-Property-Docs-Set -AttributeName $Name @DocumentationParams 2>&1
        }
        else {
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
    
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    # Test for elevation
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    $ExitCode = 0
}
process {

    # Take the script parameters and translate them into Autoruns options.
    if ($Startup) { $AutorunOptions = "l" }
    if ($Boot) { $AutorunOptions = "$($AutorunOptions)b" }
    if ($Winlogon) { $AutorunOptions = "$($AutorunOptions)w" }
    if ($AppInit) { $AutorunOptions = "$($AutorunOptions)d" }
    if ($Explorer) { $AutorunOptions = "$($AutorunOptions)e" }
    if ($Sidebar) { $AutorunOptions = "$($AutorunOptions)g" }
    if ($ImageHijacks) { $AutorunOptions = "$($AutorunOptions)h" }
    if ($IEAddons) { $AutorunOptions = "$($AutorunOptions)i" }
    if ($KnownDLLs) { $AutorunOptions = "$($AutorunOptions)k" }
    if ($WMIentries) { $AutorunOptions = "$($AutorunOptions)m" }
    if ($WinSockProtocols) { $AutorunOptions = "$($AutorunOptions)n" }
    if ($Codecs) { $AutorunOptions = "$($AutorunOptions)o" }
    if ($PrinterMonitor) { $AutorunOptions = "$($AutorunOptions)p" }
    if ($LSAProviders) { $AutorunOptions = "$($AutorunOptions)r" }
    if ($Services) { $AutorunOptions = "$($AutorunOptions)s" }
    if ($ScheduledTasks) { $AutorunOptions = "$($AutorunOptions)t" }

    if (-not $AutorunOptions) {
        Write-Host -Object "[Error] No Autoruns options selected. Please at least select one option to search for autostart entries."
        exit 1
    }

    # Download the file and unzip its contents
    $DownloadArguments = @{
        URL  = $DownloadUrl
        Path = "$DestinationFolder\Autoruns.zip"
    }
    if ($SkipSleep) { $DownloadArguments["SkipSleep"] = $true }

    # Download and unzip
    Invoke-Download @DownloadArguments
    Expand-Archive -Path "$DestinationFolder\Autoruns.zip" -DestinationPath "$DestinationFolder\Autoruns" -Force

    if (-not (Test-Path "$DestinationFolder\Autoruns\autorunsc64.exe" -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] Failed to unzip Autoruns"
        exit 1
    }

    # Now that we have the options create an argument list using those options
    $ArgumentList = New-Object System.Collections.Generic.List[string]
    $ArgumentList.Add("-a $AutorunOptions")
    $ArgumentList.Add("-h")
    $ArgumentList.Add("-c")
    $ArgumentList.Add("-s")
    if ($HideMicrosoftEntries) { $ArgumentList.Add("-m") }

    # Accept EULA
    Set-RegKey -Path "HKCU:\SOFTWARE\Sysinternals\AutoRuns" -Name "EulaAccepted" -Value 1

    # Run autoruns and store the results as a csv and then import the results into powershell
    Start-Process "$DestinationFolder\Autoruns\autorunsc64.exe" -ArgumentList $ArgumentList -NoNewWindow -RedirectStandardOutput "$DestinationFolder\Autoruns\autorunsc.csv" -Wait
    $AutorunResults = Import-Csv "$DestinationFolder\Autoruns\autorunsc.csv" | Where-Object { $_.Entry } | Sort-Object Entry | Select-Object Entry, "Entry Location", "Image Path", Signer, MD5

    if (-not ($AutorunResults)) {
        Write-Host -Object "[Error] No startup entries found. Is Autorunsc being blocked?"
        $ExitCode = 1
    }

    # Set the custom field with the Autoruns results.
    if ($CustomField) {
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Write-Warning "Ninjarmm-cli does not support setting custom fields using PowerShell 2.0"
            $ExitCode = 1
        }
        
        if ( -not (Test-IsElevated)) {
            Write-Warning "Script must be elevated in order to write to custom field."
            $ExitCode = 1
        }

        try {
            Write-Host "Attempting to set Custom Field '$CustomField'."

            # Initialize html report.
            $htmlReport = New-Object System.Collections.Generic.List[string]
            
            # Create html table based on our results.
            $htmlTable = $AutorunResults | ConvertTo-Html -Fragment

            # Gather all the unsigned and unverified results.
            $UnsignedResults = $AutorunResults | Where-Object { -not $_.Signer }
            $UnverifiedResults = $AutorunResults | Where-Object { $_.Signer -like "*Not verified*" }

            # Loop through the html table and change the table row class for the unsigned entries.
            $UnsignedResults | ForEach-Object {
                $htmlTable = $htmlTable -replace "<tr><td>$([Regex]::Escape($_.Entry))</td><td>$([Regex]::Escape($_.'Entry Location'))</td><td>$([Regex]::Escape($_.'Image Path'))</td><td></td>", "<tr class=`"danger`"><td>$($_.Entry)</td><td>$($_.'Entry Location')</td><td>$($_.'Image Path')</td><td></td>"
            }

            # Loop through the html table and change the table row class for the unverified entries.
            $UnverifiedResults | ForEach-Object {
                $htmlTable = $htmlTable -replace "<tr><td>$([Regex]::Escape($_.Entry))</td><td>$([Regex]::Escape($_.'Entry Location'))</td><td>$([Regex]::Escape($_.'Image Path'))</td><td>$([Regex]::Escape($_.Signer))</td>", "<tr class=`"warning`"><td>$($_.Entry)</td><td>$($_.'Entry Location')</td><td>$($_.'Image Path')</td><td>$($_.Signer)</td>"
            }

            # Check to see if we're at the character limit for WYSIWYG fields.
            $Characters = $htmlTable | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters

            # If we're within 500 characters of the limit we'll output a warning and add some text to the report to indicate that we're truncating the report.
            if ($Characters -ge 199500) {
                Write-Warning "200,000 Character Limit has been reached! Trimming rows until the character limit is satisfied..."
                $htmlReport.Add("<h1>This info has been truncated to accommodate the 200,000 character limit.</h1>")

                # We'll want to truncate the last entries from the report so we'll reverse the string array and look for table row entries.
                [array]::Reverse($htmlTable)
                $i = 0
                do {
                    # If a table row entry has been found we'll remove it and then check if we satisfy the limit.
                    if ($htmlTable[$i] -match '<tr><td>') {
                        $htmlTable[$i] = $null
                    }
                    $i++
                    $Characters = $htmlTable | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
                }while ($Characters -ge 199500)

                # Now that the limit has been satisfied we'll reverse the table/string array again.
                [array]::Reverse($htmlTable)
            }

            # Add the table to the report.
            $htmlReport.Add($htmlTable)

            # Set the custom field.
            Set-NinjaProperty -Name $CustomField -Value $htmlReport
            Write-Host "Successfully set Custom Field '$CustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            $ExitCode = 1
        }
    }

    # Clean up our leftover files.
    Remove-Item "$DestinationFolder\Autoruns" -Recurse -Force
    Remove-Item "$DestinationFolder\Autoruns.zip" -Force

    # Output results into activity log. Using Format-List due to size of table.
    $AutorunResults | Sort-Object Entry | Format-List

    exit $ExitCode
}
end {
    
    
    
}
