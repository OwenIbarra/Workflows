# Saves a Wireless LAN report to a WYSIWYG Custom Field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Saves a Wireless LAN report to a WYSIWYG Custom Field.
.DESCRIPTION
    Saves a Wireless LAN report to a WYSIWYG Custom Field.
.EXAMPLE
     -CustomField "wlanreport"
    Saves a Wireless LAN report to a WYSIWYG Custom Field.

    --- Wifi Report ---

    ### Wifi Adapters ###

    Interface SSID    Authentication Band   Channel Signal State        RadioType
    --------- ----    -------------- ----   ------- ------ -----        ---------
    Wi-Fi     TestAP1 WPA2-Personal  5.0GHz 157     99%    connected    802.11ac



    ### Other Wifi Networks ###

    SSID       Authentication  Band             Channel Signal
    ----       --------------  ----             ------- ------
               WPA2-Personal   2.4GHz, 6.0GHz   1       95%
    TestAP1    WPA2-Personal   5.0GHz           112     18%
    TestAP2    WPA3-Personal   2.4GHz, 6.0GHz   1       91%
    TestAP3    WPA2-Enterprise 2.4GHz, 6.0GHz   1       98%
    TestAP4    WPA2-Personal   2.4GHz, 6.0GHz   1       94%
    TestAP5    Open            5.0GHz           36      87%
    TestAP6    WPA3-Personal   2.4GHz           1       93%

    [Info] Attempting to set Custom Field 'wysiwygCustomFieldName'.
    [Info] Successfully set Custom Field 'wysiwygCustomFieldName'!

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10
    Release Notes: Renamed script and added Script Variable support
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $CustomField,
    [Parameter()]
    [switch]
    $DebugHtml
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Get-WifiBand {
        param ($RadioType, $Channel)
        @(
            [PSCustomObject]@{ # Wi-Fi 2.4GHz
                RadioType = "802.11b", "802.11g", "802.11n", "802.11ax", "802.11be"
                Band      = "2.4GHz"
                Channels  = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
            }
            [PSCustomObject]@{
                RadioType = "802.11y"
                Band      = "3.65GHz"
                Channels  = 131, 132, 133, 134, 135, 136, 137, 138
            }
            [PSCustomObject]@{
                RadioType = "802.11j"
                Band      = "4.9-5.0GHz"
                Channels  = 7, 8, 9, 11, 12, 16, 183, 184, 185, 187, 188, 189, 192, 193, 194, 195, 196
            }
            [PSCustomObject]@{ # Wi-Fi 5GHz
                RadioType = "802.11a", "802.11h", "802.11n", "802.11ac", "802.11ax", "802.11be"
                Band      = "5.0GHz"
                Channels  = 7, 8, 9, 11, 12, 16, 34, 36, 40, 42, 44, 48, 50, 52, 54, 56, 58, 60, 62, 100, 102,
                104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142,
                144, 149, 151, 153, 155, 157, 159, 161, 165, 193, 184, 185, 187, 188, 189, 192, 196
            }
            [PSCustomObject]@{ # Wiâ€‘Fi 6E
                RadioType = "802.11ax", "802.11be"
                Band      = "6.0GHz"
                Channels  = 1, 2, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43,
                45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 67, 69, 71, 73, 75, 77, 79, 81, 83, 85, 87, 89, 91, 93,
                95, 97, 99, 101, 103, 105, 107, 109, 111, 113, 115, 117, 119, 121, 123, 125, 127, 129, 131, 133, 135,
                137, 139, 141, 143, 145, 147, 149, 151, 153, 155, 157, 159, 161, 163, 165, 167, 169, 171, 173, 175, 177,
                179, 181, 183, 185, 187, 189, 191, 193, 195, 197, 199, 201, 203, 205, 209, 211, 213, 215, 217, 219, 221,
                225, 227, 229, 233
            }
            [PSCustomObject]@{
                RadioType = "802.11p"
                Band      = "5.9GHz"
                Channels  = 172, 174, 176, 178, 180, 182, 184
            }
            [PSCustomObject]@{ # WiGig
                RadioType = "802.11ad", "802.11aj", "802.11ay"
                Band      = "60GHz"
                Channels  = 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17, 18,
                19, 20, 21, 22, 25, 26, 27, 29, 28, 33, 34, 35, 36, 37, 38, 39, 40
            }
            [PSCustomObject]@{
                RadioType = "802.11ah"
                Band      = "900MHz"
                Channels  = 1, 2, 3, 5, 6, 11, 13, 26
            }
        ) | Where-Object {
            $_.RadioType -contains $RadioType -and $_.Channels -contains $Channel
        } | Select-Object -ExpandProperty Band
    }

    function Get-WifiAdapters {
        $NetShOutput = $(netsh.exe wlan show interfaces)
        $IsNext = $false
        $IsLast = $false
        foreach ($Line in $NetShOutput) {
            switch -regex ($Line) {
                "^\s{4}Name\s{1,24}\s:\s(.*)" {
                    $Name = $Matches[1]
                    $IsNext = $true
                }
                default {
                    if ($IsNext) {
                        if ($Line -eq "") {
                            $IsNext = $false
                            $Band = Get-WifiBand -RadioType $RadioType -Channel $Channel
                            if ($null -eq $Band) { $Band = "Unknown" }
                            [PSCustomObject]@{
                                Interface      = $Name
                                SSID           = $Ssid
                                Authentication = $Authentication
                                Band           = $($Band) -join ', '
                                Channel        = $Channel
                                Signal         = $Signal
                                State          = $State
                                RadioType      = $RadioType
                            }
                            $IsLast = $false
                        }
                        else {
                            switch -regex ($Line) {
                                "^\s{4}BSSID\s{1,24}\s:\s(.*)" {
                                    if ($IsLast) {
                                        $Band = Get-WifiBand -RadioType $RadioType -Channel $Channel
                                        if ($null -eq $Band) { $Band = "Unknown" }
                                        [PSCustomObject]@{
                                            Interface      = $Name
                                            SSID           = $Ssid
                                            Authentication = $Authentication
                                            Band           = $($Band) -join ', '
                                            Channel        = $Channel
                                            Signal         = $Signal
                                            State          = $State
                                            RadioType      = $RadioType
                                        }
                                        $IsLast = $false
                                    }
                                }
                                "^\s{4}Description\s{1,24}\s:\s(.*)" { $Description = $Matches[1] }
                                "^\s{4}SSID\s{1,24}\s:\s(.*)" { $Ssid = $Matches[1] }
                                "^\s{4}State\s{1,24}\s:\s(.*)" { $State = $Matches[1] }
                                "^\s{4}Signal\s{1,24}\s:\s(.*)" { $Signal = $Matches[1] }
                                "^\s{4}Radio type\s{1,24}\s:\s(.*)" { $RadioType = $Matches[1] }
                                "^\s{4}Channel\s{1,24}\s:\s(.*)" { $Channel = $Matches[1] }
                                "^\s{4}Authentication\s{1,24}\s:\s(.*)" { $Authentication = $Matches[1] }
                                "^\s{4}Profile\s{1,24}\s:\s(.*)" { $IsLast = $true }
                            }
                        }
                    }
                }
            }
        }
    }

    function Get-WifiAPs {
        $SsidRegex = "^SSID\s[0-9]{1,4}\s:\s(.*)"
        $NetShOutput = $(netsh.exe wlan show networks mode=bssid)
        $IsNext = $false
        $IsLast = $false
        foreach ($Line in $NetShOutput) {
            switch -regex ($Line) {
                $SsidRegex {
                    $Name = [regex]::Match($Line, $SsidRegex).Captures.Groups[1].Value
                    $IsNext = $true
                }
                default {
                    if ($IsNext) {
                        if ($Line -eq "") {
                            $IsNext = $false
                            $Band = Get-WifiBand -RadioType $RadioType -Channel $Channel
                            if ($null -eq $Band) { $Band = "Unknown" }
                            [PSCustomObject]@{
                                SSID           = $Name
                                Authentication = $Authentication
                                Band           = $($Band) -join ', '
                                Channel        = $Channel
                                Signal         = $Signal
                                RadioType      = $RadioType
                            }
                            $IsLast = $false
                        }
                        else {
                            switch -regex ($Line) {
                                "^\s{4}Authentication\s{1,24}\s:\s(.*)" { $Authentication = $Matches[1] }
                                "^\s{4}BSSID\s{1,24}\s:\s(.*)" {
                                    if ($IsLast) {
                                        $Band = Get-WifiBand -RadioType $RadioType -Channel $Channel
                                        if ($null -eq $Band) { $Band = "Unknown" }
                                        [PSCustomObject]@{
                                            SSID           = $Name
                                            Authentication = $Authentication
                                            Band           = $($Band) -join ', '
                                            Channel        = $Channel
                                            Signal         = $Signal
                                            RadioType      = $RadioType
                                        }
                                        $IsLast = $false
                                    }
                                }
                                "^\s{9}SSID\s{1,24}\s:\s(.*)" { $Name = $Matches[1] }
                                "^\s{9}Signal\s{1,24}\s:\s(.*)" { $Signal = $Matches[1] }
                                "^\s{9}Radio type\s{1,24}\s:\s(.*)" { $RadioType = $Matches[1] }
                                "^\s{9}Channel\s{1,24}\s:\s(.*)" { $Channel = $Matches[1]; $IsLast = $true }
                            }
                        }
                    }
                }
            }
        }
    }

    function Get-WifiRadioStatus {
        $NetShOutput = $(netsh.exe wlan show interfaces)
        $RadioStatus = [PSCustomObject]@{
            Hardware = "Off"
            Software = "Off"
        }
        if ($NetShOutput -imatch " connected") {
            # If we are connected to a AP then hardware and software radio status are On
            $RadioStatus.Hardware = "On"
            $RadioStatus.Software = "On"
            return $RadioStatus
        }
        foreach ($Line in $NetShOutput) {
            switch -regex ($Line) {
                "Hardware\s(.*)" { $RadioStatus.Hardware = $Matches[1] }
                "Software\s(.*)" { $RadioStatus.Software = $Matches[1] }
            }
        }
        return $RadioStatus
    }

    function Test-WifiRadioStatus {
        $RadioStatus = Get-WifiRadioStatus
        if ($RadioStatus.Hardware -eq "On" -and $RadioStatus.Software -eq "On") {
            return $true
        }
        else {
            return $false
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
        $Characters = $Value | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 10000) {
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
        # The below types require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports.
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
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1
        }
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }
}

process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    
    if ($env:wysiwygCustomFieldName -and $env:wysiwygCustomFieldName -notlike "null") { $CustomField = $env:wysiwygCustomFieldName }

    if (Test-WifiRadioStatus) {
        Write-Host "[Info] Wifi Radio is On"
    }
    else {
        $RadioStatus = Get-WifiRadioStatus
        Write-Host "[Info] Wi-Fi Radio is $($RadioStatus.Hardware) in Hardware"
        Write-Host "[Info] Wi-Fi Radio is $($RadioStatus.Software) in Software"
        Write-Host "[Warn] Wi-Fi Radio is Off"
    }

    # Get Wifi Adapters
    $WifiAdapters = Get-WifiAdapters

    # Get Wifi Access Points
    $AccessPointList = Get-WifiAPs

    # Build the report
    $Report = "<h1>Wifi Report</h1>"

    $Report += "<h2>Wifi Adapters</h2>"
    if ($WifiAdapters) {
        $Report += $WifiAdapters | ConvertTo-Html -Fragment | Out-String
    }
    else {
        $Report += "<p>No Wifi Adapters Found</p>"
    }

    $Report += "<h2>Other Wifi Networks</h2>"
    if ($AccessPointList) {
        $Report += $AccessPointList | ConvertTo-Html -Fragment | Out-String
    }
    else {
        $Report += "<p>No Other Wifi Networks Found</p>"
    }

    Write-Host "--- Wifi Report ---"
    Write-Host ""
    Write-Host "### Wifi Adapters ###"
    $WifiAdapters | Format-Table -AutoSize | Out-String -Width 4000 | Write-Host

    Write-Host "### Other Wifi Networks ###"
    $AccessPointList |
        Select-Object -Property SSID, Authentication, Band, Channel, Signal |
        Format-Table -AutoSize | Out-String -Width 4000 | Write-Host

    if ($DebugHtml) {
        $Report | Out-String | Write-Host
    }

    if ($Report) {
        # Save report to multi-line custom field
        if ($CustomField) {
            try {
                # Set the custom field with the generated report
                Write-Host "[Info] Attempting to set Custom Field '$CustomField'."
                Set-NinjaProperty -Name $CustomField -Value $($Report | Out-String)
                Write-Host "[Info] Successfully set Custom Field '$CustomField'!"
            }
            catch {
                Write-Host "[Warn] $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Host "Could not generate wlan report."
        exit 1
    }
    
}
end {
    
    
    
}

