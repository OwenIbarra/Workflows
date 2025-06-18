# Retrieves the approximate location of a device using the Google GeoLocation API and optionally saves it to a multiline custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Retrieves the approximate location of a device using the Google GeoLocation API and optionally saves it to a multiline custom field.
.DESCRIPTION
    Retrieves the approximate location of a device using the Google GeoLocation API and optionally saves it to a multiline custom field.
.EXAMPLE
    -GoogleApiKey "<GeoLocation API key here>" -CustomFieldName "Location"
    
    Approximate Address: 871 N Oak Park Blvd, Pismo Beach, CA 93449, USA
    Approximate GPS Coordinates: 35.1324183,-120.6068538
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2016
    Release Notes:
    Updated to work with either Parameters or Script Variables, switched it to use one custom field instead of two.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$GoogleApiKey,
    [Parameter()]
    [String]$CustomFieldName
)

begin {
    # Check if Script Variables are being used
    if ($env:googleApiKey -and $env:googleApiKey -notlike "null") {
        $GoogleApiKey = $env:googleApiKey
    }

    if ($env:customFieldName -and $env:customFieldName -notlike "null") {
        $CustomFieldName = $env:customFieldName
    }

    function Test-StringEmpty {
        param([string]$Text)
        # Returns true if string is empty, null, or whitespace
        process { [string]::IsNullOrEmpty($Text) -or [string]::IsNullOrWhiteSpace($Text) }
    }

    # Check if api key is set, error if not set
    if ($(Test-StringEmpty -Text $GoogleApiKey)) {
        # Both Parameter and Script Variable are empty
        # Can not combine Parameter "[Parameter(Mandatory)]" and Script Variable Required
        Write-Error "GoogleApiKey is required."
        exit 1
    }

    $SupportedTLSversions = [enum]::GetValues('Net.SecurityProtocolType')
    if ( ($SupportedTLSversions -contains 'Tls13') -and ($SupportedTLSversions -contains 'Tls12') ) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12
    }
    elseif ( $SupportedTLSversions -contains 'Tls12' ) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    }
    else {
        # Not everything requires TLS 1.2, but we'll try anyway.
        Write-Warning "TLS 1.2 and or TLS 1.3 are not supported on this system. Getting the location may fail!"
        if ($PSVersionTable.PSVersion.Major -lt 3) {
            Write-Warning "PowerShell 2 / .NET 2.0 doesn't support TLS 1.2."
        }
    }

    # Build URL with API key
    $Url = "https://www.googleapis.com/geolocation/v1/geolocate?key=$GoogleApiKey"
    
    function Get-NearestCity {
        param (
            [double]$lat,
            [double]$lon,
            [string]$GoogleApi
        )
        try {
            $Response = Invoke-RestMethod -Uri "https://maps.googleapis.com/maps/api/geocode/json?latlng=$lat,$lon&key=$GoogleApi"
        }
        catch {
            throw $Error[0]
        }
        return $Response.results[0].formatted_address
    }
    function Get-WifiNetwork {
        end {
            try {
                netsh.exe wlan sh net mode=bssid | ForEach-Object -Process {
                    if ($_ -match '^SSID (\d+) : (.*)$') {
                        $current = @{}
                        $networks += $current
                        $current.Index = $matches[1].trim()
                        $current.SSID = $matches[2].trim()
                    }
                    else {
                        if ($_ -match '^\s+(.*)\s+:\s+(.*)\s*$') {
                            $current[$matches[1].trim()] = $matches[2].trim()
                        }
                    }
                } -Begin { $networks = @() } -End { $networks | ForEach-Object { New-Object -TypeName "PSObject" -Property $_ } }    
            }
            catch {
                # return nothing
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
}
process {
    # Get WIFI network data nearby
    $WiFiData = Get-WifiNetwork |
        Select-Object @{name = 'age'; expression = { 0 } },
        @{name = 'macAddress'; expression = { $_.'BSSID 1' } },
        @{name = 'channel'; expression = { $_.Channel } },
        @{name = 'signalStrength'; expression = { (($_.Signal -replace "%") / 2) - 100 } }

    # Check if we got any number access points
    $Body = if ($WiFiData -and $WiFiData.Count -gt 0) {
        @{
            considerIp       = $true
            wifiAccessPoints = $WiFiData
        } | ConvertTo-Json
    }
    else {
        @{
            considerIp = $true
        } | ConvertTo-Json
    }

    # Get our lat,lng position
    try {
        $Response = Invoke-RestMethod -Method Post -Uri $Url -Body $Body -ContentType "application/json"

        # Save the relevant results to variable that have shorter names
        $Lat = $Response.location.lat
        $Lon = $Response.location.lng

        # Get City from Google API's
        # Google API: https://developers.google.com/maps/documentation/geocoding/requests-reverse-geocoding
        $Address = Get-NearestCity -lat $Lat -lon $Lon -GoogleApi $GoogleApiKey

        $Report = "Approximate Address: $Address`nApproximate GPS Coordinates: $Lat,$Lon"
        Write-Host $Report
    }
    catch {
        Write-Error $_
        exit 1
    }

    if (-not $CustomFieldName) {
        exit 0
    }

    # Set a custom field
    try {
        Set-NinjaProperty -Name $CustomFieldName -Value $Report
    }
    catch {
        Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
        exit 1
    }

    exit 0
}
end {
    
    
    
}

