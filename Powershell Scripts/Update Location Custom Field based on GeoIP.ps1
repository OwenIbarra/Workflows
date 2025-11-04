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
    # [String]$DocumentName # Removed NinjaOne dependency
    # ) # Removed NinjaOne dependency
    
    # # If we're requested to set the field value for a Ninja document we'll specify it here. # Removed NinjaOne dependency
    # $DocumentationParams = @{} # Removed NinjaOne dependency
    # if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName } # Removed NinjaOne dependency
 
    # # This is a list of valid fields we can set. If no type is given we'll assume the input doesn't have to be changed in any way. # Removed NinjaOne dependency
    # $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL" # Removed NinjaOne dependency
    
    # if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type! Please check here for valid types. https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" } # Removed NinjaOne dependency

    # # The below field requires additional information in order to set # Removed NinjaOne dependency
    # $NeedsOptions = "Dropdown" # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # # We'll redirect the error output to the success stream to make it easier to error out if nothing was found or something else went wrong. # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # if ($NeedsOptions -contains $Type) { # Removed NinjaOne dependency
    # $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    
    # # If we received some sort of error it should have an exception property and we'll exit the function with that error information. # Removed NinjaOne dependency
    # if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions } # Removed NinjaOne dependency
    
    # # The below type's require values not typically given in order to be set. The below code will convert whatever we're given into a format ninjarmm-cli supports. # Removed NinjaOne dependency
    # switch ($Type) { # Removed NinjaOne dependency
    # "Checkbox" { # Removed NinjaOne dependency
    # # While it's highly likely we were given a value like "True" or a boolean datatype it's better to be safe than sorry. # Removed NinjaOne dependency
    # $NinjaValue = [System.Convert]::ToBoolean($Value) # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Date or Date Time" { # Removed NinjaOne dependency
    # # Ninjarmm-cli is expecting the time to be representing as a Unix Epoch string. So we'll convert what we were given into that format. # Removed NinjaOne dependency
    # $Date = (Get-Date $Value).ToUniversalTime() # Removed NinjaOne dependency
    # $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date # Removed NinjaOne dependency
    # $NinjaValue = $TimeSpan.TotalSeconds # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # "Dropdown" { # Removed NinjaOne dependency
    # # Ninjarmm-cli is expecting the guid of the option we're trying to select. So we'll match up the value we were given with a guid. # Removed NinjaOne dependency
    # $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name" # Removed NinjaOne dependency
    # $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID # Removed NinjaOne dependency
    
    # if (-not $Selection) { # Removed NinjaOne dependency
    # throw "Value is not present in dropdown" # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    # $NinjaValue = $Selection # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # default { # Removed NinjaOne dependency
    # # All the other types shouldn't require additional work on the input. # Removed NinjaOne dependency
    # $NinjaValue = $Value # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    
    # # We'll need to set the field differently depending on if its a field in a Ninja Document or not. # Removed NinjaOne dependency
    # if ($DocumentName) { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # else { # Removed NinjaOne dependency
    # $CustomField = Ninja-Property-Set -Name $Name -Value $NinjaValue 2>&1 # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency

    # if ($CustomField.Exception) { # Removed NinjaOne dependency
    # throw $CustomField # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
    # } # Removed NinjaOne dependency
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
    # Set-NinjaProperty -Name $CustomFieldName -Value $Report # Removed NinjaOne dependency
    }
    catch {
        Write-Error -Message $_.ToString() -Category InvalidOperation -Exception (New-Object System.Exception)
        exit 1
    }

    exit 0
}
end {
    
    
    
}

