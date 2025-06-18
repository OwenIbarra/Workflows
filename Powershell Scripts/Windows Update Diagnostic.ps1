# Diagnose Windows Update issues.
#Requires -Version 5.1

<#
.SYNOPSIS
    Diagnose Windows Update issues.
.DESCRIPTION
    Checks that CryptSvc, and bits or running or not
    Checks that wuauserv is running and the startup type is set correctly.
    Checks WaaSMedic plugins doesn't have issues. (Only applies to OS Build Version is greater than 17600).
    Checks if NTP is setup.
    Checks Windows Update logs for any errors in the last week.

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    [Info] Last checked for updates on 4/29/2023
    [Issue] Windows Update has not checked for updates in over 30 days.

PARAMETER: -ResultsCustomField WindowsUpdate
    Saves results to a multi-line custom field.
.EXAMPLE
    -ResultsCustomField WindowsUpdate
    ## EXAMPLE OUTPUT WITH ResultsCustomField ##
    [Info] Last checked for updates on 4/29/2023
    [Issue] Windows Update has not checked for updates in over 90 days.
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [int]$Days = 30,
    [string]$ResultsCustomField
)

begin {
    if ($env:Days) {
        $Days = $env:Days
    }
    if ($env:resultscustomfield -notlike "null") {
        $ResultsCustomField = $env:resultscustomfield
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Test-WaaSMedic {
        [CmdletBinding()]
        param()
        $WaaS = 0
        Try {
            $WaaS = New-Object -ComObject "Microsoft.WaaSMedic.1"
        }
        Catch {
            Write-Host "WaaS Medic Support: No"
        }
    
        Try {
            if ($WaaS -ne 0) {
                Write-Host "WaaS Medic Support: Yes"
                $Plugins = $WaaS.LaunchDetectionOnly("Troubleshooter")
    
                if ($Plugins -eq "") {
                    [PSCustomObject]@{
                        Id        = "WaaSMedic"
                        Detected  = $false
                        Parameter = @{"error" = $Plugins }
                    }
                }
                else {
                    [PSCustomObject]@{
                        Id        = "WaaSMedic"
                        Detected  = $true
                        Parameter = @{"error" = $Plugins }
                    }
                    "Plugins that might have errors: " + $Plugins | Out-String | Write-Host
                }
            }
        }
        Catch {
            Write-Host "WaaS Medic Detection: Failed"
        }
        Finally {
            # Release COM Object if we aren't running test cases
            if (-not $env:NinjaPesterTesting) {
                [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WaaS) | Out-Null
            }
        }
    }
    function Get-TimeSyncType {
        [string]$result = ""
        [string]$registryKey = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters"
        [string]$registryKeyName = "Type"
    
        if ((Test-Path $registryKey -ErrorAction SilentlyContinue)) {
            $registryEntry = Get-Item -Path $registryKey -ErrorAction SilentlyContinue
            if ($null -ne $registryEntry) {
                return Get-ItemPropertyValue -Path $registryKey -Name $registryKeyName
            }
        }
        return $result
    }
    function Test-ConnectedToInternet {
        $NLMType = [Type]::GetTypeFromCLSID('DCB00C01-570F-4A9B-8D69-199FDBA5723B')
        $INetworkListManager = [Activator]::CreateInstance($NLMType)  
        return ($INetworkListManager.IsConnectedToInternet -eq $true)
    }
    function Get-ComponentAndErrorCode([string]$msg) {	
        $Codes = [regex]::matches($msg, "0x[a-f0-9a-f0-9A-F0-9A-F0-9]{6,8}")
        if ($Codes.count -gt 1) {
            $CodeList = ""
            # there can be more than one error code can be returned for the same component at once
            foreach ($Code in $Codes) {
                $CodeList += "_" + $Code
            }
            return $CodeList
        }
        else {
            return $Codes[0].Value
        }
    }
    function Get-DatedEvents($EventLog) {
        $DatedEvents = @()
        if ($null -eq $EventLog) {
            return $null 
        }
        foreach ($Event in $EventLog) {
            #$eventMsg = $event.Message
            $DatedEvents += $Event.Message
        }
        return $DatedEvents
    }
    function Get-SystemEvents($EventSrc, $Time) {
        $Events = Get-WinEvent -ProviderName $EventsSrc -ErrorAction 0 | Where-Object { ($_.LevelDisplayName -ne "Information") -and (($_.Id -eq 20) -or ($_.Id -eq 25)) -and ($_.TimeCreated -gt $Time) }
        return $Events
    }
    function Get-HasWinUpdateErrorInLastWeek([switch]$AllLastWeekError) {
        $Events = @()
        $EventsSrc = "Microsoft-Windows-WindowsUpdateClient"
        $startTime = (Get-Date) - (New-TimeSpan -Day 8)
        $wuEvents = Get-SystemEvents $EventsSrc $startTime
        if ($null -eq $wuEvents) {
            return $null
        }
        $Events += Get-DatedEvents $wuEvents
        $LatestError = Get-ComponentAndErrorCode $Events[0]
        $ErrorList = @{}
        $ErrorList.add("latest", $LatestError)
        if ($AllLastWeekError) {
            foreach ($str in $Events) {
                $ECode = Get-ComponentAndErrorCode $str
                if ($null -ne $ECode -and !$ErrorList.ContainsValue($ECode)) {
                    $ErrorList.add($ECode, $ECode)
                }
            }
        }
        return $ErrorList
    }
    Function Get-LocalTime($UTCTime) {
        $strCurrentTimeZone = (Get-CimInstance -ClassName Win32_TimeZone).StandardName
        # If running test cases return current date
        if ($env:NinjaPesterTesting) {
            return Get-Date
        }
        $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
        Return [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
    }
    $IssuesFound = $false
    $Log = [System.Collections.Generic.List[String]]::new()
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    if (-not $(Test-ConnectedToInternet)) {
        Write-Host "[Issue] Windows doesn't think it is connected to Internet."
        $IssuesFound = $true
    }

    # Check CryptSvc amd bits services
    $Service = Get-Service -Name CryptSvc
    if ($Service.StartType -notlike 'Automatic') {
        Write-Host "[Issue] (CryptSvc) CryptSvc service is set to $($Service.StartType) but needs to be set to Automatic"
        $Log.Add("[Issue] (CryptSvc) CryptSvc service is set to $($Service.StartType) but needs to be set to Automatic")
        $IssuesFound = $true
    }
    else {
        Write-Host "[Info] (CryptSvc) CryptSvc service is set to $($Service.StartType)"
        $Log.Add("[Info] (CryptSvc) CryptSvc service is set to $($Service.StartType)")
    }

    $Service = Get-Service -Name bits
    if ($Service.StartType -eq 'Disabled') {
        Write-Host "[Issue] (bits) BITS service is set to $($Service.StartType) but needs to be set to Manual"
        $Log.Add("[Issue] (bits) BITS service is set to $($Service.StartType) but needs to be set to Manual")
        $IssuesFound = $true
    }
    else {
        Write-Host "[Info] (bits) BITS service is set to $($Service.StartType)"
        $Log.Add("[Info] (bits) BITS service is set to $($Service.StartType)")
    }

    # Check that Windows Update service is running and isn't disabled
    $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
    if ($wuService.Status -ne "Running") {
        $Service = Get-Service -Name wuauserv
        if ($Service.StartType -eq 'Disabled') {
            Write-Host "[Issue] (wuauserv) Windows Update service is set to $($Service.StartType) but needs to be set to Automatic (Trigger Start) or Manual"
            $Log.Add("[Issue] (wuauserv) Windows Update service is set to $($Service.StartType) but needs to be set to Automatic (Trigger Start) or Manual")
            $IssuesFound = $true
        }
        else {
            Write-Host "[Info] (wuauserv) Windows Update service is set to $($Service.StartType)"
            $Log.Add("[Info] (wuauserv) Windows Update service is set to $($Service.StartType)")
        }
    }

    # Check WaaSMedic
    $SupportWaaSMedic = [System.Environment]::OSVersion.Version.Build -gt 17600
    if ($SupportWaaSMedic) {
        $Plugins = Test-WaaSMedic
        $PluginIssues = $Plugins | Where-Object { $_.Parameter["error"] } | ForEach-Object {
            $PluginErrors = $_.Parameter["error"]
            "[Potential Issue] WaaSMedic plugin errors found with: $($PluginErrors)"
        }
        if ($PluginIssues.Count -gt 1) {
            Write-Host "[Issue] Found more than 1 plugin errors."
            $Log.Add("[Issue] Found more than 1 plugin errors.")
            $PluginIssues | Write-Host
            $IssuesFound = $true
        }
    }

    # Check if NTP is setup
    if ("NoSync" -eq (Get-TimeSyncType)) {
        Write-Host "[Issue] NTP not setup!"
        $Log.Add("[Issue] NTP not setup!")
        $IssuesFound = $true
    }

    # Check Windows Update logs
    $EventErrors = Get-HasWinUpdateErrorInLastWeek -AllLastWeekError
    if ($EventErrors.Count -gt 0) {
        if (![string]::IsNullOrEmpty($allError.Values)) {
            Write-Host "[Issue] Event Log has Windows Update errors."
            $Log.Add("[Issue] Event Log has Windows Update errors.")
            $errorCodes = $allError.Values -join ';'
            Write-Host "[Issue] Error codes found: $errorCodes"
            $Log.Add("[Issue] Error codes found: $errorCodes")
            $IssuesFound = $true
        }
    }

    # If no issues found, get number of days since the last check for updates happened
    if (-not $IssuesFound) {
        $LastCheck = Get-LocalTime $(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate

        Write-Host "[Info] Last checked for updates on $($LastCheck.ToShortDateString())"
        $Log.Add("[Info] Last checked for updates on $($LastCheck.ToShortDateString())")

        $LastCheckTimeSpan = New-TimeSpan -Start $LastCheck -End $(Get-Date)
        if ($LastCheckTimeSpan.TotalDays -gt $Days) {
            $Days = [System.Math]::Round($LastCheckTimeSpan.TotalDays, 0)
            Write-Host "[Issue] Windows Update has not checked for updates in over $Days days."
            $Log.Add("[Issue] Windows Update has not checked for updates in over $Days days.")
            $IssuesFound = $true
        }
    }

    if ($ResultsCustomField) {
        Ninja-Property-Set -Name $ResultsCustomField -Value $($Log | Out-String)
    }

    if ($IssuesFound) {
        exit 1
    }
    exit 0
}
end {
    
    
    
}

