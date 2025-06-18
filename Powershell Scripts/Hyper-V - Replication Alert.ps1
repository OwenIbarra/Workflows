# This will get information about the current status of Hyper-V Replication. If its abnormal itll check the last replication time to see if it should alert on it.
#Requires -Version 5.1

<#
.SYNOPSIS
    This will get information about the current status of Hyper-V Replication. If its abnormal it'll check the last replication time to see if it should alert on it.
.DESCRIPTION
    This will get information about the current status of Hyper-V Replication. If its abnormal it'll check the last replication time to see if it should alert on it.
.EXAMPLE 
    (No Parameters)
    Replication is currently failing!
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,customscript_gen_2.ps1
 

    VMName      PrimaryServer            State   Health LastReplicationTime 
    ------      -------------            -----   ------ ------------------- 
    WIN10-TEST  SRV16-TEST.test.lan      Error Critical 4/13/2023 8:20:11 AM
    Win10-TEST2 SRV16-TEST.test.lan      Error Critical 4/13/2023 8:20:11 AM

PARAMETER: -FailedFor "30"
    Time in minutes any given vm replication is allowed to be abnormal.
    Ex. "20" will alert on a vm replication after its been in the abnormal state for 20 minutes.
.EXAMPLE
    -FailedFor "20"
    WARNING: Some of the vm's currently have replication paused!
 

    VMName      PrimaryServer                  State  Health LastReplicationTime 
    ------      -------------                  -----  ------ ------------------- 
    WIN10-TEST  SRV16-TEST.test.lan      Replicating  Normal 4/13/2023 8:40:04 AM
    Win10-TEST2 SRV16-TEST.test.lan        Suspended Warning 4/13/2023 8:32:06 AM

PARAMETER: -IncludePaused
    Script will consider paused vm's abnormal if this parameter is used.    
.EXAMPLE
    -IncludePaused
    Replication is currently failing!
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,customscript_gen_2.ps1
 

    VMName      PrimaryServer                  State  Health LastReplicationTime 
    ------      -------------                  -----  ------ ------------------- 
    WIN10-TEST  SRV16-TEST.test.lan      Replicating  Normal 4/13/2023 8:40:04 AM
    Win10-TEST2 SRV16-TEST.test.lan        Suspended Warning 4/13/2023 8:32:06 AM

PARAMETER: -FromCustomField "ReplaceMeWithAnyIntegerCustomField"
    Name of an integer custom field that contains your desired FailedFor threshold.
    ex. "ReplicationAlertThreshold" where you have entered in your desired alert limit in the "ReplicationAlertThreshold" custom field rather than in a parameter.
.EXAMPLE
    -FromCustomField "ReplaceMeWithAnyIntegerCustomField"
    WARNING: Some of the vm's currently have replication paused!
 

    VMName      PrimaryServer                  State  Health LastReplicationTime 
    ------      -------------                  -----  ------ ------------------- 
    WIN10-TEST  SRV16-TEST.test.lan      Replicating  Normal 4/13/2023 8:40:04 AM
    Win10-TEST2 SRV16-TEST.test.lan        Suspended Warning 4/13/2023 8:32:06 AM
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Server 2016
    Release Notes: Updated Calculated Name
#>

[CmdletBinding()]
param (
    [Parameter()]
    [int]$FailedFor = "60",
    [Parameter()]
    [String]$FromCustomField,
    [Parameter()]
    [Switch]$IncludePaused = [System.Convert]::ToBoolean($env:includePausedReplications)
)
begin {

    if ($env:allowedToFailForXMinutes -and $env:allowedToFailForXMinutes -notlike "null") { $FailedFor = $env:allowedToFailForXMinutes }
    if ($env:retrieveAllowedFailureTimeFromCustomField -and $env:retrieveAllowedFailureTimeFromCustomField -notlike "null" ) { $FromCustomField = $env:retrieveAllowedFailureTimeFromCustomField }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    if (!(Test-IsElevated) -and !(Test-IsSystem)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
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

        # If we're requested to get the field value from a Ninja document we'll specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }

        # These two types require more information to parse.
        $NeedsOptions = "DropDown","MultiSelect"

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
                if($NinjaPropertyValue){
                    [int]$NinjaPropertyValue
                }else{
                    $NinjaPropertyValue
                }
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
}
process {
    if ($FromCustomField) {
        try{
            $CustomFieldValue = Get-NinjaProperty -Name $FromCustomField -Type "Integer"
        }catch{
            Write-Warning "$($_.ToString())"
        }

        if($CustomFieldValue){
            $FailedFor = $CustomFieldValue
        }else{
            Write-Warning "Custom Field $FromCustomField was empty?"
        }
    }

    if($FailedFor -gt 0){
        $FailedFor = $FailedFor * -1
    }

    $Threshold = (Get-Date).AddMinutes($FailedFor)
    Write-Host "Checking vm's that have not replicated prior to $Threshold."

    $Failed = New-Object System.Collections.Generic.List[string]
    $UnhealthyVMs = Get-VMReplication | Where-Object { $_.Health -notlike "Normal" -and $_.LastReplicationTime -lt $Threshold -and $_.State -notlike "Suspended" }
    $PausedVMs = Get-VMReplication | Where-Object { $_.LastReplicationTime -lt $Threshold -and $_.State -like "Suspended" }

    if ($UnhealthyVMs) {
        $Failed.Add($UnhealthyVMs)
    }
    
    if ($PausedVMs) {
        Write-Warning "Some of the vm's currently have replication paused!"

        if(-not $IncludePaused){
            Write-Warning "Please use 'Include Paused Replications' to include paused replications in the alert. Otherwise, they will be skipped."
        }
    }

    if ($PausedVMs -and $IncludePaused) {
        $Failed.Add($PausedVMs)
    }

    if ($Failed) {
        Write-Error "Hyper-V Replication is currently failing!"
        Get-VMReplication | Format-Table -Property VMName, PrimaryServer, State, Health, LastReplicationTime | Out-String | Write-Host
        exit 1
    }
    else {
        Write-Host "No failing replications detected prior to $Threshold."

        Get-VMReplication | Format-Table -Property VMName, PrimaryServer, State, Health, LastReplicationTime | Out-String | Write-Host
        exit 0
    }
}end {
    
    
    
}

