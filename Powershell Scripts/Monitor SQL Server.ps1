# Monitors the database services, databases drive free space, and databases disk latency.
#Requires -Version 5.1

<#
.SYNOPSIS
    Monitors the database services, database's drive free space, and database's disk latency.
.DESCRIPTION
    Monitors the database services, database's drive free space, and database's disk latency.

    Exit code of 1 means there is a problem.

    Will not detect LocalDB uses of SQL Express

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
    SQL Server's services are running.
    SQL Server's disk latency is below threshold.
    SQL Server's disk free space is above threshold.

PARAMETER: -RequireAgentService
    Checks if the SQL Agent service is running or not.
.EXAMPLE
    -RequireAgentService
    ## EXAMPLE OUTPUT WITH RequireAgentService ##
    SQL Server's services are running.
    SQL Server's disk latency is below threshold.
    SQL Server's disk free space is above threshold.


PARAMETER: -DiskSpaceThreshold 50
    The percentage of free space where the database is stored must have free. 0-100
.EXAMPLE
    -DiskSpaceThreshold 50
    ## EXAMPLE OUTPUT WITH diskLatencyThreshold ##
    [MSSQLSERVER] C: is under the threshold(50%) at 20%

PARAMETER: -diskLatencyThreshold 40
    A brief explanation of the parameter.
.EXAMPLE
    -diskLatencyThreshold 40
    ## EXAMPLE OUTPUT WITH diskLatencyThreshold ##
    [MSSQLSERVER] Disk Read/Write latency is over 0 ms.
    Path                                           InstanceName          CookedValue
    ----                                           ------------          -----------
    \\test01\logicaldisk(c:)\disk reads/sec      c:               42.89807648928576
    \\test01\logicaldisk(c:)\disk writes/sec     c:                49.484308202068
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Updated Calculated Name
#>

[CmdletBinding()]
param (
    [Parameter()]
    # Expects number in percentage with out the %
    # Default is 10 %
    [int]$DiskSpaceThreshold = 10,
    [Parameter()]
    # Expects number in milliseconds(ms)
    # Default is 50 ms
    [int]$diskLatencyThreshold = 50,
    [switch]$RequireAgentService = [System.Convert]::ToBoolean($env:requireAgentService)
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if ($env:diskFreeSpaceThreshold) {
        $DiskSpaceThreshold = $env:diskFreeSpaceThreshold
    }
    if ($env:diskLatencyThreshold) {
        $diskLatencyThreshold = $env:diskLatencyThreshold
    }

    Function Get-DefaultDBLocation {
        Param ([string] $vInstance)
        # Get the registry key associated with the Instance Name
        $vRegInst = (Get-ItemProperty -Path HKLM:"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue).$vInstance
        $vRegPath = "SOFTWARE\Microsoft\Microsoft SQL Server\" + $vRegInst + "\MSSQLServer"
        # Get the Data and Log file paths if available
        $vDataPath = (Get-ItemProperty -Path HKLM:$vRegPath -ErrorAction SilentlyContinue).DefaultData
        $vLogPath = (Get-ItemProperty -Path HKLM:$vRegPath -ErrorAction SilentlyContinue).DefaultLog
        # Report the entries found
        $Locations = [PSCustomObject]@{
            Data = ""
            Log  = ""
        }
        if ($vDataPath.Length -lt 1) {
            $vRegPath = "SOFTWARE\Microsoft\Microsoft SQL Server\" + $vRegInst + "\Setup"
            $vDataPath = (Get-ItemProperty -Path HKLM:$vRegPath -ErrorAction SilentlyContinue).SQLDataRoot + "\Data\"
            $Locations.Data = $vDataPath
        }
        else {
            $Locations.Data = $vDataPath
        }
        if ($vLogPath.Length -lt 1) {
            $vRegPath = "SOFTWARE\Microsoft\Microsoft SQL Server\" + $vRegInst + "\Setup"
            $vDataPath = (Get-ItemProperty -Path HKLM:$vRegPath -ErrorAction SilentlyContinue).SQLDataRoot + "\Data\"
            $Locations.Log = $vDataPath
        }
        else {
            $Locations.Log = $vDataPath
        }
        $Locations
    }
    function Get-DiskCounters {
        param ($Drive)
        $Counters = @(
            "\LogicalDisk($Drive*)\Avg. Disk sec/Read"
            "\LogicalDisk($Drive*)\Avg. Disk sec/Write"
            "\LogicalDisk($Drive*)\Disk Reads/sec"
            "\LogicalDisk($Drive*)\Disk Writes/sec"
        )
        $CounterData = Get-Counter -Counter $Counters -MaxSamples 1 -SampleInterval 10 | Select-Object -ExpandProperty CounterSamples

        $CounterData | Where-Object { $_.CookedValue -gt $diskLatencyThreshold } | Write-Output
    }
    function Get-DiskFreePercentage {
        param ($Drive)
        $TotalSize = Get-Partition | Where-Object { $_.DriveLetter -like $Drive } | Select-Object -ExpandProperty Size
        $Free = Get-PSDrive -Name $Drive | Select-Object -ExpandProperty Free
        try {
            $Free / $TotalSize * 100
        }
        catch {
            0
        }
    }
    $script:HasErrors = $false
}
process {
    Write-Host
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
    $Services = Get-Service | Where-Object { $_.DisplayName -like "SQL Server*" }
    $SqlDbServices = $Services | Where-Object { $_.DisplayName -like "SQL Server (*" } | Select-Object -ExpandProperty DisplayName
    $SqlDbNames = $SqlDbServices | ForEach-Object {
        "$_" -split '\(' -replace '\)' | Select-Object -Last 1
    }

    # Get all MS SQL Databases
    $Databases = $SqlDbNames | ForEach-Object {
        $DbName = $_
        $DbLocations = Get-DefaultDBLocation -vInstance $DbName
        [PSCustomObject]@{
            Name            = $DbName
            DatabaseService = $Services | Where-Object { $_.DisplayName -like "SQL Server ($DbName)" }
            AgentService    = $Services | Where-Object { $_.DisplayName -like "*Agent *$DbName*" }
            DataPath        = $DbLocations.Data
            LogPath         = $DbLocations.Log
        }
    }

    $Databases | ForEach-Object {
        $Database = $_
        $DatabaseService = $Database.DatabaseService
        $AgentService = $Database.AgentService
        $DatabaseName = $Database.Name
        $Drive = $Database.DataPath -split ':\\' | Select-Object -First 1

        # Check service status
        if ($DatabaseService.Status -notlike "Running") {
            Write-Host "[$DatabaseName] Database Service is not running."
            $script:HasErrors = $true
        }
        if ($AgentService.Status -notlike "Running") {
            Write-Host "[$DatabaseName] Database Agent Service is not running."
            if ($RequireAgentService) {
                $script:HasErrors = $true
            }
        }

        # Get disk free space percentage
        $FreePercent = Get-DiskFreePercentage -Drive $Drive
        if ($FreePercent -lt $DiskSpaceThreshold) {
            Write-Host "[$DatabaseName] $($Drive): is under the threshold($DiskSpaceThreshold%) at $([System.Math]::Round($FreePercent,0))%"
            $script:HasErrors = $true
        }

        # Get disk latency
        $HighCounters = Get-DiskCounters -Drive $Drive
        if ($HighCounters) {
            $HighCounters | ForEach-Object {
                Write-Host "[$DatabaseName] Disk Read/Write latency is over $diskLatencyThreshold ms at $([System.Math]::Round($_.CookedValue,2)) for $($_.InstanceName)."
            }
            $HighCounters | Out-String | Write-Host
            $script:HasErrors = $true
        }
    }

    if ($script:HasErrors) {
        exit 1
    }
    else {
        Write-Host "SQL Server's services are running."
        Write-Host "SQL Server's disk latency is below threshold."
        Write-Host "SQL Server's disk free space is above threshold."
        exit 0
    }
    
}
end {
    
    
    
}

