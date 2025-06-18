# Changes the max size for the specified Event Logs.
#Requires -Version 5.1

<#
.SYNOPSIS
    Changes the max size for the specified Event Logs.
.DESCRIPTION
    Changes the max size for the specified Event Logs.
    Common log names used: Security, Application, System
    To get a list of Event Log names from your system you can run:
        Get-WinEvent -ListLog * | Select-Object LogName
.EXAMPLE
     -LogNames "Security" -MaxSize "50MB"
    Changes the max log size for Security to 50MB
.EXAMPLE
     -LogNames "Security, Application, System" -MaxSize "50MB"
    Changes the max log size for Security, Application, and System to 50MB
.OUTPUTS
    None
.NOTES
    Windows 10 defaults to 20MB / 20480KB

    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script, added Script Variable support, addes support for friendly sizes, added force restart option.
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$LogNames,
    [Parameter()]
    [String]$MaxSize,
    [Parameter()]
    [Switch]$Restart = [System.Convert]::ToBoolean($env:forceRestart)
)

begin {
    $LogName = New-Object System.Collections.Generic.List[string]
    
    if ($env:LogName) {
        $LogNames = $env:LogName
    }

    if ($env:MaxSize) {
        $MaxSize = $env:MaxSize
    }

    $LogNames -split ',' | ForEach-Object { $LogName.Add($_.Trim()) }

    $LogName | ForEach-Object {
        if ( -not $($_ | Where-Object { $_ -in $(Get-WinEvent -ListLog * | Select-Object LogName).LogName }) ) {
            throw "$_ is not a valid Event Log Name."
        }
    }

    function Get-Size {
        param (
            [string]$String
        )
        switch -wildcard ($String) {
            '*PB' { [int64]$($String -replace '[^\d+]+') * 1PB; break }
            '*TB' { [int64]$($String -replace '[^\d+]+') * 1TB; break }
            '*GB' { [int64]$($String -replace '[^\d+]+') * 1GB; break }
            '*MB' { [int64]$($String -replace '[^\d+]+') * 1MB; break }
            '*KB' { [int64]$($String -replace '[^\d+]+') * 1KB; break }
            '*B' { [int64]$($String -replace '[^\d+]+') * 1; break }
            '*Bytes' { [int64]$($String -replace '[^\d+]+') * 1; break }
            Default { [int64]$($String -replace '[^\d+]+') * 1MB }
        }
    }

    function Get-FriendlySize {
        param($Bytes)
        # Converts Bytes to the highest matching unit
        $Sizes = 'Bytes,KB,MB,GB,TB,PB,EB,ZB' -split ','
        for ($i = 0; ($Bytes -ge 1kb) -and ($i -lt $Sizes.Count); $i++) { $Bytes /= 1kb }
        $N = 2
        if ($i -eq 0) { $N = 0 }
        if ($Bytes) { "$([System.Math]::Round($Bytes,$N)) $($Sizes[$i])" }else { "0 B" }
    }

    $Size = Get-Size -String $MaxSize

    if ($Size -lt 64KB -or $Size -gt 4GB) {
        Write-Error -Message "$(Get-FriendlySize $Size) is not a valid size!" -Category InvalidArgument -Exception (New-Object System.Exception)
        exit 1
    }

    if (-not $LogName -or -not $Size) {
        Write-Host "LogName and MaxSize Parameters are required."
        exit 1
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges." -Category PermissionDenied -Exception (New-Object System.Security.SecurityException)
        exit 1
    }

    Write-Host "### Current Log Sizes ###"
    Get-WinEvent -ListLog $LogName | Select-Object LogName, MaximumSizeInBytes | ForEach-Object {
        Write-Host "$($_.LogName): $(Get-FriendlySize $_.MaximumSizeInBytes)"
    }
}
process {
    $LogName | ForEach-Object {
        Limit-EventLog -LogName $_ -MaximumSize $Size -ErrorAction Stop
    
        # -ErrorAction Stop will exit and return an exit code of 1
        Write-Warning "Changed $_ Log Size to $(Get-FriendlySize $Size) a reboot may be required to complete this change."
    }

    if($Restart){
        Write-Warning "A restart was requested, scheduling restart for 60 seconds from now."
        Start-Process shutdown.exe -ArgumentList "-r -t 60" -NoNewWindow -Wait
    }
}
end {
    
    
    
}


