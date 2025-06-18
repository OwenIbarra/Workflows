# Checks whether a file is present and if it has been updated within your specified time frame or fails a hash check.
<#
.SYNOPSIS
    Checks whether a file is present and if it has been updated within your specified time frame or fails a hash check.
.DESCRIPTION
    Checks whether a file is present and if it has been updated within your specified time frame or fails a hash check.

PARAMETER: -Alert "Alert If Change" or -Alert "Alert If No Change"
    Raise an alert if the file has or hasn't been modified based on your other parameters.

PARAMETER: -Hash "REPLACEMEC32D73431CED24FF114B2A216671C60117AF5012B40"
    The hash or checksum to verify that the file hasn't been modified.
PARAMETER: -Algorithm "SHA256"
    The hashing algorithm used for your inputted hash.
.EXAMPLE
    -Path "C:\TestFile.txt" -Hash "REPLACEME04C6F26CC32D73431CED24FF114B2A216671C60117AF5012B40" -Alert "Alert If No Change"

    C:\TestFile.txt exists!
    Hash Given: REPLACEME04C6F26CC32D73431CED24FF114B2A216671C60117AF5012B40
    Current Hash: 35BAFB1CE99AEF3AB068AFBAABAE8F21FD9B9F02D3A9442E364FA92C0B3EEEF0
    Hash mismatch!

.EXAMPLE
    -Path "C:\TestFile.txt" -Hash "35BAFB1CE99AEF3AB068AFBAABAE8F21FD9B9F02D3A9442E364FA92C0B3BEEF0" -Alert "Alert If No Change"

    C:\TestFile.txt exists!
    Hash Given: 35BAFB1CE99AEF3AB068AFBAABAE8F21FD9B9F02D3A9442E364FA92C0B3BEEF0
    Current Hash: 35BAFB1CE99AEF3AB068AFBAABAE8F21FD9B9F02D3A9442E364FA92C0B3BEEF0
    Hash matches!
    [Alert] File has not been modified!

PARAMETER: -Days "REPLACEMEWITHANUMBER"
    Raise an alert if the file hasn't been modified within the specified number of days. 
    Minutes and Hours are added to this time.

PARAMETER: -Hours "REPLACEMEWITHANUMBER"
    Raise an alert if the file hasn't been modified within the specified number of hours. 
    Days and Minutes are added to this time.

PARAMETER: -Minutes "REPLACEMEWITHANUMBER"
    Raise an alert if the file hasn't been modified within the specified number of minutes. 
    Days and Hours are added to this time.
.EXAMPLE
    -Path "C:\TestFile.txt" -Days 365 -Alert "Alert If Change"

    C:\TestFile.txt exists!
    Checking if the file was modified in the last 365 day(s) 00 hour(s) 00 minute(s)
    File was last modified on 02/07/2024 14:59:56.
    File has been updated within the time period.
    [Alert] File has been modified!
.EXAMPLE
    -Path "C:\TestFile.txt" -Days 30 -Alert "Alert If Change"

    C:\TestFile.txt exists!
    Checking if the file was modified in the last 30 day(s) 00 hour(s) 00 minute(s)
    File was last modified on 05/15/2023 15:13:55.
    File has not been modified within the time period.

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 8+, Server 2012+
    Release Notes:
    Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Alert,
    [Parameter()]
    [String]$Path,
    [Parameter()]
    [String]$Hash,
    [Parameter()]
    [String]$Algorithm = "SHA256",
    [Parameter()]
    [int]$Days,
    [Parameter()]
    [int]$Hours,
    [Parameter()]
    [int]$Minutes
)

begin {
    # Replace parameters with dynamic script variables
    if ($env:alert -and $env:alert -notlike "null") { $Alert = $env:alert }
    if ($env:targetFilePath -and $env:targetFilePath -notlike "null") { $Path = $env:targetFilePath }
    if ($env:hash -and $env:hash -notlike "null") { $Hash = $env:hash }
    if ($env:algorithm -and $env:algorithm -notlike "null") { $Algorithm = $env:algorithm }
    if ($env:daysSinceLastModification -and $env:daysSinceLastModification -notlike "null") { $Days = $env:daysSinceLastModification }
    if ($env:hoursSinceLastModification -and $env:hoursSinceLastModification -notlike "null") { $Hours = $env:hoursSinceLastModification }
    if ($env:minutesSinceLastModification -and $env:minutesSinceLastModification -notlike "null") { $Minutes = $env:minutesSinceLastModification }

    # Test for local administrator permissions
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (-not (Test-IsElevated)) {
        Write-Warning -Message "Some files or folders may require local Administrator permissions to view."
    }

    # Verify the given algorithm is supported by PowerShell
    $AllowedAlgorithms = "SHA1", "SHA256", "SHA384", "SHA512", "MD5"
    if ($AllowedAlgorithms -notcontains $Algorithm) {
        Write-Host "[Error] Invalid Algorithm selected ($Algorithm)! Allowed selections are 'SHA1','SHA256','SHA384','SHA512' and 'MD5'."
        exit 1
    }

    # Check for required parameter
    if (-Not ($Path)) {
        Write-Host "[Error] A filepath is required!"
        Exit 1
    }

    switch ($Alert) {
        "Alert If Change" { Write-Verbose "Alerting if file $Path has been modified." }
        "Alert If No Change" { Write-Verbose "Alerting if file $Path has not been modified." }
        default { Write-Verbose "No alert was selected." }
    }

    $ExitCode = 0
}
process {

    # File existence check
    if ($Path -and -Not (Test-Path $Path -ErrorAction SilentlyContinue)) {
        Write-Host "[Alert] $Path does not exist!"
        Exit 1
    }
    else {
        Write-Host "$Path exists!"
    }

    # Confirm we were given a filepath and not a directory
    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
    if ($File.PSIsContainer) {
        Write-Host "[Error] Please provide a file path, not a directory."
        Exit 1
    }

    # If given the files hash verify it matches
    if ($Hash) {
        $CurrentHash = Get-FileHash -Path $File.FullName -Algorithm $Algorithm | Select-Object -ExpandProperty Hash
        Write-Host "Hash Given: $Hash"
        Write-Host "Current Hash: $CurrentHash"

        if ($Hash -notlike $CurrentHash) {
            Write-Host "Hash mismatch!"

            if($Alert -eq "Alert If Change"){
                Write-Host "[Alert] File has been modified!"
                $ExitCode = 1
            }
        }
        else {
            Write-Host "Hash matches!"

            if($Alert -eq "Alert If No Change"){
                Write-Host "[Alert] File has not been modified!"
                $ExitCode = 1
            }
        }
    }

    # Get the current date and subtract the days, hours and minutes to compare with the file 
    $Cutoff = Get-Date
    $CurrentDate = $Cutoff

    if ($Days) { $Cutoff = $Cutoff.AddDays(-$Days) }
    if ($Hours) { $Cutoff = $Cutoff.AddHours(-$Hours) }
    if ($Minutes) { $Cutoff = $Cutoff.AddMinutes(-$Minutes) }

    $TimeSpan = New-TimeSpan $Cutoff $CurrentDate

    if (($Days -or $Hours -or $Minutes) -and ($Cutoff -ne $CurrentDate)) {
        Write-Host "Checking if the file was modified in the last $($TimeSpan.ToString("dd' day(s) 'hh' hour(s) 'mm' minute(s)'"))"
        Write-Host "File was last modified on $($File.LastWriteTime)."

        if ($File.LastWriteTime -ge $Cutoff) {
            Write-Host "File has been updated within the time period."

            if($Alert -eq "Alert If Change"){
                Write-Host "[Alert] File has been modified!"
                $ExitCode = 1
            }
        }
        else {
            Write-Host "File has not been updated within the time period."

            if($Alert -eq "Alert If No Change"){
                Write-Host "[Alert] File has not been modified!"
                $ExitCode = 1
            }
        }
    }

    Exit $ExitCode
}
end {
    
    
    
}
