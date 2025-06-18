# Alerts when a USB drive is detected and optionally saves the results to a Custom Field.

<#
.SYNOPSIS
    Alerts when a USB drive is detected and optionally saves the results to a Custom Field.
.DESCRIPTION
    Alerts when a USB drive is detected and optionally saves the results to a Custom Field.
.EXAMPLE
    (No Parameters)
    
    No USB Drives are present.
.EXAMPLE
    (No Parameters)

    C:\Users\KyleBohlander\Documents\bitbucket_clientscripts\client_scripts\src\Test-USBDrive.ps1 : A USB Drive has been detected!
    At line:1 char:1
    + .\src\Test-USBDrive.ps1
    + ~~~~~~~~~~~~~~~~~~~~~~~
        + CategoryInfo          : LimitsExceeded: (:) [Write-Error], Exception
        + FullyQualifiedErrorId : System.Exception,Test-USBDrive.ps1

    Index Caption                        SerialNumber     Partitions
    ----- -------                        ------------     ----------
        1 Samsung Flash Drive USB Device AA00000000000489          1

PARAMETER: -CustomFieldName "replaceMeWithACustomFieldName"
    Name of a custom field to save the results to. This is optional; results will also output to the activity log.

.OUTPUTS
    None
.NOTES
    Minimum supported OS: Windows 10, Server 2012 R2
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomFieldName
)

begin {
    # Grab CustomFieldName from dynamic script form
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomFieldName = $env:customFieldName }

    # Initialize exit code
    $ExitCode = 0

    # Initialize generic list for the report
    $Report = New-Object System.Collections.Generic.List[String]
    $CustomFieldReport = New-Object System.Collections.Generic.List[String]
}
process {

    # Get a list of USB drives
    $USBDrives = if ($PSVersionTable.PSVersion.Major -ge 5) {
        Get-CimInstance win32_diskdrive | Where-Object { $_.InterfaceType -eq 'USB' }
    }
    else {
        Get-WmiObject win32_diskdrive | Where-Object { $_.InterfaceType -eq 'USB' }
    }

    # Alert if a USB drive is detected
    if ($USBDrives) {
        Write-Error -Message "A USB Drive has been detected!" -Category LimitsExceeded -Exception (New-Object -TypeName System.Exception)

        # Grab relevant information about the USB Drive
        $USBDrives | ForEach-Object {
            $Report.Add( ($_ | Format-Table Index, Caption, SerialNumber, Partitions | Out-String) )
            if ($CustomFieldName) { $CustomFieldReport.Add( ($_ | Format-List Index, Caption, SerialNumber, Partitions | Out-String) ) }

            $Report.Add( (Get-Partition -DiskNumber $_.Index | Get-Volume | Format-Table DriveLetter, FriendlyName, DriveType, HealthStatus, SizeRemaining, Size | Out-String) )
            if ($CustomFieldName) { $CustomFieldReport.Add( (Get-Partition -DiskNumber $_.Index | Get-Volume | Format-List DriveLetter, FriendlyName, DriveType, HealthStatus, SizeRemaining, Size | Out-String) ) }
        }

        # Change exit code to indicate failure/alert
        $ExitCode = 1
    }
    else {
        # If no drives were found we'll need to indicate that.
        $Report.Add("No USB Drives are present.")
        if ($CustomFieldName) { $CustomFieldReport.Add("No USB Drives are present.") }
    }

    # Write to the activity log
    Write-Host $Report

    # Save to custom field if given one
    if ($CustomFieldName) {
        Write-Host ""
        Ninja-Property-Set -Name $CustomFieldName -Value $CustomFieldReport
    }

    # Exit with appropriate exit code
    Exit $ExitCode
}
end {
    
    
    
}
