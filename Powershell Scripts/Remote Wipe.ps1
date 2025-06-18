# Remote Wipe a device.
#Requires -Version 5.1

<#
.SYNOPSIS
    Remote Wipe a device.
.DESCRIPTION
    Remote Wipe a device via InvokeMethod from a Cim Session. doWipe, doWipeProtected, doWipePersistUserData, and doWipePersistProvisionedData are supported.
    See examples for how to use each.
.EXAMPLE
    -Method Wipe -ComputerName "PC-001"
    Runs the doWipe method. Equivalent to running "Reset this PC > Remove everything" from the Settings app, with Clean Data set to No and Delete Files set to Yes.
    ComputerName needs to match the computer name of the computer the script is running on. If it doesn't then the script will exit, doing nothing.
.EXAMPLE
    -Method Wipe -ComputerNameBypass
    Runs the doWipe method. Equivalent to running "Reset this PC > Remove everything" from the Settings app, with Clean Data set to No and Delete Files set to Yes.
    Will bypass the computer name check and run regards less.
.EXAMPLE
    -Method WipeProtected -ComputerName "PC-001"
    Runs the doWipeProtected method. Performs a remote reset on the device and also fully cleans the internal drive.
    Windows 10 build version 1703 and above.
    ComputerName needs to match the computer name of the computer the script is running on. If it doesn't then the script will exit, doing nothing.
.EXAMPLE
    -Method WipePersistUserData
    Runs the doWipeProtected method. Equivalent to selecting "Reset this PC > Keep my files" when manually starting a reset from the Settings app.
    Windows 10 build version 1709 and above.
    ComputerName needs to match the computer name of the computer the script is running on. If it doesn't then the script will exit, doing nothing.
.EXAMPLE
    -Method WipePersistProvisionedData
    Runs the doWipeProtected method. Provisioning packages in the %SystemDrive%\ProgramData\Microsoft\Provisioning folder will be retained and then applied to the OS after the reset.
    The information that was backed up will be restored and applied to the device when it resumes.
    ComputerName needs to match the computer name of the computer the script is running on. If it doesn't then the script will exit, doing nothing.
.NOTES
    Reference: https://docs.microsoft.com/en-us/windows/client-management/mdm/remotewipe-csp
    Release Notes: Updated Calculated Name
#>

[CmdletBinding()]
param (
    [Parameter()]
    [ValidateSet("Wipe", "WipeProtected", "WipePersistProvisionedData", "WipePersistUserData")]
    [String]
    $Method,
    [Parameter()]
    [String]
    $ComputerName,
    [Parameter()]
    [switch]
    $ComputerNameBypass = [System.Convert]::ToBoolean($env:ComputerNameBypass)
)

begin {
    if ($env:Method) {
        $Method = $env:Method
    }
    if ($env:ComputerNameEnv) {
        $ComputerName = $env:ComputerNameEnv
    }
}

process {
    if ([string]::IsNullOrEmpty($Method) -or [string]::IsNullOrWhiteSpace($Method) -or $Method -like "null") {
        Write-Host "Must specify a Wipe method."
        exit 1
    }
    # ComputerNameBypass was used, continue on.
    if ($ComputerNameBypass) {
        Write-Host "Bypassing Computer Name check."
    }
    else {
        # If computer name matches, continue on.
        if ($ComputerName -notlike $env:COMPUTERNAME) {
            Write-Error "Computer Name does not match."
            exit 1
        }
    }

    # Check if the requested Method is supported or not
    $BuildVersion = [System.Environment]::OSVersion.Version.Build
    if ($BuildVersion -lt 1703 -and $Method -like "WipeProtected") {
        Write-Host "WipeProtected is only supported on Windows 10 build version 1703 and above."
        exit 1
    }
    if ($BuildVersion -lt 1709 -and $Method -like "WipePersistUserData") {
        Write-Host "WipePersistUserData is only supported on Windows 10 build version 1709 and above."
        exit 1
    }

    $session = New-CimSession

    $params = New-Object Microsoft.Management.Infrastructure.CimMethodParametersCollection
    $param = [Microsoft.Management.Infrastructure.CimMethodParameter]::Create("param", "", "String", "In")
    $params.Add($param)

    $CimSplat = @{
        Namespace = "root\cimv2\mdm\dmmap"
        ClassName = "MDM_RemoteWipe"
        Filter    = "ParentID='./Vendor/MSFT' and InstanceID='RemoteWipe'"
    }

    try {
        $instance = Get-CimInstance @CimSplat
        $session.InvokeMethod($CimSplat["Namespace"], $instance, "do$($Method)Method", $params)
    }
    catch {
        Write-Error $_
        exit 1
    }
}
end {
    
    
    
}


