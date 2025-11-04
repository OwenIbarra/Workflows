# Gets computers that have been inactive for a specified number of days.
#Requires -Version 5.1

<#
.SYNOPSIS
    Gets computers that have been inactive for a specified number of days.
.DESCRIPTION
    Gets computers that have been inactive for a specified number of days.
    The number of days to consider a computer inactive can be specified as a parameter or saved to a custom field.

PARAMETER: -InactiveDays 30
    The number of days to consider a computer inactive. Computers that have been inactive for this number of days will be included in the report.
.EXAMPLE
    -InactiveDays 30
    ## EXAMPLE OUTPUT WITH InactiveDays ##
    [Info] Searching for computers that are inactive for 30 days or more.
    [Info] Found 11 inactive computers.

PARAMETER: -InactiveDays 30 -WysiwygCustomField "ReplaceMeWithAnyWysiwygCustomField"
    The number of days to consider a computer inactive. Computers that have been inactive for this number of days will be included in the report.
.EXAMPLE
    -InactiveDays 30 -WysiwygCustomField "ReplaceMeWithAnyWysiwygCustomField"
    ## EXAMPLE OUTPUT WITH WysiwygCustomField ##
    [Info] Searching for computers that are inactive for 30 days or more.
    [Info] Found 11 inactive computers.
    [Info] Attempting to set Custom Field 'Inactive Computers'.
    [Info] Successfully set Custom Field 'Inactive Computers'!

.NOTES
    Minimum OS Architecture Supported: Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    $InactiveDays,
    [Parameter()]
    [String]$WysiwygCustomField
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

}
process {
    if (-not (Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Get Script Variables and override parameters with them
    if ($env:inactiveDays -and $env:inactiveDays -notlike "null") {
        $InactiveDays = $env:inactiveDays
    }
    if ($env:wysiwygCustomField -and $env:wysiwygCustomField -notlike "null") {
        $WysiwygCustomField = $env:wysiwygCustomField
    }

    # Parameter Requirements
    if ([string]::IsNullOrWhiteSpace($InactiveDays)) {
        Write-Host "[Error] Inactive Days is required."
        exit 1
    }
    elseif ([int]::TryParse($InactiveDays, [ref]$null) -eq $false) {
        Write-Host "[Error] Inactive Days must be a number."
        exit 1
    }

    # Check that Active Directory module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "[Error] Active Directory module is not available. Please install it and try again."
        exit 1
    }

    try {
        # Get the date in the past $InactiveDays days
        $InactiveDate = (Get-Date).AddDays(-$InactiveDays)
        # Get the SearchBase for the domain
        $Domain = "DC=$(
            $(Get-CimInstance Win32_ComputerSystem).Domain -split "\." -join ",DC="
        )"
        Write-Host "[Info] Searching for computers that are inactive for $InactiveDays days or more."

        # For Splatting parameters into Get-ADComputer
        $GetComputerSplat = @{
            Property   = "Name", "LastLogonTimeStamp", "OperatingSystem"
            # LastLogonTimeStamp is converted to a DateTime object from the Get-ADComputer cmdlet
            Filter     = { (Enabled -eq "true") -and (LastLogonTimeStamp -le $InactiveDate) }
            SearchBase = $Domain
        }

        # Get inactive computers that are not active in the past $InactiveDays days
        $InactiveComputers = Get-ADComputer @GetComputerSplat | Select-Object "Name", @{
            # Format the LastLogonTimeStamp property to a human-readable date
            Name       = "LastLogon"
            Expression = {
                if ($_.LastLogonTimeStamp -gt 0) {
                    # Convert LastLogonTimeStamp to a datetime
                    $lastLogon = [DateTime]::FromFileTime($_.LastLogonTimeStamp)
                    # Format the datetime
                    $lastLogonFormatted = $lastLogon.ToString("MM/dd/yyyy hh:mm:ss tt")
                    return $lastLogonFormatted
                }
                else {
                    return "01/01/1601 00:00:00 AM"
                }
            }
        }, "OperatingSystem"

        if ($InactiveComputers -and $InactiveComputers.Count -gt 0) {
            Write-Host "[Info] Found $($InactiveComputers.Count) inactive computers."
        }
        else {
            Write-Host "[Info] No inactive computers were found."
        }
    }
    catch {
        Write-Host "[Error] Failed to get inactive computers. Please try again."
        exit 1
    }

    # Save the results to a custom field
    if ($WysiwygCustomField) {
        Write-Host ""
        Write-Host "Note: Custom field '$WysiwygCustomField' was specified but NinjaOne integration has been removed."
        Write-Host "All output has been displayed above."
    }

    $InactiveComputers | Format-Table -AutoSize | Out-String -Width 4000 | Write-Host

    exit $ExitCode
}
end {

}
