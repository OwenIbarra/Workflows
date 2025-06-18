# Retrieves a list of scheduled tasks and outputs the list into the activity log. This list can optionally be saved to a Custom Field.

<#
.SYNOPSIS
    Retrieves a list of scheduled tasks and outputs the list into the activity log. This list can optionally be saved to a Custom Field.
.DESCRIPTION
    Retrieves a list of scheduled tasks and outputs the list into the activity log. This list can optionally be saved to a Custom Field.
.EXAMPLE
    (No Parameters)
    
    Scheduled Task(s) Found!

    TaskName                          TaskPath  State
    --------                          --------  -----
    Firefox Background Update 3080... \Mozilla\ Ready

PARAMETER: -IncludeMicrosoft
    Includes Scheduled Tasks created by Microsoft in the report.

PARAMETER: -IncludeDisabled
    Includes Scheduled Tasks that are currently disabled in the report.

PARAMETER: -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    Name of a multiline custom field to save the results to. This is optional; results will also output to the activity log.

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2012 R2
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$IncludeMicrosoft = [System.Convert]::ToBoolean($env:includeMicrosoftTasks),
    [Parameter()]
    [Switch]$IncludeDisabled = [System.Convert]::ToBoolean($env:includeDisabledTasks),
    [Parameter()]
    [String]$CustomFieldName
)

begin {
    # Get CustomFieldName value from Dynamic Script Form.
    if ($env:customFieldName -and $env:customFieldName -notlike "null" ) { $CustomFieldName = $env:customFieldName }

    # Some Scheduled Tasks require Local Admin Privileges to view.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Initialize Generic List for Report
    $Report = New-Object System.Collections.Generic.List[String]
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges." -Category PermissionDenied -Exception (New-Object -TypeName System.UnauthorizedAccessException)
        exit 1
    }

    # By default, we'll exclude tasks made by Microsoft. They don't always put themselves down as an author.
    if (-not $IncludeMicrosoft) {
        $ScheduledTasks = Get-ScheduledTask | Where-Object { $_.Author -notlike "Microsoft*" -and $_.TaskPath -notlike "\Microsoft*" }
    }
    else {
        $ScheduledTasks = Get-ScheduledTask
    }

    # We should ignore disabled tasks unless told otherwise.
    if (-not $IncludeDisabled) {
        $ScheduledTasks = $ScheduledTasks | Where-Object { $_.State -notlike "Disabled" }
    }

    # The activity log isn't going to fit all this output, so we'll trim it if it's too large.
    if ($ScheduledTasks) {
        $FormattedTasks = $ScheduledTasks | ForEach-Object {
            $Name = if (($_.TaskName).Length -gt 30) { ($_.TaskName).Substring(0, 30) + "..." }else { $_.TaskName }
            $Path = if (($_.TaskPath).Length -gt 30) { ($_.TaskPath).Substring(0, 30) + "..." }else { $_.TaskPath }

            [PSCustomObject]@{
                TaskName = $Name
                TaskPath = $Path
                State    = $_.State
            }
        }

        Write-Host "Scheduled Task(s) Found!"
        $Report.Add(( $FormattedTasks | Format-Table TaskName, TaskPath, State -AutoSize | Out-String ))
    }
    else {
        $Report.Add("No Scheduled Tasks have been found.")
    }

    # Output our results.
    Write-Host $Report

    # Save our results to a custom field.
    if ($CustomFieldName) {
        Ninja-Property-Set -Name $CustomFieldName -Value $Report
    }
}
end {
    
    
    
}
