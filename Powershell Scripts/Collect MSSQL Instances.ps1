# Gets a list of MSSQL server instances and optionally save the results to a custom field.
#Requires -Version 5.1

<#
.SYNOPSIS
    Gets a list of MSSQL server instances and optionally save the results to a custom field.
.DESCRIPTION
    Gets a list of MSSQL server instances and optionally save the results to a custom field.
    The custom field can be either/both a multi-line or WYSIWYG custom field.

    SQL Server, SQL Server Developer and SQL Express are supported.

    SQL "Local" that are built into an application are not supported as they aren't an SQL Server instance.

    SQL service name that don't start with "MSSQL$" will not get detected.

    PS > Get-Service -Name "MSSQL`$*"
    Status   Name               DisplayName
    ------   ----               -----------
    Running  MSSQL$DB           SQL Server (DB)
    Running  MSSQL$DB01         SQL Server (DB01)
    Running  MSSQL$DB02         SQL Server (DB02)

.EXAMPLE
    (No Parameters)
    ## EXAMPLE OUTPUT WITHOUT PARAMS ##
     Status Name              Instance Path
     ------ ----              -------- ----
    Running SQL Server (DB01) DB01     C:\Program Files\Microsoft SQL Server\MSSQL16.DB01\MSSQL
    Running SQL Server (DB02) DB02     C:\Program Files\Microsoft SQL Server\MSSQL16.DB02\MSSQL

PARAMETER: -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    Saves an text table to a multi-line Custom Field with a list of SQL instances.
.EXAMPLE
    -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    ## EXAMPLE OUTPUT WITH CustomFieldName ##
     Status Name              Instance Path
     ------ ----              -------- ----
    Running SQL Server (DB01) DB01     C:\Program Files\Microsoft SQL Server\MSSQL16.DB01\MSSQL
    Running SQL Server (DB02) DB02     C:\Program Files\Microsoft SQL Server\MSSQL16.DB02\MSSQL

PARAMETER: -CustomFieldParam "ReplaceMeWithAnyWysiwygCustomField"
    Saves an html table to a Wysiwyg Custom Field with a list of SQL instances.
.EXAMPLE
    -WysiwygCustomFieldName "ReplaceMeWithAnyWysiwygCustomField"
    ## EXAMPLE OUTPUT WITH WysiwygCustomFieldName ##
     Status Name              Instance Path
     ------ ----              -------- ----
    Running SQL Server (DB01) DB01     C:\Program Files\Microsoft SQL Server\MSSQL16.DB01\MSSQL
    Running SQL Server (DB02) DB02     C:\Program Files\Microsoft SQL Server\MSSQL16.DB02\MSSQL
.OUTPUTS
    None
.NOTES
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [String]$CustomFieldName,
    [String]$WysiwygCustomFieldName
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if ($env:multilineCustomFieldName -and $env:multilineCustomFieldName -notlike "null") {
        $CustomFieldName = $env:multilineCustomFieldName
    }
    if ($env:WysiwygCustomFieldName -and $env:WysiwygCustomFieldName -notlike "null") {
        $WysiwygCustomFieldName = $env:WysiwygCustomFieldName
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    try {
        $InstanceNames = $(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\" -ErrorAction Stop).InstalledInstances
        $SqlInstances = $InstanceNames | ForEach-Object {
            $SqlPath = $(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$_\Setup" -ErrorAction Stop).SQLPath
            $SqlServices = Get-Service -Name "MSSQL`$$_" -ErrorAction Stop
            $SqlService = $SqlServices | Where-Object { $_.Name -notlike $SqlServices.DependentServices.Name -and $_.Name -notlike "SQLTelemetry*" }
            [PSCustomObject]@{
                Status   = $SqlService.Status
                Service  = $SqlService.DisplayName
                Instance = $_
                Path     = $SqlPath
            }
        }
    }
    catch {
        Write-Host "[Error] $($_.Message)"
        Write-Host "[Info] Likely no MSSQL instance found."
        exit 1
    }

    $SqlInstances | Out-String | Write-Host

    if ($CustomFieldName) {
        Write-Host ""
        Write-Host "Note: Custom field '$CustomFieldName' was specified but NinjaOne integration has been removed."
        Write-Host "All output has been displayed above."
    }

    if ($WysiwygCustomFieldName) {
        Write-Host ""
        Write-Host "Note: Custom field '$WysiwygCustomFieldName' was specified but NinjaOne integration has been removed."
        Write-Host "All output has been displayed above."
    }
    exit 0
}
end {

}
