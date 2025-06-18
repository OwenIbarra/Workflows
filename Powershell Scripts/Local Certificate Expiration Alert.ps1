# Alerts when a local certificate will expire in a configurable number of days. Can optionally ignore self-signed certificates, certificates that have been expired for a long time and certificates that were only valid for an extremely short time frame.
<#
.SYNOPSIS
    Alerts when a local certificate will expire in a configurable number of days. Can optionally ignore self-signed certificates, certificates that have been expired for a long time and certificates that were only valid for an extremely short time frame.
.DESCRIPTION
    Alerts when a local certificate will expire in a configurable number of days. 
    Can optionally ignore self-signed certificates, certificates that have been expired for a long time 
    and certificates that were only valid for an extremely short time frame.
.EXAMPLE
    (No Parameters)
    
    Checking for certificates that were valid before 10/10/2023 09:07:23 and will expire before 11/11/2023 09:07:23.
    No Certificates were found with an expiration date before 11/11/2023 09:07:23 and after 07/13/2023 09:07:23.

PARAMETER: -DaysUntilExpiration "ReplaceWithNumber"
    Alerts if a certificate is set to expire within the specified number of days.
.EXAMPLE
    -DaysUntilExpiration "366"
    
    Checking for certificates that were valid before 10/10/2023 09:08:14 and will expire before 10/12/2024 09:08:14.

    WARNING: Expired Certificates found!

    ### Expired Certificates ###

    SerialNumber                     HasPrivateKey ExpirationDate        Subject
    ------------                     ------------- --------------        -------
    0AA60783EBB5076EBC2D12DA9B04C290         False 6/10/2024 4:59:59 PM  CN=Insecure.Com LLC, O=Insecure.Com...
    619DCC976458E38D471DC3DCE3603C2C          True 3/29/2024 10:19:00 AM CN=KYLE-SRV22-TEST.test.lan
    0AA60783EBB5076EBC2D12DA9B04C290         False 6/10/2024 4:59:59 PM  CN=Insecure.Com LLC, O=Insecure.Com...
    7D5FC733E3A8CF9344CDDFC0AB01CCB9          True 4/9/2024 9:53:53 AM   CN=KYLE-SRV22-TEST.test.lan
    4EDC0A79D6CD5A8D4D1E3705BC20C206          True 4/9/2024 9:58:06 AM   CN=KYLLE-SRV22-TEST.test.lan

PARAMETER: -MustBeValidBefore "ReplaceWithNumber"
    Only alert on certificates that are older than X days. This is primarily to silence alerts about certificates that were only valid for 24 hours in their entire lifetime.

PARAMETER: -Cutoff "ReplaceWithNumber"
    Don't alert on certificates that have been expired for longer than X days (default is 91 days).

PARAMETER: -IgnoreSelfSignedCerts
    Ignore certificates where the subject of the certificate and the issuer of the certificate are identical.

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Server 2008
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$ExpirationFromCustomField = "certExpirationAlertDays",
    [Parameter()]
    [int]$DaysUntilExpiration = 30,
    [Parameter()]
    [int]$MustBeValidBefore = 2,
    [Parameter()]
    [int]$Cutoff = 91,
    [Parameter()]
    [Switch]$IgnoreSelfSignedCerts = [System.Convert]::ToBoolean($env:ignoreSelfSignedCerts)
)
begin {
    # Retrieve script variables from the dynamic script form.
    if ($env:expirationFromCustomFieldName -and $env:expirationFromCustomFieldName -notlike "null") { $ExpirationFromCustomField = $env:expirationFromCustomFieldName }
    if ($env:daysUntilExpiration -and $env:daysUntilExpiration -notlike "null") { $DaysUntilExpiration = $env:daysUntilExpiration }
    if ($env:certificateMustBeOlderThanXDays -and $env:certificateMustBeOlderThanXDays -notlike "null") { $MustBeValidBefore = $env:certificateMustBeOlderThanXDays }
    if ($env:skipCertsExpiredForMoreThanXDays -and $env:skipCertsExpiredForMoreThanXDays -notlike "null") { $Cutoff = $env:skipCertsExpiredForMoreThanXDays }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # If using the custom field option, check for the default value and replace it if necessary.
    if ($PSVersionTable.PSVersion.Major -gt 2) {
        $CustomField = Ninja-Property-Get -Name $ExpirationFromCustomField 2>$Null
    }

    if ($CustomField -and $DaysUntilExpiration -eq 30 -and (Test-IsElevated) -and $PSVersionTable.PSVersion.Major -gt 2) {
        Write-Host "Retrieved value of $CustomField days from Custom Field $ExpirationFromCustomField. Using it for expiration value."
        $DaysUntilExpiration = $CustomField
    }
    elseif (-not (Test-IsElevated) -or $PSVersionTable.PSVersion.Major -le 2) {
        Write-Warning "Skipping CustomField retrieval due to either incompatible PowerShell version or lack of elevation."
    }
}
process {
    # Calculate expiration and cutoff dates.
    $ExpirationDate = (Get-Date "11:59pm").AddDays($DaysUntilExpiration)
    $CutoffDate = (Get-Date "12am").AddDays(-$Cutoff)
    $MustBeValidBeforeDate = (Get-Date "12am").AddDays(-$MustBeValidBefore)

    # Retrieve all certificates.
    $Certificates = Get-ChildItem -Path "Cert:\" -Recurse

    Write-Host "Checking for certificates that were valid before $MustBeValidBeforeDate and will expire before $ExpirationDate."
    
    # Filter down to certificates that are expired in our desired date range
    $ExpiredCertificates = $Certificates | Where-Object { $_.NotAfter -le $ExpirationDate -and $_.NotAfter -gt $CutoffDate -and $_.NotBefore -lt $MustBeValidBeforeDate }

    # If we're asked to ignore self signed certs we'll filter them out
    if ($IgnoreSelfSignedCerts -and $ExpiredCertificates) {
        Write-Host "Removing Self-Signed certificates from list."
        $ExpiredCertificates = $ExpiredCertificates | Where-Object { $_.Subject -ne $_.Issuer }
    }

    if ($ExpiredCertificates) {
        Write-Host ""
        Write-Warning "Expired Certificates found!"
        Write-Host ""

        $Report = $ExpiredCertificates | ForEach-Object {
            # Subject can be a long property, we'll truncate it to maintain readability
            New-Object PSObject -Property @{
                SerialNumber   = $_.SerialNumber
                HasPrivateKey  = $_.HasPrivateKey
                ExpirationDate = $_.NotAfter
                Subject        = if ($_.Subject.Length -gt 35) { $_.Subject.Substring(0, 35) + "..." }else { $_.Subject }
            }
        }

        Write-Host "### Expired Certificates ###"
        $Report | Format-Table -AutoSize | Out-String | Write-Host

        exit 1
    }
    else {
        Write-Host "No Certificates were found with an expiration date before $ExpirationDate and after $CutoffDate."
    }
}
end {
    
    
    
}
