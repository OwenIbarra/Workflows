# Gets the Organizational Units (OUs) that this device is a member of in Active Directory or Azure AD.
<#
.SYNOPSIS
    Gets the Organizational Units (OUs) that this device is a member of in Active Directory or Azure AD.
.DESCRIPTION
    Gets the Organizational Units (OUs) that this device is a member of in Active Directory or Azure AD.
.EXAMPLE
    -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    
    Attempting to set Custom Field 'ReplaceMeWithAnyMultilineCustomField'.
    Successfully set Custom Field 'ReplaceMeWithAnyMultilineCustomField'!

    Organizational Units Found:
    OU=Domain Controllers,OU=Computers,DC=test,DC=lan
    OU=Servers,OU=Computers,DC=test,DC=lan

PARAMETER: -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    Name of a multiline custom field to save the results to.
.EXAMPLE
    -CustomFieldName "ReplaceMeWithAnyMultilineCustomField"
    
    Attempting to set Custom Field 'ReplaceMeWithAnyMultilineCustomField'.
    Successfully set Custom Field 'ReplaceMeWithAnyMultilineCustomField'!

    Organizational Units Found:
    OU=Domain Controllers,OU=Computers,DC=test,DC=lan
    OU=Servers,OU=Computers,DC=test,DC=lan
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomFieldName
)

begin {
    # If using script form variables, replace command line parameters with the form variables.
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomFieldName = $env:customFieldName }

    # Function to check if the script is running with elevated (administrator) privileges
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsDomainJoined {
        # Check the PowerShell version to determine the appropriate cmdlet to use
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
        }
        else {
            return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
        }
    }

}
process {
    # Check if the script is running with elevated (administrator) privileges
    if (!(Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine'
    $DistinguishedName = Get-ItemProperty -Path $regPath -Name 'Distinguished-Name' -ErrorAction SilentlyContinue

    $OrganizationalUnit = if ($DistinguishedName -and $DistinguishedName.'Distinguished-Name') {
        $OU = $DistinguishedName.'Distinguished-Name' -replace '^CN=.*?,', ''
        Write-Output $OU
    }
    else {
        Write-Host "[Warn] Failed to retrieve Organizational Unit from Group Policy State."
    }

    $OrganizationalUnit = if (Test-ComputerSecureChannel -ErrorAction SilentlyContinue) {
        "$OrganizationalUnit"
    }
    else {
        "(Cached) $OrganizationalUnit"
    }

    if ($OrganizationalUnit) {
        Write-Host "[Info] The OU for $env:COMPUTERNAME is: $OrganizationalUnit"
    }
    else {
        Write-Host "[Error] Failed to retrieve Organizational Units."
        exit 1
    }

    # If custom field name is provided, set the custom field with the list of OUs
    if ($CustomFieldName) {
        Write-Host ""
        Write-Host "Note: Custom field '$CustomFieldName' was specified but NinjaOne integration has been removed."
        Write-Host "All output has been displayed above."
    }

    exit 0
}
end {

}
