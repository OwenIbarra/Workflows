# Get ConnectWise ScreenConnect Launch URL and save to custom field (defaults to screenconnectUrl). Requires the domain used for ScreenConnect and a Session Group the machine is a part of to successfully build URL.

<#
.SYNOPSIS
    Get ConnectWise ScreenConnect Launch URL and save to custom field (defaults to screenconnectUrl). Requires the domain used for ScreenConnect and a Session Group the machine is a part of to successfully build URL.
.DESCRIPTION
    Get ConnectWise ScreenConnect Launch URL and save to custom field (defaults to screenconnectUrl). 
    Requires the domain used for ScreenConnect and a Session Group the machine is a part of to successfully build URL.
.EXAMPLE
    -ScreenConnectDomain "replace.me" -InstanceID "1111111111"

    Building Launch URL(s)...
    Launch URL(s) Created


    Instance  : 1111111111
    LaunchURL : https://replace.me/Host#Access/All%20Machines//555555-555-555-5555-55555/Join
    SessionId : 555555-555-555-5555-55555

PARAMETER: -ScreenConnectDomain "ExampleInput"
    The domain used for your Connectwise ScreenConnect Instance.

PARAMETER: -SessionGroup "ExampleInput"
    The Session Group in which the machine would normally be found. Defaults to "All Machines".

PARAMETER: -InstanceID "ExampleInput"
    The Instance ID for your instance of ScreenConnect. Used to differentiate between multiple installed ScreenConnect Instances.
    To get the instance id you can see it in the program's name in Control Panel e.g. ScreenConnect Client (yourinstanceidishere) 
    or in ScreenConnect itself (Admin > Advanced > Server Information > Instance Identifier Fingerprint).

PARAMETER: -CustomField "ReplaceWithAnyMultilineCustomField"
    The custom field you would like to write the results to. Defaults to screenconnectUrl

.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7+, Server 2008+
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$ScreenConnectDomain,
    [Parameter()]
    [String]$SessionGroup = "All Machines",
    [Parameter()]
    [String]$InstanceID,
    [Parameter()]
    [String]$CustomField = "screenconnectUrl"
)

begin {
    if ($env:screenconnectDomain -and $env:screenconnectDomain -notlike "null") { $ScreenConnectDomain = $env:screenconnectDomain }
    if ($env:sessionGroup -and $env:sessionGroup -notlike "null") { $SessionGroup = $env:sessionGroup }
    if ($env:instanceId -and $env:instanceId -notlike "null") { $InstanceID = $env:instanceId }
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }

    # Warn end-user if we're not provided an instance id
    if (-not ($InstanceID)) {
        Write-Warning "Without the instance id we will be unable to tell which ScreenConnect instance is yours if multiple are installed resulting in the wrong URL being displayed."
        Write-Warning "To get the instance id you can see it in the programs name in Control Panel ex. ScreenConnect Client (yourinstanceidishere) or in Control itself (Admin > Advanced > Server Information > Instance Identifier Fingerprint)"
    }

    # These two are actually necessary to build the URL
    if (-not ($ScreenConnectDomain) -or -not ($SessionGroup)) {
        Write-Error "Unable to build URL without the domain or Session Group."
        exit 1
    }

    # Test for elevation
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Checks the two Uninstall registry keys to see if the app is installed. Needs the name as it would appear in Control Panel.
    function Find-UninstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString
        )
        process {
            $UninstallList = New-Object System.Collections.Generic.List[Object]

            $Result = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($Result) { $UninstallList.Add($Result) }

            $Result = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($Result) { $UninstallList.Add($Result) }

            # Programs don't always have an uninstall string listed here so to account for that I made this optional.
            if ($UninstallString) {
                $UninstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $UninstallList
            }
        }
    }

    # Define the name of the software we are searching for and look for it in both the 64 bit and 32 bit registry nodes.
    if (-not $InstanceID) { $SoftwareName = "ScreenConnect Client" }else { $SoftwareName = "ScreenConnect Client ($InstanceID)" }
    $ControlInstallation = Find-UninstallKey -DisplayName $SoftwareName

    # If its not installed lets error out.
    if (-not ($ControlInstallation)) {
        Write-Error "Connectwise ScreenConnect is not installed!"
        exit 1
    }

    # Elevation is required to write to custom fields. 
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }
}
process {
    # The Image Path Registry Key contains the unique session id needed to generate the URL
    Write-Host "Building Launch URL(s)..."
    $ControlInstances = $ControlInstallation.DisplayName | ForEach-Object {
        $ImagePath = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$_" | Select-Object -Property ImagePath -ExpandProperty ImagePath
        $Id = ($ImagePath -split '&' | Where-Object { $_ -match 's=(.*-){4}' }) -replace "s="
        $Instance = ($_ -replace "ScreenConnect Client \(" -replace "\)").trim()
        New-Object psobject -Property @{
            Instance  = $Instance
            LaunchURL = [URI]::EscapeUriString("https://$ScreenConnectDomain/Host#Access/$SessionGroup//$Id/Join")
            SessionId = $Id
        }
    }

    # Create a Table/List of our results 
    Write-Host "Launch URL(s) Created"
    $ControlInstances | Format-List -Property Instance, LaunchURL, SessionId | Out-String | Write-Host

    # PowerShell 2.0 does not support ninjarmm-cli
    if ($PSVersionTable.PSVersion.Major -gt 2) {
        if ($ControlInstances.LaunchURL.Count -gt 1) {
            Ninja-Property-Set -Name $CustomField -Value ($ControlInstances | Format-List -Property Instance, LaunchURL | Out-String)
        }
        else {
            Ninja-Property-Set -Name $CustomField -Value ($ControlInstances.LaunchURL | Out-String)
        }
    }
    else {
        Write-Host "ninjarmm-cli does not support PowerShell 1 & 2. Refer to https://ninjarmm.zendesk.com/hc/en-us/articles/4405408656013 ."
    }
}
end {
    
    
    
}
