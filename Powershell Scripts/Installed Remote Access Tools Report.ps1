# This script will look for remote access tools installed on the system. It can be given a list of tools to ignore as well as grab the exclusion list from a designated custom field.

DISCLAIMER: This script is provided as a best effort for detecting remote access software installed on an agent, but it is not guaranteed to be 100% accurate.
Some remote access software may not be detected, or false positives may be reported. Use this script at your own risk and verify its results with other methods where possible.
#Requires -Version 5.1

<#
.SYNOPSIS
    This script will look for remote access tools installed on the system. It can be given a list of tools to ignore as well as grab the exclusion list from a designated custom field.
    
    DISCLAIMER: This script is provided as a best effort for detecting remote access software installed on an agent, but it is not guaranteed to be 100% accurate. 
    Some remote access software may not be detected, or false positives may be reported. Use this script at your own risk and verify its results with other methods where possible.
.DESCRIPTION
    This script will look for remote access tools installed on the system. Below is the full list of tools. Please note you can give it a list of tools to ignore and you can have
    it grab the list from a custom field of your choosing.

    DISCLAIMER: This script is provided as a best effort for detecting remote access software installed on an agent, but it is not guaranteed to be 100% accurate. 
    Some remote access software may not be detected, or false positives may be reported. Use this script at your own risk and verify its results with other methods where possible.

    Remote Tools: AeroAdmin, Ammyy Admin, AnyDesk, BeyondTrust, Chrome Remote Desktop, Connectwise Control, DWService, GoToMyPC, LiteManager, LogMeIn, ManageEngine,
    NoMachine, Parsec, Remote Utilities, RemotePC, Splashtop, Supremo, TeamViewer, TightVNC, UltraVNC, VNC Connect (RealVNC), Zoho Assist
    RMM's: Atera, Automate, Datto RMM, Kaseya, N-Able N-Central, N-Able N-Sight, Syncro

.EXAMPLE
    (No Parameters)
    Name                    CurrentlyRunning    HasRunningService   UninstallString
    ----                    ----------------    -----------------   ---------------
    Connectwise Control     Yes                 Yes                 MsiExec /X{examplestring}
    Chrome Remote Desktop   Yes                 Yes                 MsiExec /X{examplestring}

PARAMETER: -ExcludeTools "Chrome Remote Desktop,Connectwise Control"
    A comma separated list of tools you'd like to exclude from alerting on.
.EXAMPLE
    -ExcludeTools "Chrome Remote Desktop,Connectwise Control"
    We couldn't find any active remote access tools!

PARAMETER: -ExclusionsFromCustomField "ReplaceMeWithAnyTextCustomField"
    The name of a custom field that contains a comma separated list of tools to exclude from alerting. E.g. "ApprovedRemoteTools"
.EXAMPLE
    -ExclusionsFromCustomField "ReplaceMeWithAnyTextCustomField"
    We couldn't find any active remote access tools!

PARAMETER: -ExportCSV "ReplaceMeWithAnyMultiLineCustomField"
    The name of a multiline custom field to export to in csv format. ex. "RemoteTools"
.EXAMPLE
    -ExportCSV "ReplaceMeWithAnyMultiLineCustomField"
    Name                    CurrentlyRunning    HasRunningService   UninstallString
    ----                    ----------------    -----------------   ---------------
    Connectwise Control     Yes                 Yes                 MsiExec /X{examplestring}
    Chrome Remote Desktop   Yes                 Yes                 MsiExec /X{examplestring}

PARAMETER: -ExportJSON "ReplaceMeWithAnyMultiLineCustomField"
    The name of a multiline custom field to export to in JSON format. E.g. "RemoteTools"
.EXAMPLE
    -ExportJSON "ReplaceMeWithAnyMultiLineCustomField"
    Name                    CurrentlyRunning    HasRunningService   UninstallString
    ----                    ----------------    -----------------   ---------------
    Connectwise Control     Yes                 Yes                 MsiExec /X{examplestring}
    Chrome Remote Desktop   Yes                 Yes                 MsiExec /X{examplestring}

PARAMETER: -ShowNotFound
    Show the tools the script did not find as well.
.EXAMPLE
    -ShowNotFound
    Name                    CurrentlyRunning    HasRunningService   UninstallString
    ----                    ----------------    -----------------   ---------------
    AeroAdmin               No                  No
    Ammyy Admin             No                  No
    BeyondTrust             No                  No
    Connectwise Control     Yes                 Yes                 MsiExec /X{examplestring}
    Chrome Remote Desktop   Yes                 Yes                 MsiExec /X{examplestring}
    
.OUTPUTS
    None
.NOTES
    General notes: CustomFields must be multiline for export. Regular text is fine for ExclusionsFromCustomField
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Renamed script and added Script Variable support, added error for when -ExportJSON and -ExportCSV are used together
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$ExcludeTools,
    [Parameter()]
    [String]$ExclusionsFromCustomField,
    [Parameter()]
    [String]$ExportCSV,
    [Parameter()]
    [String]$ExportJSON,
    [Parameter()]
    [Switch]$ShowNotFound = [System.Convert]::ToBoolean($env:includeToolsThatWereNotFound)
)

begin {
    #DISCLAIMER: This script is provided as a best effort for detecting remote access software installed on an agent, but it is not guaranteed to be 100% accurate. 
    #Some remote access software may not be detected, or false positives may be reported. Use this script at your own risk and verify its results with other methods where possible.

    if ($env:toolsToIgnore -and $env:toolsToIgnore -notlike "null") { $ExcludeTools = $env:toolsToIgnore }
    if ($env:retrieveIgnoreListFromCustomField -and $env:retrieveIgnoreListFromCustomField -notlike "null") { $ExclusionsFromCustomField = $env:retrieveIgnoreListFromCustomField }
    if ($env:exportCsvResultsToThisCustomField -and $env:exportCsvResultsToThisCustomField -notlike "null") { $ExportCSV = $env:exportCsvResultsToThisCustomField }
    if ($env:exportJsonResultsToThisCustomField -and $env:exportJsonResultsToThisCustomField -notlike "null") { $ExportJSON = $env:exportJsonResultsToThisCustomField }

    if ($ExportCSV -and $ExportJSON) { Write-Error "You can only export in either JSON or CSV format. Not both."; exit 1 }

    # Check's the two Uninstall registry keys to see if the app is installed. Needs the name as it would appear in Control Panel.
    function Find-UninstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString
        )
        process {
            $UninstallList = New-Object System.Collections.Generic.List[Object]

            $Result = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | 
                Where-Object { $_.DisplayName -like "*$DisplayName*" }

            if ($Result) { $UninstallList.Add($Result) }

            $Result = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | 
                Where-Object { $_.DisplayName -like "*$DisplayName*" }

            if ($Result) { $UninstallList.Add($Result) }

            # Programs don't always have an uninstall string listed here so to account for that I made this optional.
            if ($UninstallString) {
                # 64 Bit
                $UninstallList | Select-Object -ExpandProperty UninstallString -ErrorAction Ignore
            }
            else {
                $UninstallList
            }
        }
    }

    # This will see if the process is currently active. Some people may want to react sooner to these alerts if its currently running vs not.
    function Find-Process {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [String]$Name
        )
        process {
            Get-Process | Where-Object { $_.ProcessName -like "*$Name*" } | Select-Object -ExpandProperty Name
        }
    }

    # This will search C:\ProgramFiles and C:\ProgramFiles(x86) for the executable these tools use to run.
    function Find-Executable {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [String]$Path,
            [Parameter()]
            [Switch]$Special
        )
        process {
            if (!$Special) {
                if (Test-Path "$env:ProgramFiles\$Path") {
                    "$env:ProgramFiles\$Path"
                }
        
                if (Test-Path "${Env:ProgramFiles(x86)}\$Path") {
                    "${Env:ProgramFiles(x86)}\$Path"
                }
    
                if (Test-Path "$env:ProgramData\$Path") {
                    "$env:ProgramData\$Path"
                }
            }
            else {
                if (Test-Path $Path) {
                    $Path
                }
            }
        }
    }

    # Brought Get-CimInstance outside the function for better performance.

    $ServiceList = Get-CimInstance win32_service
    function Find-Service {
        [CmdletBinding()]
        param(
            [Parameter(ValueFromPipeline)]
            [String]$Name
        )
        process {
            # Get-Service will display an error everytime it has an issue reading a service. Ignoring them as they're not relevant.
            $ServiceList | Where-Object { $_.State -notlike "Disabled" -and $_.State -notlike "Stopped" } | 
                Where-Object { $_.PathName -Like "*$Name.exe*" }
        }
    }

    function Export-CustomField {
        [CmdletBinding()]
        param(
            [Parameter()]
            [String]$Name,
            [Parameter()]
            [ValidateSet("csv", "json")]
            [String]$Format,
            [Parameter()]
            [PSCustomObject]$Object
        )
        if ($Format -eq "csv") {
            $csv = $Object | ConvertTo-Csv -NoTypeInformation | Out-String
            Ninja-Property-Set $Name $csv
        }
        else {
            $json = $Object | ConvertTo-Json | Out-String
            Ninja-Property-Set $Name $json
        }
    }

    # This define's what tools we're looking for and how the script can find them. Some don't actually install anywhere (portable app) others do. 
    # Some change their installation path everytime so not particularly worth it to find it that way.
    # Others store themselves in a super weird directory. Many don't list exactly where there .exe file is stored and suggest you exclude the whole folder from the av.
    $RemoteToolList = @(
        [PSCustomObject]@{Name = "AeroAdmin"; ProcessName = "AeroAdmin" }
        [PSCustomObject]@{Name = "Ammyy Admin"; ProcessName = "AA_v3" }
        [PSCustomObject]@{Name = "AnyDesk"; DisplayName = "AnyDesk"; ProcessName = "AnyDesk"; ExecutablePath = "AnyDesk\AnyDesk.exe" }
        [PSCustomObject]@{Name = "BeyondTrust"; DisplayName = "Remote Support Jump Client", "Jumpoint"; ProcessName = "bomgar-jpt" }
        [PSCustomObject]@{Name = "Chrome Remote Desktop"; DisplayName = "Chrome Remote Desktop Host"; ProcessName = "remoting_host"; ExecutablePath = "Google\Chrome Remote Desktop\112.0.5615.26\remoting_host.exe" }
        [PSCustomObject]@{Name = "Connectwise Control"; DisplayName = "ScreenConnect Client"; ProcessName = "ScreenConnect.ClientService" }
        [PSCustomObject]@{Name = "DWService"; DisplayName = "DWAgent"; ProcessName = "dwagent", "dwagsvc"; ExecutablePath = "DWAgent\runtime\dwagent.exe" }
        [PSCustomObject]@{Name = "GoToMyPC"; DisplayName = "GoToMyPC"; ProcessName = "g2comm", "g2pre", "g2svc", "g2tray"; ExecutablePath = "GoToMyPC\g2comm.exe", "GoToMyPC\g2pre.exe", "GoToMyPC\g2svc.exe", "GoToMyPC\g2tray.exe" }
        [PSCustomObject]@{Name = "LiteManager"; DisplayName = "LiteManager Pro - Server"; ProcessName = "ROMServer", "ROMFUSClient"; ExecutablePath = "LiteManager Pro - Server\ROMFUSClient.exe", "LiteManager Pro - Server\ROMServer.exe" }
        [PSCustomObject]@{Name = "LogMeIn"; DisplayName = "LogMeIn"; ProcessName = "LogMeIn"; ExecutablePath = "LogMeIn\x64\LogMeIn.exe", "LogMeIn\x64\LogMeInSystray.exe" }
        [PSCustomObject]@{Name = "ManageEngine"; DisplayName = "ManageEngine Remote Access Plus - Server", "ManageEngine UEMS - Agent"; ProcessName = "dcagenttrayicon", "UEMS", "dcagentservice"; ExecutablePath = "UEMS_Agent\bin\dcagenttrayicon.exe", "UEMS_CentralServer\bin\UEMS.exe", "UEMS_Agent\bin\dcagentservice.exe" }
        [PSCustomObject]@{Name = "NoMachine"; DisplayName = "NoMachine"; ProcessName = "nxd", "nxnode.bin", "nxserver.bin", "nxservice64"; ExecutablePath = "NoMachine\bin\nxd.exe", "NoMachine\bin\nxnode.bin", "NoMachine\bin\nxserver.bin", "NoMachine\bin\nxservice64.exe" }
        [PSCustomObject]@{Name = "Parsec"; DisplayName = "Parsec"; ProcessName = "parsecd", "pservice"; ExecutablePath = "Parsec\parsecd.exe", "Parsec\pservice.exe" }
        [PSCustomObject]@{Name = "Remote Utilities"; DisplayName = "Remote Utilities - Host"; ProcessName = "rutserv", "rfusclient"; ExecutablePath = "Remote Utilities - Host\rfusclient.exe" }
        [PSCustomObject]@{Name = "RemotePC"; DisplayName = "RemotePC"; ProcessName = "RemotePCHostUI", "RPCPerformanceService"; ExecutablePath = "RemotePC Host\RemotePCHostUI.exe", "RemotePC Host\RemotePCPerformance\RPCPerformanceService.exe" }
        [PSCustomObject]@{Name = "Splashtop"; DisplayName = "Splashtop Streamer"; ProcessName = "SRAgent", "SRAppPB", "SRFeature", "SRManager", "SRService"; ExecutablePath = "Splashtop\Splashtop Remote\Server\SRService.exe" }
        [PSCustomObject]@{Name = "Supremo"; ProcessName = "Supremo", "SupremoHelper", "SupremoService"; ExecutablePath = "Supremo\SupremoService.exe" }
        [PSCustomObject]@{Name = "TeamViewer"; DisplayName = "TeamViewer"; ProcessName = "TeamViewer", "TeamViewer_Service", "tv_w32", "tv_x64"; ExecutablePath = "TeamViewer\TeamViewer.exe", "TeamViewer\TeamViewer_Service.exe", "TeamViewer\tv_w32.exe", "TeamViewer\tv_x64.exe" }
        [PSCustomObject]@{Name = "TightVNC"; DisplayName = "TightVNC"; ProcessName = "tvnserver"; ExecutablePath = "TightVNC\tvnserver.exe" }
        [PSCustomObject]@{Name = "UltraVNC"; DisplayName = "UltraVNC"; ProcessName = "winvnc"; ExecutablePath = "uvnc bvba\UltraVNC\WinVNC.exe" }
        [PSCustomObject]@{Name = "VNC Connect (RealVNC)"; DisplayName = "VNC Server"; ProcessName = "vncserver"; ExecutablePath = "RealVNC\VNC Server\vncserver.exe" }
        [PSCustomObject]@{Name = "Zoho Assist"; DisplayName = "Zoho Assist Unattended Agent"; ProcessName = "ZohoURS", "ZohoURSService"; ExecutablePath = "ZohoMeeting\UnAttended\ZohoMeeting\ZohoURS.exe", "ZohoMeeting\UnAttended\ZohoMeeting\ZohoURSService.exe" }
        [PSCustomObject]@{Name = "Atera"; DisplayName = "AteraAgent"; ProcessName = "AteraAgent"; ExecutablePath = "ATERA Networks\AteraAgent\AteraAgent.exe" }
        [PSCustomObject]@{Name = "Automate"; DisplayName = "Connectwise Automate"; ProcessName = "LTService", "LabTechService"; SpecialExecutablePath = "C:\Windows\LTSvc\LTSvc.exe" }
        [PSCustomObject]@{Name = "Datto RMM"; DisplayName = "Datto RMM"; ProcessName = "AEMAgent"; ExecutablePath = "CentraStage\AEMAgent\AEMAgent.exe", "CentraStage\gui.exe" }
        [PSCustomObject]@{Name = "Kaseya"; DisplayName = "Kaseya Agent"; ProcessName = "AgentMon", "KaseyaRemoteControlHost", "Kasaya.AgentEndpoint"; ExecutablePath = "Kaseya\AgentMon\AgentMon.exe" }
        [PSCustomObject]@{Name = "N-Able N-Central"; DisplayName = "Windows Agent"; ProcessName = "winagent"; ExecutablePath = "N-able Technologies\Windows Agent\winagent.exe" }
        [PSCustomObject]@{Name = "N-Able N-Sight"; DisplayName = "Advanced Monitoring Agent"; ProcessName = "winagent"; ExecutablePath = "Advanced Monitoring Agent\winagent.exe", "Advanced Monitoring Agent GP\winagent.exe" }
        [PSCustomObject]@{Name = "Syncro"; DisplayName = "Syncro", "Kabuto"; ProcessName = "Syncro.App.Runner", "Kabuto.App.Runner", "Syncro.Service.Runner", "Kabuto.Service.Runner", "SyncroLive.Agent.Runner", "Kabuto.Agent.Runner", "SyncroLive.Agent.Service", "Syncro.Access.Service", "Syncro.Access.App"; ExecutablePath = "RepairTech\Syncro\Syncro.Service.Runner.exe", "RepairTech\Syncro\Syncro.App.Runner.exe" }
    )
}
process {

    # Lets see what tools we don't want to alert on.
    $ExcludedTools = New-Object System.Collections.Generic.List[String]

    if ($ExcludeTools) {
        $ExcludeTools -split ',' | ForEach-Object { $ExcludedTools.Add($_.Trim()) }
    }

    # For this kind of alert it might be worth it to create a whole custom field of ignorables.
    if ($ExclusionsFromCustomField) {
        (Ninja-Property-Get $ExclusionsFromCustomField) -split ',' | ForEach-Object { $ExcludedTools.Add($_.Trim()) }
    }

    if ($ExportCSV) {
        $Format = "csv"

        if ($ExportCSV) {
            $ExportResults = $ExportCSV
        }
    }
    elseif ($ExportJSON) {
        $Format = "json"

        if ($ExportJSON) {
            $ExportResults = $ExportJSON
        }
    }

    # This take's our list and begins searching by the 4 method's in the begin block. 
    $RemoteAccessTools = $RemoteToolList | ForEach-Object {

        $UninstallKey = if ($_.DisplayName) {
            $_.DisplayName | Find-UninstallKey
        }
        
        $UninstallInfo = if ($_.DisplayName) {
            $_.DisplayName | Find-UninstallKey -UninstallString
        }
        
        $RunningStatus = if ($_.ProcessName) {
            $_.ProcessName | Find-Process
        }

        $ServiceStatus = if ($_.ProcessName) {
            $_.ProcessName | Find-Service
        }
        
        $InstallPath = if ($_.ExecutablePath) {
            $_.ExecutablePath | Find-Executable
        }
        elseif ($_.SpecialExecutablePath) {
            $_.SpecialExecutablePath | Find-Executable -Special
        }

        if ($UninstallKey -or $RunningStatus -or $InstallPath -or $ServiceStatus) {
            $Installed = "Yes"
        }
        else {
            $Installed = "No"
        }

        [PSCustomObject]@{
            Name              = $_.Name
            Installed         = $Installed
            CurrentlyRunning  = if ($RunningStatus) { "Yes" }else { "No" }
            HasRunningService = if ($ServiceStatus) { "Yes" }else { "No" }
            UninstallString   = $UninstallInfo
            ExePath           = $InstallPath
        } | Where-Object { $ExcludedTools -notcontains $_.Name }
    }

    $ActiveRemoteAccessTools = $RemoteAccessTools | Where-Object { $_.Installed -eq "Yes" }

    # If we found anything in the three check's we're gonna indicate it's installed but we may also want to save our results to a custom field.
    # We also may want to output more than "We couldn't find any active remote access tools!" in the event we find nothing.
    if ($ShowNotFound) {

        $RemoteAccessTools | Format-Table -Property Name, Installed, CurrentlyRunning, HasRunningService, UninstallString -AutoSize -Wrap | Out-String | Write-Host

        if ($ExportResults) {
            Export-CustomField -Name $ExportResults -Format $Format -Object ($RemoteAccessTools | Select-Object Name, Installed, CurrentlyRunning, HasRunningService)
        }

    }
    else {
        if ($ActiveRemoteAccessTools) {

            $ActiveRemoteAccessTools | Format-Table -Property Name, CurrentlyRunning, HasRunningService, UninstallString -AutoSize -Wrap | Out-String | Write-Host

            if ($ExportResults) {
                Export-CustomField -Name $ExportResults -Format $Format -Object ($ActiveRemoteAccessTools | Select-Object Name, CurrentlyRunning, HasRunningService)
            }

        }
        else {
            Write-Host "We couldn't find any active remote access tools!"
        }
    }

    if ($ActiveRemoteAccessTools) {
        # We're going to set a failure status code in the event that we find something.
        exit 1
    }
    else {
        exit 0
    }
}
end {
    
    
    
}

