# Pins items to the taskbar. Required to be run as an Administrator account and not as SYSTEM.

<#
.SYNOPSIS
    Pins items to the taskbar. Required to be run as an Administrator account and not as SYSTEM.
.DESCRIPTION
    Pins items to the taskbar. Required to be run as an Administrator account and not as SYSTEM.
    This script will use the AppId from Get-StartApps.
    Running Get-StartApps will list all available applications.
    You can find the AppId by running Get-StartApps and looking at the "AppId" column.

    Notes:
     Clearing all pinned items will not remove pinned items that a user has added themselves.
     Using environment variables like %APPDATA% will work,
      but this script might warn you that the file path does not exist if the user running this doesn't have the file in it's %APPDATA% path.

    If pinning a Windows Store app, use the AppId without the ! and text after the !.
    For example use "Microsoft.Windows.Photos_8wekyb3d8bbwe" instead of "Microsoft.Windows.Photos_8wekyb3d8bbwe!App".

    For desktop apps, use the AppID as well.
    A few examples:
     Google Chrome's AppId is "Chrome".
     Internet Explorer's AppId is "Microsoft.InternetExplorer.Default".
     Microsoft Edge's AppId is "MSEdge".
     Node.js's AppId is "{6D809377-6AF0-444B-8957-A3773F02200E}\nodejs\node.exe"
     Notepad++'s AppId is "{6D809377-6AF0-444B-8957-A3773F02200E}\Notepad++\notepad++.exe".
     My Application in AppData is "%APPDATA%\My Application\MyApplication.exe".


.EXAMPLE
     -Application "Photos"
    Pins the Photos UWP app to the taskbar.

.EXAMPLE
     -Application "Chrome"
    Pins the Chrome desktop app to the taskbar.

.EXAMPLE
     -Application "Microsoft.Windows.Photos_8wekyb3d8bbwe, Chrome, {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
    Pins the Photos UWP, Chrome, and PowerShell to the taskbar.

.EXAMPLE
     -Application "Chrome, Microsoft.InternetExplorer.Default, {6D809377-6AF0-444B-8957-A3773F02200E}\nodejs\node.exe"


.EXAMPLE
     -Clear
    Clears ALL pinned items from the taskbar.

PARAMETER: -Application "ReplaceMeWithApplicationName"
    The name of the application you would like to pin to the taskbar. Running Get-StartApps will list all available applications.

PARAMETER: -Clear
        Clears ALL pinned items from the taskbar.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release

    System Layout Path: C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml
#>

[CmdletBinding()]
param (
    [String]$Applications,
    [switch]$Clear,
    [switch]$Restart
)

begin {
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    if ($env:applications -and $env:applications -notlike "null") { $Applications = $env:applications }
    if ($env:clear -and $env:clear -notlike "false") { $Clear = $true }
    if ($env:restart -and $env:restart -notlike "false") { $Restart = $true }

    $XmlTemplate = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
    LAYOUTXML
        <defaultlayout:TaskbarLayout>
            <taskbar:TaskbarPinList>
                PINLISTXML
            </taskbar:TaskbarPinList>
        </defaultlayout:TaskbarLayout>
    </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@

    $DefaultLayout = "<CustomTaskbarLayoutCollection>"

    $TempLayoutPath = "$env:Temp\layoutmodification$(Get-Random).xml"
    $HasError = $false
}
process {
    if ((Test-IsSystem)) {
        Write-Host "[Error] This script must be ran as an Administrator and not as SYSTEM."
        exit 1
    }

    if (-not (Test-IsElevated)) {
        Write-Host "[Error] This script must be ran as an Administrator."
        exit 1
    }

    if ($Clear -and $Applications) {
        Write-Host "[Error] You cannot use both Clear and Applications parameters."
        exit 1
    }
    $PinnedApps = [System.Collections.Generic.List[String]]::new()
    # Check if we are clearing pinned apps
    $PinListContent = if ($Clear) {
        # Add PinListPlacement="Replace" to CustomTaskbarLayoutCollection
        $DefaultLayout = "<CustomTaskbarLayoutCollection PinListPlacement=`"Replace`">"
        # Add <taskbar:DesktopApp DesktopApplicationLinkPath="#leaveempty"/> to TaskbarPinList
        Write-Output "<taskbar:DesktopApp DesktopApplicationLinkPath=`"#leaveempty`"/>"
    }
    elseif ($Applications) {
        $InstalledAppxPackages = Get-AppxPackage -AllUsers
        $AumidList = foreach ($app in $InstalledAppxPackages) {
            # Get the AppId from the manifest file
            try {
                $ManifestPath = Join-Path -Path $app.InstallLocation -ChildPath "AppxManifest.xml"
                $ManifestPathLeaf = Split-Path -Path $app.InstallLocation -Leaf
                if ($(Test-Path -Path $ManifestPath -ErrorAction SilentlyContinue)) {
                    [xml]$Manifest = Get-Content -Path $ManifestPath -ErrorAction Stop
                    $Name = $Manifest.Package.Identity.Name
                    $Publisher = @(
                        # Get the First and Last part the folder name from the manifest path
                        # From: Microsoft.Windows.Photos_2024.11070.15005.0_x64__8wekyb3d8bbwe
                        # To:   Microsoft.Windows.Photos_8wekyb3d8bbwe
                        "$ManifestPathLeaf" -split '_' | Select-Object -First 1
                        "$ManifestPathLeaf" -split '_' | Select-Object -Last 1
                    ) -join '_'
                    $Id = $Manifest.Package.Applications.Application.Id
                    if ($Publisher -and $Id -and $Publisher -like "*$Name*") {
                        $Id | ForEach-Object {
                            Write-Output "$($Publisher)!$($_)"
                        }
                    }
                }
            }
            catch {}
        }
        Write-Host "[Info] Found $($AumidList.Count) installed Microsoft Store apps."

        $SoftwareList = Get-StartApps | Select-Object -ExpandProperty AppId

        Write-Host "[Info] Total installed apps: $($AumidList.Count + $SoftwareList.Count)"

        # Check if we are pinning apps
        # Split the applications by comma
        $Applications -split ',' | ForEach-Object {
            $Application = $_.Trim()
            $FoundApp = $SoftwareList | Where-Object { $_ -like "*$Application*" } | Select-Object -First 1

            $FoundApp | ForEach-Object {
                Write-Host "[Info] Found AppId: $($_)"
            }

            if ($FoundApp -like "*!*") {
                # Add UWP App
                # UWP apps have ! in the AppId
                Write-Host "[Info] Adding UWP App: $($FoundApp)"
                Write-Output "<taskbar:UWA AppUserModelID=`"$($FoundApp)`" />"
                $PinnedApps.Add($Application)
            }
            elseif ($FoundApp -notlike "*!*" -and $Application -in $SoftwareList) {
                # Add Desktop App
                # Desktop apps don't have ! in the AppId
                Write-Host "[Info] Adding Desktop App: $($FoundApp)"
                Write-Output "<taskbar:DesktopApp DesktopApplicationID=`"$($FoundApp)`" />"
                $PinnedApps.Add($Application)
            }
            elseif ($FoundApp -notlike "*!*" -and $Application -notin $SoftwareList) {
                # Add Pinned Link Path

                # Save $Application in $Text for testing if the path exists
                $Text = $Application
                # Regex to find environment variables, eg %APPDATA%, %CommonProgramFiles(x86)%, etc.
                $re = [regex]::new('(%[a-zA-Z\(\)0-9_]+%)')
                if ($re.IsMatch($Text)) {
                    # Replace environment variables with their PowerShell equivalents and resolve the path, eg %SystemRoot% -> $env:SystemRoot -> C:\Windows
                    $re.Matches($Text) | ForEach-Object {
                        $Text = $Text -replace "$_", $(Get-Item -Path "env:$("$_" -replace '%', '')" -ErrorAction SilentlyContinue).Value
                    }
                }

                if (-not $(Test-Path -Path $Text -ErrorAction SilentlyContinue)) {
                    Write-Host "[Warn] File path does not exist for ($($Application)) and might fail to launch."
                }

                Write-Host "[Info] Adding Pinned Link Path: $($Application)"
                Write-Output "<taskbar:DesktopApp DesktopApplicationLinkPath=`"$($Application)`" />"
                $PinnedApps.Add($Application)
            }
            else {
                Write-Host "[Warn] AppId does not exist: $($Application)"
            }
        }
    }

    # Case-sensitive Replace
    $XmlTemplate = $XmlTemplate -creplace "LAYOUTXML", $DefaultLayout
    $XmlTemplate = $XmlTemplate -creplace "PINLISTXML", $PinListContent
    # Check if the layout contains UWP or Desktop Apps
    if ($($XmlTemplate -split [System.Environment]::NewLine | Where-Object { $_ -like "*<taskbar:UWA*" -or $_ -like "*<taskbar:DesktopApp*" }).Count -gt 0) {
        Write-Host "[Info] Successfully created layout."
    }
    else {
        Write-Host "[Error] Missing apps in layout."
        $HasError = $true
    }

    try {
        # Save XML to temp file
        Write-Host "[Info] Creating layout file at ($TempLayoutPath)."
        Set-Content -Path $TempLayoutPath -Value $XmlTemplate -Force -Confirm:$false -ErrorAction Stop
        Write-Host "[Info] Successfully saved layout file."
    }
    catch {
        Write-Host "[Error] Failed to create layout file."
        exit 1
    }

    if ($HasError) {
        exit 1
    }

    try {
        Import-StartLayout -LayoutPath $TempLayoutPath -MountPath "C:\" -Confirm:$false -ErrorAction Stop
        if ($Clear) {
            Write-Host "[Info] Successfully cleared pinned items from the taskbar."
        }
        else {
            Write-Host "[Info] Successfully pinned $($PinnedApps -join ', ') to the taskbar."
        }
    }
    catch {
        if ($_.Exception.Message -like "*is not a valid layout file*") {
            Write-Host ""
            Write-Host $_.Exception.Message
            Write-Host ""
            Write-Host "[Error] Failed to pin application to the taskbar."
            Write-Host ""
            Write-Host "[Info] Layout Content:"
            $XmlTemplate | Write-Host
        }
        Write-Host "[Error] Failed to pin application to the taskbar."
        $HasError = $true
    }

    # Clean up temp file
    try {
        Write-Host "[Info] Removing layout file at ($TempLayoutPath)."
        Remove-Item $TempLayoutPath -Force -ErrorAction SilentlyContinue
        Write-Host "[Info] Successfully removed layout file."
    }
    catch {
        Write-Host "[Error] Failed to remove layout file. Template file is located at ($TempLayoutPath)."
        $HasError = $true
    }

    if ($HasError) {
        exit 1
    }

    if ($Restart) {
        Write-Host "[Info] Restarting computer."
        Start-Sleep -Seconds 10
        Restart-Computer -Force -Confirm:$false -ErrorAction Stop
    }

    exit 0
}
end {
    
    
    
}
