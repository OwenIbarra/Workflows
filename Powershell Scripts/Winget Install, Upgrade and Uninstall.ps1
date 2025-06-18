# Install, Uninstall, or Upgrade a package using WinGet. Needs to be run as another user (preferably one with local admin permissions) and not as System. Please see this Ninja Dojo link. https://ninjarmm.zendesk.com/hc/en-us/articles/360016094532-Credential-Exchange
#Requires -Version 5.1

<#
.SYNOPSIS
    Install, Uninstall, or Upgrade a package using WinGet. Needs to be run as another user (preferably one with local admin permissions) and not as System. Please see this Ninja Dojo link. https://ninjarmm.zendesk.com/hc/en-us/articles/360016094532-Credential-Exchange
.DESCRIPTION
    Install, Uninstall, or Upgrade a package using WinGet. 
    Needs to be run as another user (preferably one with local admin permissions) and not as System.
    https://ninjarmm.zendesk.com/hc/en-us/articles/360016094532-Credential-Exchange
.LINK
    https://ninjarmm.zendesk.com/hc/en-us/articles/360016094532-Credential-Exchange
.EXAMPLE
    Preset Parameter: -WinGetArgs "Install vlc --accept-package-agreements --accept-source-agreements --silent --source winget"
    Runs WinGet directly and installs VLC. If InstallWinget checkbox was checked, then WinGet will be installed first before running the command.
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    https://learn.microsoft.com/en-us/windows/package-manager/winget/
    Release Notes: Updated dependencies, made dependencies install only if missing or outdated, removed dependency hashes.
#>

param(
    [Parameter()]
    [string[]]$WinGetArgs
)

begin {
    #Region Helper Functions
    function Update-EnvironmentVariables {
        foreach ($level in "Machine", "User") {
            [Environment]::GetEnvironmentVariables($level).GetEnumerator() | ForEach-Object {
                # For Path variables, append the new values, if they're not already in there
                if ($_.Name -match 'Path$') {
                    $_.Value = ($((Get-Content "Env:$($_.Name)") + ";$($_.Value)") -split ';' | Select-Object -Unique) -join ';'
                }
                $_
            } | Set-Content -Path { "Env:$($_.Name)" }
        }
    }

    Update-EnvironmentVariables

    $WinGetPath = "$env:localappdata\Microsoft\WindowsApps\winget.exe"
    Write-Host "Path to WinGet: $WinGetPath"

    function Get-LatestUrl($Url, $FileName) {
        $((Invoke-WebRequest $Url -UseBasicParsing | ConvertFrom-Json).assets | Where-Object { $_.name -match "^$FileName`$" }).browser_download_Url
    }

    function Get-LatestHash($Url, $FileName) {
        $shaUrl = $((Invoke-WebRequest $Url -UseBasicParsing | ConvertFrom-Json).assets | Where-Object { $_.name -match "^$FileName`$" }).browser_download_Url
        [System.Text.Encoding]::UTF8.GetString($(Invoke-WebRequest -Uri $shaUrl -UseBasicParsing).Content)
    }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }
    #EndRegion Helper Functions

    if (-not (Test-IsElevated)) {
        Write-Warning "Many apps require administrator privileges in order to install, uninstall, or upgrade. This action may fail however some apps like Zoom may work."
    }

    if ((Test-IsSystem)) {
        Write-Error -Message "WinGet will not run under a System account. Use a user account with Administrator privileges. https://ninjarmm.zendesk.com/hc/en-us/articles/360016094532-Credential-Exchange"
        exit 1
    }
}
process {
    try {
        $Version = & $WinGetPath "--version"
        Write-Host "WinGet $Version found."
    }
    catch {
        Write-Host "WinGet not installed."
        if ($env:installWingetIfNecessary -like "True") {
            Write-Host "Installing WinGet."

            $apiLatestUrl = 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol::Tls13 -bor [System.Net.SecurityProtocolType]::Tls12

            # Hide the progress bar of Invoke-WebRequest
            $oldProgressPreference = $ProgressPreference
            $ProgressPreference = 'Silent'
            $desktopAppInstaller = @{
                FileName = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
                Url      = $(Get-LatestUrl -Url $apiLatestUrl -FileName "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle")
                Hash     = $(Get-LatestHash -Url $apiLatestUrl -FileName "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.txt")
            }

            $Dependencies = New-Object System.Collections.Generic.List[Object]
            $DependencyPaths = New-Object System.Collections.Generic.List[String]

            # Downloads winget as a zip file and retrieves the required ui xaml version
            Invoke-WebRequest -Uri $desktopAppInstaller.Url -OutFile $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.zip
            if ((Get-FileHash -Path "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.zip").Hash -notlike $desktopAppInstaller.Hash) {
                Write-Host "$($desktopAppInstaller.FileName) Hash does not match!"
                Write-Host "Expected Hash: $($desktopAppInstaller.Hash)"
                Write-Host "Downloaded File Hash: $((Get-FileHash -Path "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.zip").Hash)"
                Remove-Item -Path "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.zip" -Force
                exit 1
            }

            # Prep downloaded file to retrieve the app manifest
            Expand-Archive -Path $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.zip -DestinationPath $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -Force
            Rename-Item -Path $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AppInstaller_x64.msix -NewName AppInstaller_x64.zip
            Expand-Archive -Path $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AppInstaller_x64.zip -DestinationPath $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AppInstaller_x64 -Force

            # Retrieve the app manifest and find winget's two dependenencies
            [xml]$AppManifest = Get-Content -Path $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\AppInstaller_x64\AppxManifest.xml
            $uiXaml = $AppManifest.Package.Dependencies.PackageDependency | Where-Object { $_.Name -like "*Microsoft.UI.Xaml*" } | Select-Object -ExpandProperty Name
            $uiXamlVersion = $AppManifest.Package.Dependencies.PackageDependency | Where-Object { $_.Name -like "*Microsoft.UI.Xaml*" } | Select-Object -ExpandProperty MinVersion
            $vcLibs = $AppManifest.Package.Dependencies.PackageDependency | Where-Object { $_.Name -like "*Microsoft.VCLibs*" } | Select-Object -ExpandProperty Name
            $vcLibsVersion = $AppManifest.Package.Dependencies.PackageDependency | Where-Object { $_.Name -like "*Microsoft.VCLibs*" } | Select-Object -ExpandProperty MinVersion

            # Renambe the zip file back to an msix bundle
            Rename-Item -Path $env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.zip -NewName "Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            Remove-Item -Path "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe" -Recurse -Force

            # If the Xaml dependency is not installed or out-dated update it.
            if (!(Get-AppxPackage -Name $uiXaml) -or (Get-AppxPackage -Name $uiXaml).Version -lt $uiXamlVersion) {
                $MinimumVersion = $($uiXaml.replace('Microsoft.UI.Xaml.', ''))

                $SearchResults = Invoke-WebRequest -Uri "https://azuresearch-usnc.nuget.org/query?q=Microsoft.UI.Xaml&take=1" -UseBasicParsing | ConvertFrom-Json
                $VersionToDownload = $SearchResults.data.versions.version | Where-Object { $_ -like "$MinimumVersion*" } | Select-Object -Last 1

                if (-not $VersionToDownload) {
                    Write-Host "[Error] could not find the proper version of Microsoft.UI.Xaml to download!"
                    exit 1
                }

                $uiLibsUwp = @{
                    FileName = "Microsoft.UI.Xaml.$VersionToDownload.zip"
                    Url      = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/$VersionToDownload"
                }
                $Dependencies.Add($uiLibsUwp)

                $InstallUiXaml = $True
            }

            # If the VCLibs dependency is not installed or out-dated update it.
            if (!(Get-AppxPackage -Name $vcLibs) -or (Get-AppxPackage -Name $vcLibs).Version -lt $vcLibsVersion) {
                $vcLibsUwp = @{
                    FileName = 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
                    Url      = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
                    # https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/cpp/libraries/c-runtime-packages-desktop-bridge
                }
                $Dependencies.Add($vcLibsUwp)
            }

            # Download dependencies
            foreach ($Dependency in $Dependencies) {
                $DependencyPaths.Add($Dependency.FileName)
                Invoke-WebRequest $Dependency.Url -OutFile $Dependency.FileName
                $Hash = $(Get-FileHash -Path $Dependency.FileName).Hash
                if ($Dependency.Hash -and $Hash -notlike $Dependency.Hash) {
                    Write-Host "$($Dependency.FileName) Hash does not match!"
                    Write-Host "Expected Hash: $($Dependency.Hash)"
                    Write-Host "Downloaded File Hash: $Hash"
                    Remove-Item -Path $Dependency.FileName -Force
                    exit 1
                }
            }

            if ($InstallUiXaml) {
                $Index = $DependencyPaths.IndexOf("Microsoft.UI.Xaml.$VersionToDownload.zip")

                # Extract Microsoft.UI.Xaml
                $uiLibsUwpWithOutExtension = $(($uiLibsUwp.FileName -split '\.' | Select-Object -SkipLast 1) -join '.')
                Expand-Archive -Path $uiLibsUwp.FileName -DestinationPath "$env:TEMP\$uiLibsUwpWithOutExtension" -Force

                $DependencyPaths[$Index] = (Get-Item -Path "$env:TEMP\$uiLibsUwpWithOutExtension\tools\AppX\x64\Release\Microsoft.UI.Xaml*.appx" | Select-Object -ExpandProperty FullName)
            }

            if ($Dependencies.Count -gt 0) {
                $DependencyPaths | ForEach-Object {
                    Add-AppxPackage -Path $_
                }
            }

            # Install WinGet
            Add-AppxPackage -Path "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

            # Cleanup downloaded files
            $DependencyPaths | ForEach-Object {
                Remove-Item -Path $_ -Force
            }

            Remove-Item -Path "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Force

            if($InstallUiXaml){
                Remove-Item -Recurse -Path "$env:TEMP\$uiLibsUwpWithOutExtension" -Force
            }

            Write-Host "WinGet installed!"

            Invoke-WebRequest -Uri "https://cdn.winget.microsoft.com/cache/source.msix" -OutFile "Microsoft.Winget.Source.msix" -UseBasicParsing
            Add-AppxPackage -Path "Microsoft.Winget.Source.msix"
            Remove-Item -Path "Microsoft.Winget.Source.msix"

            $ProgressPreference = $oldProgressPreference

            Update-EnvironmentVariables

            $ProgressPreference = 'Continue'
        }
        else {
            Write-Host "WinGet is required to be installed."
            exit 1
        }
    }
    
    if (-not $PSBoundParameters.ContainsKey("WinGetArgs")) {

        if ($env:useNameFlag -like "true" -and $env:packageNameOrQuery -like "null") {
            Write-Error "Missing package name!"
            exit 1
        }

        if ($env:action -like "Install") {
            $WinGetArgs += "install"
        }
        elseif ($env:action -like "Uninstall") {
            $WinGetArgs += "uninstall"
        }
        elseif ($env:action -like "Upgrade") {
            $WinGetArgs += "upgrade"
        }
        elseif ($env:action -and $env:action -notlike "null") {
            Write-Error "You must specify an action to take (Install, Uninstall or Upgrade)."
            exit 1
        }

        if ($env:packageId -and $env:packageId -notlike "null") {
            $WinGetArgs += "--id", $env:packageId
        }

        if ($env:scope -and $env:scope -notlike "null") {
            $WinGetArgs += "--scope", $env:scope
        }

        if ($env:locale -and $env:locale -notlike "null") {
            $WinGetArgs += "--locale", $env:locale
        }

        if ($env:acceptPackageAgreements -like "True" -and $env:action -notlike "uninstall") {
            $WinGetArgs += "--accept-package-agreements"
        }

        if ($env:acceptSourceAgreements -like "True") {
            $WinGetArgs += "--accept-source-agreements"
        }

        if ($env:silent -like "True") {
            $WinGetArgs += "--silent"
        }

        $WinGetArgs += "--source", "winget"

    }

    # Validate arguments to avoid hanging on user input when uninstalling a package
    if ($env:action -like "Uninstall" -and $env:acceptSourceAgreements -notlike "True") {
        Write-Host "Accept Source Agreements is required to continue."
        exit 1
    }

    # Validate arguments to avoid hanging on user input when installing or upgrading a package
    if (
        $(
            $env:action -like "Install" -or
            $env:action -like "Upgrade"
        ) -and $env:acceptPackageAgreements -like "false" -and $env:acceptSourceAgreements -like "false"
    ) {
        Write-Host "Accept Package and Source Agreements is required to continue."
        exit 1
    }

    # Run WinGet
    $winget = Start-Process $WinGetPath -ArgumentList $WinGetArgs -Wait -PassThru -NoNewWindow

    if ($winget.ExitCode -eq -1978335217) {

        # Sources need to be reset and updated
        Write-Host "Attempting to reset source."
        $resetSource = Start-Process $WinGetPath -ArgumentList "source", "reset", "--force" -Wait -PassThru -NoNewWindow
        Start-Sleep 1

        Write-Host "Attempting to update sources."
        $updateSource = Start-Process $WinGetPath -ArgumentList "source", "update" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\ninjaone-rmm-updatesource-output.txt"
        Start-Sleep 1

        if ($updateSource.ExitCode -lt 0 -or ((Get-Content "$env:TEMP\ninjaone-rmm-updatesource-output.txt") -contains "Cancelled")) {
            # Update sources once more if exit code is not 0
            Write-Host "Attempting to update sources by adding the Microsoft.WinGet.Source package."

            try {
                Invoke-WebRequest -Uri "https://cdn.winget.microsoft.com/cache/source.msix" -OutFile "Microsoft.Winget.Source.msix" -UseBasicParsing -ErrorAction Stop
                Add-AppxPackage -Path "Microsoft.Winget.Source.msix" -ErrorAction Stop
                Remove-Item "Microsoft.Winget.Source.msix" -Force
            }
            catch {
                Write-Host "Error updating sources. Try running ""winget source update"" in the console or use the Parameter -WinGetArgs with ""source update"" alone to fix this error."
                Write-Host "Exit Code: $($updateSource.ExitCode)"
                exit $updateSource.ExitCode
            }
            Write-Host "Successfully added winget source"
        }
        Write-Host "Running WinGet with original arguments once more."
        $winget = Start-Process $WinGetPath -ArgumentList $WinGetArgs -Wait -PassThru -NoNewWindow
        Start-Sleep 1
    }
    Write-Host "Exit Code: $($winget.ExitCode)"
    exit $winget.ExitCode

}
end {
    
    
    
}

