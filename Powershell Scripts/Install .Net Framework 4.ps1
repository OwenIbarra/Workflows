# Install NetFx4 features(.NET 4.x), with the option to install from an offline source.
#Requires -Version 5.1

<#
.SYNOPSIS
    Install NetFx4 features(.NET 4.x), with the option to install from an offline source.
.DESCRIPTION
    Install NetFx4 features(.NET 4.x), with the option to install from an offline source.
    An offline source can be an attached CD/DVD image of the OS's installer.
.EXAMPLE
     No parameters needed.
    Install NetFx4 features from Local Install/Windows Update/WSUS.
.EXAMPLE
     -OfflineSource "D:\sources\sxs"
    Install NetFx4 features from a specified source.
.EXAMPLE
    PS C:\> Install-DotNet4.ps1
    Install NetFx4 features from Local Install/Windows Update/WSUS.
.EXAMPLE
    PS C:\> Install-DotNet4.ps1 -OfflineSource "D:\sources\sxs"
    Install NetFx4 features from a specified source.
.OUTPUTS
    None
.NOTES
    General notes
    Release Notes:
    Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $OfflineSource
)

begin {
    $OSVersion = [System.Environment]::OSVersion.Version
}
process {
    if ($OSVersion -gt [Version]::new(6, 2)) {
        # Windows 8.1/Server 2012 R2 or greater
        $Packages = dism /Online /Get-Features /Format:Table
        if ($OfflineSource) {
            # Install .NET 3 and 4
            if ((Test-Path -Path $OfflineSource -ErrorAction SilentlyContinue)) {
                if ($($Packages | Select-String -Pattern "NetFx4" | Select-Object -First 1) -like "Disabled") {
                    dism /Online /Enable-Feature /FeatureName:NetFx4 /All /Source:$OfflineSource
                }
            }
            else {
                Write-Error "Path to $OfflineSource doesn't exist."
            }
        }
        else {
            if ($($Packages | Select-String -Pattern "NetFx4" | Select-Object -First 1) -like "Disabled") {
                dism /Online /Enable-Feature /FeatureName:NetFx4 /All
            }
        }
    }
    else {
        # Windows 8/Server 2012 or lesser
        # This requires copying the installer to the target in some way; either by downloading or shared folder as examples.
        Write-Output "More Info: https://ninjarmm.zendesk.com/hc/en-us/articles/360043992771-How-to-install-software-outside-of-3rd-Party-Patching"
        Write-Error "Use the Install Application script to install dotNetFx40_Full_x86_x64.exe"

        # The code below is an example of downloading, but isn't guarantied to work 100%.

        # Invoke-WebRequest -Uri "http://download.microsoft.com/download/9/5/A/95A9616B-7A37-4AF6-BC36-D6EA96C8DAAE/dotNetFx40_Full_x86_x64.exe" -OutFile "dotNetFx40_Full_x86_x64.exe"
        # dotNetFx40_Full_x86_x64.exe /q: http://download.microsoft.com/download/9/5/A/95A9616B-7A37-4AF6-BC36-D6EA96C8DAAE/dotNetFx40_Full_x86_x64.exe
        # Remove-Item -Path "dotNetFx40_Full_x86_x64.exe"
    }
}
end {}
