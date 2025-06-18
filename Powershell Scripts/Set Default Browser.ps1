# Sets the default browser for all users.
#Requires -Version 5.1

<#
.SYNOPSIS
    Sets the default browser for all users.
.DESCRIPTION
    Sets the default browser for all users.
.EXAMPLE
    -Browser "Mozilla Firefox" -RestartExplorer

    Checking that 'Firefox' is currently installed.

    Setting default browser of Mozilla Firefox for Administrator.
    Setting 
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice\Hash changed from 8Ou3SgSdFO8= to k4ZWXiyK+z8=
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice\ProgId changed from ChromeHTML to FirefoxURL-308046B0AF4A39CB
    Setting 
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice\Hash changed from xQYQ9/Fwp10= to xnrMnenk37Q=
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice\ProgId changed from ChromeHTML to FirefoxURL-308046B0AF4A39CB
    Setting 
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\UserChoice\Hash changed from PcR2R2hoCGM= to OUwc/aGCLhc=
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.htm\UserChoice\ProgId changed from ChromeHTML to FirefoxHTML-308046B0AF4A39CB
    Setting 
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice\Hash changed from Xh2ArpvfGmY= to c2IJZAbQyQU=
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice\ProgId changed from ChromeHTML to FirefoxHTML-308046B0AF4A39CB
    Setting 
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xhtml\UserChoice\Hash changed from xxvsmb7hJWw= to zBOrxnkCxCw=
    Registry::HKEY_USERS\S-1-5-21-2075707993-3158328168-3942738527-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xhtml\UserChoice\ProgId changed from ChromeHTML to FirefoxHTML-308046B0AF4A39CB

    Restarting Explorer.exe as requested.

PARAMETER: -Action "Set Default Browser"
    Specify whether you would like to set the default browser, or disable or enable the block on the protected protocols and extensions used by browsers.
    Valid actions are 'Set Default Browser', 'Disable User Choice Protection Driver' or 'Enable User Choice Protection Driver'.
    https://blogs.windows.com/windows-insider/2023/11/16/previewing-changes-in-windows-to-comply-with-the-digital-markets-act-in-the-european-economic-area/

PARAMETER: -Browser "Mozilla Firefox"
    Set the default browser to either "Mozilla Firefox", "Google Chrome" or "Microsoft Edge".

PARAMETER: -RestartExplorer
    Restarts Explorer.exe so that the desktop icons for .html files refresh immediately.

PARAMETER: -ForceRestartComputer
    Restarts the computer so that the user protection driver changes can take effect immediately.
    
LICENSE:
    Modified version from: https://github.com/DanysysTeam/PS-SFTA/blob/22a32292e576afc976a1167d92b50741ef523066/SFTA.ps1
    This script incorporates the `Get-HexDateTime` and `Get-Hash` functions from Danysys, without which it would not be possible.
    
    LICENSE: https://github.com/DanysysTeam/PS-SFTA/blob/22a32292e576afc976a1167d92b50741ef523066/SFTA.ps1
    MIT License
    
    Copyright (c) 2022 Danysys. <danysys.com>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
.NOTES
    Minimum OS Architecture Supported: Windows 10+
    Release Notes: Added option to disable user protection driver
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action,
    [Parameter()]
    [String]$Browser,
    [Parameter()]
    [Switch]$RestartExplorer = [System.Convert]::ToBoolean($env:restartExplorer),
    [Parameter()]
    [Switch]$ForceRestartComputer = [System.Convert]::ToBoolean($env:forceRestartComputer)
)

begin {
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }
    if ($env:browser -and $env:browser -notlike "null") { $Browser = $env:browser }

    # Trim any leading or trailing whitespace from $Action if it is set
    if ($Action) {
        $Action = $Action.Trim()
    }

    # If no action was specified, display an error message and exit with code 1
    if (!$Action) {
        Write-Host -Object "[Error] No action was specified. Please specify either 'Set Default Browser', 'Disable User Choice Protection Driver' or 'Enable User Choice Protection Driver'."
        exit 1
    }

    # Define valid actions
    $ValidActions = "Set Default Browser", "Disable User Choice Protection Driver", "Enable User Choice Protection Driver"
    # If the action is invalid, display an error message and exit with code 1
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] An invalid action of '$Action' was given. Please give a valid action such as 'Set Default Browser', 'Disable User Choice Protection Driver' or 'Enable User Choice Protection Driver'."
        exit 1
    }

    # Trim any leading or trailing whitespace from $Browser if it is set
    if ($Browser) {
        $Browser = $Browser.Trim()
    }

    if ($Browser -and ($Action -eq "Disable User Choice Protection Driver" -or $Action -eq "Enable User Choice Protection Driver")) {
        Write-Host -Object "[Error] Cannot set default browser and '$Action' at the same time."
        exit 1
    }

    # If no browser is selected, terminate with an error message.
    if (!$Browser -and $Action -eq "Set Default Browser") {
        Write-Host "[Error] Please select at least one browser!"
        exit 1
    }

    if ($Browser) {
        # Handlers for each product
        switch ($Browser) {
            "Google Chrome" {
                $DisplayName = "Chrome"
                $urlID = "ChromeHTML"
                $htmlID = "ChromeHTML"
            }
            "Microsoft Edge" {
                $DisplayName = "Edge"
                $urlID = "MSEdgeHTM"
                $htmlID = "MSEdgeHTM"
            }
            "Mozilla Firefox" {
                $DisplayName = "Firefox"
                $urlID = "FirefoxURL-308046B0AF4A39CB"
                $htmlID = "FirefoxHTML-308046B0AF4A39CB"
            }
            default {
                Write-Host "[Error] An invalid browser of '$Browser' was given. Only the following browsers can be made the default. 'Google Chrome','Microsoft Edge' or 'Mozilla Firefox'."
                exit 1
            }
        }
    }

    # Get the status of the User Choice Protection Driver service and scheduled task
    $UserProtectionService = Get-Service -Name "UCPD" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    $UserProtectionTask = Get-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }

    # Check if the User Protection service or task is running
    if ($Action -eq "Set Default Browser" -and ($UserProtectionService -or $UserProtectionTask)) {
        Write-Host -Object "[Warning] The browser default may be protected by the 'User Choice Protection Driver'. You may need to select the 'Disable User Choice Protection Driver' to successfully complete this change."
    }

    # Test if running as Administrator
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Test if running as System
    function Test-IsSystem {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
    }

    function Get-HexDateTime {
        # This function was created by DanySys at https://github.com/DanysysTeam/PS-SFTA
        [OutputType([string])]
    
        $now = [DateTime]::Now
        $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
        $fileTime = $dateTime.ToFileTime()
        $hi = ($fileTime -shr 32)
        $low = ($fileTime -band 0xFFFFFFFFL)
        ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
    }

    function Get-Hash {
        # This function was created by DanySys at https://github.com/DanysysTeam/PS-SFTA
        [CmdletBinding()]
        param (
            [Parameter( Position = 0, Mandatory = $True )]
            [string]
            $BaseInfo
        )
    
        function local:Get-ShiftRight {
            [CmdletBinding()]
            param (
                [Parameter( Position = 0, Mandatory = $true)]
                [long] $iValue, 
                
                [Parameter( Position = 1, Mandatory = $true)]
                [int] $iCount 
            )
        
            if ($iValue -band 0x80000000) {
                Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
            }
            else {
                Write-Output ($iValue -shr $iCount)
            }
        }
    
        function local:Get-Long {
            [CmdletBinding()]
            param (
                [Parameter( Position = 0, Mandatory = $true)]
                [byte[]] $Bytes,
        
                [Parameter( Position = 1)]
                [int] $Index = 0
            )
        
            Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
        }
    
        function local:Convert-Int32 {
            param (
                [Parameter( Position = 0, Mandatory = $true)]
                [long] $Value
            )
        
            [byte[]] $bytes = [BitConverter]::GetBytes($Value)
            return [BitConverter]::ToInt32( $bytes, 0) 
        }
    
        [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
        $bytesBaseInfo += 0x00, 0x00  
        
        $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
        
        $lengthBase = ($baseInfo.Length * 2) + 2 
        $length = (($lengthBase -band 4) -le 1) + (Get-ShiftRight $lengthBase 2) - 1
        $base64Hash = ""
    
        if ($length -gt 1) {
        
            $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
                R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
            }
        
            $map.CACHE = 0
            $map.OUTHASH1 = 0
            $map.PDATA = 0
            $map.MD51 = (((Get-Long $bytesMD5) -bor 1) + 0x69FB0000L)
            $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1) + 0x13DB0000L
            $map.INDEX = Get-ShiftRight ($length - 2) 1
            $map.COUNTER = $map.INDEX + 1
        
            while ($map.COUNTER) {
                $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + [long]$map.OUTHASH1)
                $map.R1[0] = Convert-Int32 (Get-Long $bytesBaseInfo ($map.PDATA + 4))
                $map.PDATA = $map.PDATA + 8
                $map.R2[0] = Convert-Int32 (($map.R0 * ([long]$map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $map.R0 16))))
                $map.R2[1] = Convert-Int32 ((0x79F8A395L * ([long]$map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $map.R2[0] 16)))
                $map.R3 = Convert-Int32 ((0xEA970001L * $map.R2[1]) - (0x3C101569L * (Get-ShiftRight $map.R2[1] 16) ))
                $map.R4[0] = Convert-Int32 ($map.R3 + $map.R1[0])
                $map.R5[0] = Convert-Int32 ($map.CACHE + $map.R3)
                $map.R6[0] = Convert-Int32 (($map.R4[0] * [long]$map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $map.R4[0] 16)))
                $map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $map.R6[0] 16)))
                $map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $map.R6[1] 16)))
                $map.OUTHASH2 = Convert-Int32 ([long]$map.R5[0] + [long]$map.OUTHASH1)
                $map.CACHE = ([long]$map.OUTHASH2)
                $map.COUNTER = $map.COUNTER - 1
            }
    
            [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            [byte[]] $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
            $buffer.CopyTo($outHash, 0)
            $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
            $buffer.CopyTo($outHash, 4)
        
            $map = @{PDATA = 0; CACHE = 0; COUNTER = 0 ; INDEX = 0; MD51 = 0; MD52 = 0; OUTHASH1 = 0; OUTHASH2 = 0;
                R0 = 0; R1 = @(0, 0); R2 = @(0, 0); R3 = 0; R4 = @(0, 0); R5 = @(0, 0); R6 = @(0, 0); R7 = @(0, 0)
            }
        
            $map.CACHE = 0
            $map.OUTHASH1 = 0
            $map.PDATA = 0
            $map.MD51 = ((Get-Long $bytesMD5) -bor 1)
            $map.MD52 = ((Get-Long $bytesMD5 4) -bor 1)
            $map.INDEX = Get-ShiftRight ($length - 2) 1
            $map.COUNTER = $map.INDEX + 1
    
            while ($map.COUNTER) {
                $map.R0 = Convert-Int32 ((Get-Long $bytesBaseInfo $map.PDATA) + ([long]$map.OUTHASH1))
                $map.PDATA = $map.PDATA + 8
                $map.R1[0] = Convert-Int32 ($map.R0 * [long]$map.MD51)
                $map.R1[1] = Convert-Int32 ((0xB1110000L * $map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $map.R1[0] 16)))
                $map.R2[0] = Convert-Int32 ((0x5B9F0000L * $map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $map.R1[1] 16)))
                $map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $map.R2[0] 16)) - (0x46930000L * $map.R2[0]))
                $map.R3 = Convert-Int32 ((0x1D830000L * $map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $map.R2[1] 16)))
                $map.R4[0] = Convert-Int32 ([long]$map.MD52 * ([long]$map.R3 + (Get-Long $bytesBaseInfo ($map.PDATA - 4))))
                $map.R4[1] = Convert-Int32 ((0x16F50000L * $map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $map.R4[0] 16)))
                $map.R5[0] = Convert-Int32 ((0x96FF0000L * $map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $map.R4[1] 16)))
                $map.R5[1] = Convert-Int32 ((0x2B890000L * $map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $map.R5[0] 16)))
                $map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($map.R5[1]) 16)))
                $map.OUTHASH2 = Convert-Int32 ([long]$map.OUTHASH1 + $map.CACHE + $map.R3) 
                $map.CACHE = ([long]$map.OUTHASH2)
                $map.COUNTER = $map.COUNTER - 1
            }
        
            $buffer = [BitConverter]::GetBytes($map.OUTHASH1)
            $buffer.CopyTo($outHash, 8)
            $buffer = [BitConverter]::GetBytes($map.OUTHASH2)
            $buffer.CopyTo($outHash, 12)
        
            [Byte[]] $outHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            $hashValue1 = ((Get-Long $outHash 8) -bxor (Get-Long $outHash))
            $hashValue2 = ((Get-Long $outHash 12) -bxor (Get-Long $outHash 4))
        
            $buffer = [BitConverter]::GetBytes($hashValue1)
            $buffer.CopyTo($outHashBase, 0)
            $buffer = [BitConverter]::GetBytes($hashValue2)
            $buffer.CopyTo($outHashBase, 4)
            $base64Hash = [Convert]::ToBase64String($outHashBase) 
        }
    
        $base64Hash
    }

    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
        if (-not (Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            try {
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "[Error] Unable to create the registry path $Path for $Name. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            Write-Host "Set $Path\$Name to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    # Retrieves all accounts on a system.
    function Get-UserHives {
        param (
            [Parameter()]
            [ValidateSet('AzureAD', 'DomainAndLocal', 'All')]
            [String]$Type = "All",
            [Parameter()]
            [String[]]$ExcludedUsers,
            [Parameter()]
            [switch]$IncludeDefault
        )
    
        # User account SID's follow a particular patter depending on if they're azure AD or a Domain account or a local "workgroup" account.
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # We'll need the NTuser.dat file to load each users registry hive. So we grab it if their account sid matches the above pattern. 
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
                Where-Object { $_.PSChildName -match $Pattern } | 
                Select-Object @{Name = "SID"; Expression = { $_.PSChildName } },
                @{Name = "UserName"; Expression = { "$($_.ProfileImagePath | Split-Path -Leaf)" } }, 
                @{Name = "UserHive"; Expression = { "$($_.ProfileImagePath)\NTuser.dat" } }, 
                @{Name = "Path"; Expression = { $_.ProfileImagePath } }
        }
    
        # There are some situations where grabbing the .Default user's info is needed.
        switch ($IncludeDefault) {
            $True {
                $DefaultProfile = "" | Select-Object UserName, SID, UserHive, Path
                $DefaultProfile.UserName = "Default"
                $DefaultProfile.SID = "DefaultProfile"
                $DefaultProfile.Userhive = "$env:SystemDrive\Users\Default\NTUSER.DAT"
                $DefaultProfile.Path = "C:\Users\Default"
    
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.UserName }
            }
        }
    
        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
    }

    # Function to find installation keys based on the display name, optionally returning uninstall strings
    function Find-InstallKey {
        [CmdletBinding()]
        param (
            [Parameter(ValueFromPipeline = $True)]
            [String]$DisplayName,
            [Parameter()]
            [Switch]$UninstallString,
            [Parameter()]
            [String]$UserBaseKey
        )
        process {
            # Initialize an empty list to hold installation objects
            $InstallList = New-Object System.Collections.Generic.List[Object]

            # If no user base key is specified, search in the default system-wide uninstall paths
            if (!$UserBaseKey) {
                # Search for programs in 32-bit and 64-bit locations. Then add them to the list if they match the display name
                $Result = Get-ChildItem -Path "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }

                $Result = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
            else {
                # If a user base key is specified, search in the user-specified 64-bit and 32-bit paths.
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
    
                $Result = Get-ChildItem -Path "$UserBaseKey\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }
            }
    
            # If the UninstallString switch is specified, return only the uninstall strings; otherwise, return the full installation objects.
            if ($UninstallString) {
                $InstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $InstallList
            }
        }
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    if (!(Test-IsElevated)) {
        Write-Host "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Check if the action is to disable the User Choice Protection Driver
    if ($Action -eq "Disable User Choice Protection Driver") {
        Write-Host -Object "Disabling the User Choice Protection Driver service."

        # Check if the registry path for the User Choice Protection Driver service exists
        if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UCPD" -ErrorAction SilentlyContinue) {
            Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UCPD" -Name "Start" -Value 4
        }
        else {
            Write-Host -Object "[Error] The User Choice Protection Driver service does not exist."
            $ExitCode = 1
        }

        Write-Host -Object "Disabling the User Choice Protection scheduled task."

        # Get the scheduled task for the User Choice Protection Driver
        $ScheduledTask = Get-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction SilentlyContinue
        if ($ScheduledTask) {
            try {
                # Disable the scheduled task
                $ScheduledTask | Disable-ScheduledTask -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to disable User Choice Protection scheduled task at '\Microsoft\Windows\AppxDeploymentClient\UCPD velocity'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
        else {
            Write-Host -Object "[Error] The 'UCPD velocity' scheduled task was not found."
            $ExitCode = 1
        }

        # Restart explorer if requested
        if ($RestartExplorer -and $ExitCode -eq 0) {
            Write-Host "`nRestarting Explorer.exe as requested."

            # Stop all instances of Explorer
            Get-Process explorer | Stop-Process -Force
        
            Start-Sleep -Seconds 1

            # Restart Explorer if not running as System and Explorer is not already running
            if (!(Test-IsSystem) -and !(Get-Process -Name "explorer")) {
                Start-Process explorer.exe
            }
        }

        # Restart computer if requested
        if ($ForceRestartComputer -and $ExitCode -eq 0) {
            Write-Host "`nScheduling forced restart for $((Get-Date).AddSeconds(60))."

            # Restart Computer
            Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
        }
        elseif ($ExitCode -eq 0) {
            Write-Host -Object "`n[Warning] In order for the User Protection Driver updates to take immediate effect, you may need to restart the computer."
        }

        exit $ExitCode
    }

    # Check if the action is to enable the User Choice Protection Driver
    if ($Action -eq "Enable User Choice Protection Driver") {
        Write-Host -Object "Enabling the User Choice Protection Driver service."

        # Check if the registry path for the User Choice Protection Driver service exists
        if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UCPD" -ErrorAction SilentlyContinue) {
            Set-RegKey -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UCPD" -Name "Start" -Value 1
        }
        else {
            Write-Host -Object "[Error] The User Choice Protection Driver service does not exist."
            $ExitCode = 1
        }

        Write-Host -Object "Enabling the User Choice Protection scheduled task."

        # Get the scheduled task for the User Choice Protection Driver
        $ScheduledTask = Get-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction SilentlyContinue
        if ($ScheduledTask) {
            try {
                # Enable the scheduled task
                $ScheduledTask | Enable-ScheduledTask -ErrorAction Stop
            }
            catch {
                Write-Host -Object "[Error] Failed to enable User Choice Protection scheduled task at '\Microsoft\Windows\AppxDeploymentClient\UCPD velocity'."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
        else {
            Write-Host -Object "[Error] The 'UCPD velocity' scheduled task was not found."
            $ExitCode = 1
        }

        # Restart explorer if requested
        if ($RestartExplorer -and $ExitCode -eq 0) {
            Write-Host "`nRestarting Explorer.exe as requested."

            # Stop all instances of Explorer
            Get-Process explorer | Stop-Process -Force
        
            Start-Sleep -Seconds 1

            # Restart Explorer if not running as System and Explorer is not already running
            if (!(Test-IsSystem) -and !(Get-Process -Name "explorer")) {
                Start-Process explorer.exe
            }
        }

        # Restart computer if requested
        if ($ForceRestartComputer -and $ExitCode -eq 0) {
            Write-Host "`nScheduling forced restart for $((Get-Date).AddSeconds(60))."

            # Restart Computer
            Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
        }
        elseif ($ExitCode -eq 0) {
            Write-Host -Object "`n[Warning] In order for the User Protection Driver updates to take immediate effect, you may need to restart the computer."
        }

        exit $ExitCode
    }

    # Protocols and file associations to set
    $Protocols = "http", "https"
    $Files = "htm", "html", "xhtml"

    Write-Host -Object "Checking that '$DisplayName' is currently installed."
    # Check if the application is installed
    $ProgramIsInstalled = Find-InstallKey -DisplayName "$DisplayName"

    # Get all user profiles on the machine
    $UserProfiles = Get-UserHives -Type "All"
    $ProfileWasLoaded = New-Object System.Collections.Generic.List[object]

    # Loop through each profile on the machine
    ForEach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        If (!(Test-Path -Path Registry::HKEY_USERS\$($UserProfile.SID) -ErrorAction SilentlyContinue)) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            $ProfileWasLoaded.Add($UserProfile)
        }

        # Check if the application is installed for this user profile
        if (!$ProgramIsInstalled) {
            $ProgramIsInstalled = Find-InstallKey -DisplayName "$DisplayName" -UserBaseKey "Registry::HKEY_USERS\$($UserProfile.SID)"
        }
    }

    # If user profiles were loaded and the application is not installed, unload the profiles
    if ($ProfileWasLoaded.Count -gt 0 -and !$ProgramIsInstalled) {
        ForEach ($UserProfile in $ProfileWasLoaded) {
            # Unload NTuser.dat
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Check if the program is installed
    if (!$ProgramIsInstalled) {
        Write-Host "[Error] '$Browser' is not installed. Please install the browser prior to running this script."
        exit 1
    }

    ForEach ($UserProfile in $UserProfiles) {
        # The hex date and user experience don't really change
        $userExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
        $hexDateTime = Get-HexDateTime

        Write-Host "`nSetting default browser of $Browser for $($UserProfile.UserName)."

        # Set protocol association registry keys
        $Protocols | ForEach-Object {
            Write-Host "Setting "
            $Protocol = $_

            $ToBeHashed = "$Protocol$($UserProfile.SID)$urlID$hexDateTime$userExperience".ToLower()
            $Hash = Get-Hash -BaseInfo $ToBeHashed

            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice" -Name "Hash" -Value $Hash -PropertyType String
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice" -Name "ProgId" -Value $urlID -PropertyType String
        }

        # Set file association registry keys
        $Files | ForEach-Object {
            Write-Host "Setting "
            $File = $_

            $ToBeHashed = ".$File$($UserProfile.SID)$htmlID$hexDateTime$userExperience".ToLower()
            $Hash = Get-Hash -BaseInfo $ToBeHashed

            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.$File\UserChoice" -Name "Hash" -Value $Hash -PropertyType String
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.$File\UserChoice" -Name "ProgId" -Value $htmlID -PropertyType String
        }
    }

    # Unload the profiles if they were loaded during the script execution
    if ($ProfileWasLoaded.Count -gt 0) {
        ForEach ($UserProfile in $ProfileWasLoaded) {
            # Unload NTuser.dat
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Restart explorer if requested
    if ($RestartExplorer) {
        Write-Host "`nRestarting Explorer.exe as requested."

        # Stop all instances of Explorer
        Get-Process explorer | Stop-Process -Force
        
        Start-Sleep -Seconds 1

        # Restart Explorer if not running as System and Explorer is not already running
        if (!(Test-IsSystem) -and !(Get-Process -Name "explorer")) {
            Start-Process explorer.exe
        }
    }

    # Restart computer if requested
    if ($ForceRestartComputer -and $ExitCode -eq 0) {
        Write-Host "`nScheduling forced restart for $((Get-Date).AddSeconds(60))."

        # Restart Computer
        Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
    }

    exit $ExitCode
}
end {
    
    
    
}
