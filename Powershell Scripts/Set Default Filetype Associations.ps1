# Set the default application a given file extension should be opened with for all users.
#Requires -Version 5.1

<#
.SYNOPSIS
    Set the default application a given file extension should be opened with for all users.
.DESCRIPTION
    Set the default application a given file extension should be opened with for all users.
.EXAMPLE
    -Action "Set File Association" -ApplicationName "Notepad" -Extensions ".txt, .csv" -ProgId "AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn"

    Checking that 'Notepad' is installed.
    Found 'Notepad'.

    Setting association of '.csv' to 'AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn' for Administrator.
    Registry::HKEY_USERS\S-1-5-21-310806365-1327645792-1560496493-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.csv\UserChoice\Hash changed from 9lk186jZ4QQ= to MPJbUZcy3qc=
    Registry::HKEY_USERS\S-1-5-21-310806365-1327645792-1560496493-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.csv\UserChoice\ProgId changed from AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn to AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn
    Association set.

    Setting association of '.txt' to 'AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn' for Administrator.
    Registry::HKEY_USERS\S-1-5-21-310806365-1327645792-1560496493-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice\Hash changed from y+/OgocyOH8= to es3/U8QFd80=
    Registry::HKEY_USERS\S-1-5-21-310806365-1327645792-1560496493-500\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice\ProgId changed from AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn to AppXkv2jqn1pq8ajm0p5dhgqde7aafykkrrn
    Association set.
    
    [Warning] In order for the thumbnails to update immediately, you may need to restart Explorer.

PARAMETER: -Action "Set File Association"
    Specify whether you would like to set the default application for a given extension, or disable or enable the block on the '.html', '.htm', or '.pdf' extensions.
    Valid actions are 'Set File Association', 'Disable User Choice Protection Driver' or 'Enable User Choice Protection Driver'.
    https://blogs.windows.com/windows-insider/2023/11/16/previewing-changes-in-windows-to-comply-with-the-digital-markets-act-in-the-european-economic-area/

PARAMETER: -ApplicationName "ReplaceMeWithTheNameOfAnApplication"
    Specify the application you are setting as the default for your given file extension(s).

PARAMETER: -Extensions ".ai, .csv, .txt"
    Provide a comma-separated list of file extensions to set the default association for.

PARAMETER: -ProgId "ChromeHTML"
    Enter the programmatic identifier for your given application. You can usually find this in HKEY_CLASSES_ROOT.
    https://learn.microsoft.com/en-us/windows/win32/shell/fa-progids

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
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Action = "Set File Association",
    [Parameter()]
    [String]$ApplicationName,
    [Parameter()]
    [String]$Extensions,
    [Parameter()]
    [String]$ProgID,
    [Parameter()]
    [Switch]$RestartExplorer = [System.Convert]::ToBoolean($env:restartExplorer),
    [Parameter()]
    [Switch]$ForceRestartComputer = [System.Convert]::ToBoolean($env:forceRestartComputer)
)

begin {
    # If script form variables are used, replace the command line parameters with the form variables.
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }
    if ($env:applicationName -and $env:applicationName -notlike "null") { $ApplicationName = $env:applicationName }
    if ($env:fileExtensions -and $env:fileExtensions -notlike "null") { $Extensions = $env:fileExtensions }
    if ($env:programId -and $env:programId -notlike "null") { $ProgID = $env:programId }

    # Trim any leading or trailing whitespace from $Action if it is set
    if ($Action) {
        $Action = $Action.Trim()
    }

    # If no action was specified, display an error message and exit with code 1
    if (!$Action) {
        Write-Host -Object "[Error] No action was specified. Please specify either 'Set File Association', 'Disable User Choice Protection Driver' or 'Enable User Choice Protection Driver'."
        exit 1
    }

    # Define valid actions
    $ValidActions = "Set File Association", "Disable User Choice Protection Driver", "Enable User Choice Protection Driver"
    # If the action is invalid, display an error message and exit with code 1
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] An invalid action of '$Action' was given. Please give a valid action such as 'Set File Association', 'Disable User Choice Protection Driver' or 'Enable User Choice Protection Driver'."
        exit 1
    }

    # Trim any leading or trailing whitespace from $ApplicationName if it is set
    if ($ApplicationName) {
        $ApplicationName = $ApplicationName.Trim()
    }

    if($Action -eq "Disable User Choice Protection Driver" -or $Action -eq "Enable User Choice Protection Driver" -and $ApplicationName){
        Write-Host -Object "[Error] Cannot add an association and '$Action' at the same time."
        exit 1
    }

    # If invalid characters are found in $ApplicationName, display an error message and exit with code 1
    if ($ApplicationName -match '[\\/:*?"<>\|]') {
        Write-Host -Object "[Error] The application name '$ApplicationName' contains one of the following invalid characters: '\/:*?`"<>|'"
        exit 1
    }

    # Check if $ApplicationName is not set and the action is not related to the User Choice Protection Driver
    if (!$ApplicationName -and $Action -ne "Disable User Choice Protection Driver" -and $Action -ne "Enable User Choice Protection Driver") {
        Write-Host -Object "[Error] An application name was not given. The application name as shown in Ninja is required."
        exit 1
    }

    # Create a list to store valid extensions
    $ExtensionList = New-Object System.Collections.Generic.List[string]
    # Define extensions protected by the User Choice Protection Driver
    $ProtectedExtensions = ".html", ".htm", ".pdf"

    # Get the status of the User Choice Protection Driver service and scheduled task
    $UserProtectionService = Get-Service -Name "UCPD" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    $UserProtectionTask = Get-ScheduledTask -TaskName "UCPD velocity" -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }

    if($Action -eq "Disable User Choice Protection Driver" -or $Action -eq "Enable User Choice Protection Driver" -and $Extensions){
        Write-Host -Object "[Error] Cannot add an association and '$Action' at the same time."
        exit 1
    }

    # If extensions are provided and the action is not related to User Choice Protection Driver
    if ($Extensions -and $Action -ne "Disable User Choice Protection Driver" -and $Action -ne "Enable User Choice Protection Driver") {
        # Split the extensions string by the comma character and process each extension
        $Extensions -split ',' | ForEach-Object {
            $ExtensionToAdd = $_.Trim()
            if (!$ExtensionToAdd) {
                return
            }

            # Add a dot to the extension if it doesn't start with one
            if ($ExtensionToAdd -notmatch '^\.') {
                $ExtensionToAdd = ".$ExtensionToAdd"
                Write-Host -Object "[Warning] Added a '.' to the extension. New extension '$ExtensionToAdd'."
            }

            # Check if the extension contains any invalid characters
            if ($ExtensionToAdd -match '[\\/:*?"<>\|]') {
                Write-Host -Object "[Error] The extension '$ExtensionToAdd' contains one of the following invalid characters: '\/:*?`"<>|'"
                $ExitCode = 1
                return
            }

            # Check if the extension is not found in the registry
            if (!(Test-Path -Path "Registry::HKEY_CLASSES_ROOT\$ExtensionToAdd" -ErrorAction SilentlyContinue)) {
                Write-Host -Object "[Error] '$ExtensionToAdd' is invalid; it was not found in HKEY_CLASSES_ROOT."
                $ExitCode = 1
                return
            }

            # Check if the extension is protected and the User Protection service or task is running
            if ($ProtectedExtensions -contains $ExtensionToAdd -and ($UserProtectionService -or $UserProtectionTask)) {
                Write-Host -Object "[Warning] '$ExtensionToAdd' may be protected by the 'User Choice Protection Driver'. You may need to select the 'Disable User Choice Protection Driver' to successfully complete this change."
            }

            # Add the valid extension to the list
            $ExtensionList.Add($ExtensionToAdd)
        }
    }

    # Check if no valid extensions were provided and the action is not related to the User Choice Protection Driver
    if ((!$Extensions -or $ExtensionList.Count -eq 0) -and $Action -ne "Disable User Choice Protection Driver" -and $Action -ne "Enable User Choice Protection Driver") {
        Write-Host -Object "[Error] You must provide a valid extension to set a default program association."
        exit 1
    }

    # Trim any leading or trailing whitespace from $ProgID if it is set
    if ($ProgID) {
        $ProgID = $ProgID.Trim()
    }

    if($Action -eq "Disable User Choice Protection Driver" -or $Action -eq "Enable User Choice Protection Driver" -and $ProgID){
        Write-Host -Object "[Error] Cannot add an association and '$Action' at the same time."
        exit 1
    }

    # Check if $ProgID is not set and the action is not related to the User Choice Protection Driver
    if (!$ProgId -and $Action -ne "Disable User Choice Protection Driver" -and $Action -ne "Enable User Choice Protection Driver") {
        Write-Host -Object "[Error] Missing the program id for the program you'd like to associate with your given file type."
        Write-Host -Object "https://learn.microsoft.com/en-us/windows/win32/shell/fa-progids"
        exit 1
    }

    # Check if $ProgID is a file extension
    if ($ProgID -Match '^\.') {
        Write-Host -Object "[Error] Program ID '$ProgID' starts with an invalid character '.'. Please specify a different program id."
        Write-Host -Object "https://learn.microsoft.com/en-us/windows/win32/shell/fa-progids"
        exit 1
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
                $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
                if ($Result) { $InstallList.Add($Result) }

                $Result = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
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
            Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
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

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated privileges
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with administrator privileges."
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

    # Check if the application is installed
    Write-Host -Object "Checking that '$ApplicationName' is installed."
    $ProgramIsInstalled = Find-InstallKey -DisplayName $ApplicationName

    # Get all user profiles on the machine
    $UserProfiles = Get-UserHives -Type "All"
    $ProfileWasLoaded = New-Object System.Collections.Generic.List[object]

    # Check if $ProgID is found in the registry
    if (Test-Path -Path "Registry::HKEY_LOCAL_MACHINE\Software\Classes\$ProgID" -ErrorAction SilentlyContinue) {
        $ProgIDisValid = $True
    }

    # Loop through each profile on the machine
    ForEach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        If (!(Test-Path -Path Registry::HKEY_USERS\$($UserProfile.SID) -ErrorAction SilentlyContinue)) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            $ProfileWasLoaded.Add($UserProfile)
        }

        # Check if $ProgID is found in the registry under the user profile
        if (Test-Path -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Classes\$ProgID" -ErrorAction SilentlyContinue) {
            $ProgIDisValid = $True
        }

        # Check if the application is installed for this user profile
        if (!$ProgramIsInstalled) {
            $ProgramIsInstalled = Find-InstallKey -DisplayName $ApplicationName -UserBaseKey "Registry::HKEY_USERS\$($UserProfile.SID)"
        }
    }

    # HKEY_CLASSES_ROOT is the combined keys of HKEY_LOCAL_MACHINE\Software\Classes and HKEY_CURRENT_USER\Software\Classes
    if (!$ProgIDisValid) {
        Write-Host -Object "[Error] Program ID '$ProgID' is invalid and was not found at HKEY_CLASSES_ROOT\$ProgID. Please specify a different program id."
        Write-Host -Object "https://learn.microsoft.com/en-us/windows/win32/shell/fa-progids"
        exit 1
    }

    # Check if the application is installed as an AppX package
    if (!$ProgramIsInstalled) {
        $ProgramIsInstalled = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*$ApplicationName*" }
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

    # If the application is not installed, display a warning
    if (!$ProgramIsInstalled) {
        Write-Host -Object "[Warning] The application '$ApplicationName' was not found."
    }
    else {
        Write-Host -Object "Found '$ApplicationName'."
    }

    # Set file associations for each user profile
    ForEach ($UserProfile in $UserProfiles) {
        $ExtensionList | ForEach-Object {
            Write-Host -Object "`nSetting association of '$_' to '$ProgId' for $($UserProfile.Username)."
            
            # Prepare values for setting the association
            $userExperience = "User Choice set via Windows User Experience {D18B6DD5-6124-4341-9318-804003BAFA0B}"
            $hexDateTime = Get-HexDateTime
        
            $File = $_
            $ToBeHashed = "$File$($UserProfile.SID)$ProgID$hexDateTime$userExperience".ToLower()
            $Hash = Get-Hash -BaseInfo $ToBeHashed

            # Set the registry keys for file association
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$File\UserChoice" -Name "Hash" -Value $Hash -PropertyType String
            Set-RegKey -Path "Registry::HKEY_USERS\$($UserProfile.SID)\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$File\UserChoice" -Name "ProgId" -Value $ProgID -PropertyType String

            Write-Host -Object "Association set."
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
    elseif (!$ForceRestartComputer -and $ExitCode -eq 0) {
        Write-Host -Object "`n[Warning] In order for the thumbnails to update immediately, you may need to restart Explorer."
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
