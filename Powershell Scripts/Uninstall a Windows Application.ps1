# Uninstall an application using the UninstallString and custom arguments. This script will auto-add /qn /norestart or /S arguments.

This script will only uninstall apps that follow typical uninstall patterns such as msiexec /X{GUID} /qn /norestart.
#Requires -Version 5.1

<#
.SYNOPSIS
    Uninstall an application using the UninstallString and custom arguments. This script will auto-add /qn /norestart or /S arguments.

    This script will only uninstall apps that follow typical uninstall patterns such as msiexec /X{GUID} /qn /norestart.
.DESCRIPTION
    Uninstall an application using the UninstallString and custom arguments. This script will auto-add /qn /norestart or /S arguments.

    This script will only uninstall apps that follow typical uninstall patterns such as msiexec /X{GUID} /qn /norestart.
.EXAMPLE
    -Name "VLC media Player"
    
    Beginning uninstall of VLC media player using MsiExec.exe /X{9675011C-2395-4AD7-B1CC-92910F991F58} /qn /norestart...
    Exit Code for VLC media player: 0
    Successfully uninstalled your requested apps!

PARAMETER: -Name "ReplaceMeWithNameOfApp"
    Exact name of the application to uninstall, separated by commas. E.g., 'VLC media player, Everything 1.4.1.1024 (x64)'.

PARAMETER: -Arguments "/SILENT, /NOREBOOT"
    Additional arguments to use when uninstalling the app, separated by commas. E.g., '/SILENT, /NOREBOOT'.

PARAMETER: -Reboot
    Schedules a reboot for 1 minute after the uninstall process succeeds.

PARAMETER: -Timeout "ReplaceMeWithTheNumberOfMinutesToWait"
    Specify the amount of time in minutes to wait for the uninstall process to complete. 
    If the process exceeds this time, the script and uninstall process will be terminated.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
.COMPONENT
    Misc
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$Name,
    [Parameter()]
    [String]$Arguments,
    [Parameter()]
    [switch]$Reboot = [System.Convert]::ToBoolean($env:reboot),
    [Parameter()]
    [int]$Timeout = 10
)

begin {
    # Replace parameters with dynamic script variables
    if ($env:nameOfAppToUninstall -and $env:nameOfAppToUninstall -notlike "null") { $Name = $env:nameOfAppToUninstall }
    if ($env:arguments -and $env:arguments -notlike "null") { $Arguments = $env:arguments }
    if ($env:timeoutInMinutes -and $env:timeoutInMinutes -notlike "null") { $Timeout = $env:timeoutInMinutes }

    # Check if application name is provided
    if (-not $Name) {
        Write-Host -Object "[Error] No name given, please enter in the name of an app to uninstall!"
        exit 1
    }

    # Check if timeout is provided
    if (-not $Timeout) {
        Write-Host -Object "[Error] No timeout given!"
        Write-Host -Object "[Error] Please enter in a timeout that's greater than or equal to 1 minute or less than or equal to 60 minutes."
        exit 1
    }

    # Validate the timeout is within the acceptable range
    if ($Timeout -lt 1 -or $Timeout -gt 60) {
        Write-Host -Object "[Error] An invalid timeout was given of $Timeout minutes."
        Write-Host -Object "[Error] Please enter in a timeout that's greater than or equal to 1 minute or less than or equal to 60 minutes."
        exit 1
    }

    # Create a list to hold application names after splitting
    $AppNames = New-Object System.Collections.Generic.List[String]
    $Name -split ',' | ForEach-Object {
        $AppNames.Add($_.Trim())
    }

    # Function to check if the script is run with elevated permissions
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Get all users registry hive locations
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
    
        # User account SID's follow a particular pattern depending on if they're Azure AD, a Domain account, or a local "workgroup" account.
        $Patterns = switch ($Type) {
            "AzureAD" { "S-1-12-1-(\d+-?){4}$" }
            "DomainAndLocal" { "S-1-5-21-(\d+-?){4}$" }
            "All" { "S-1-12-1-(\d+-?){4}$" ; "S-1-5-21-(\d+-?){4}$" } 
        }
    
        # We'll need the NTUSER.DAT file to load each user's registry hive. So we grab it if their account SID matches the above pattern. 
        $UserProfiles = Foreach ($Pattern in $Patterns) { 
            Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" |
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

    # Function to find the uninstallation key of an application
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

            # Search for uninstall key in 32-bit registry location
            $Result = Get-ChildItem "Registry::HKEY_USERS\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -match "$([regex]::Escape($DisplayName))" }
            if ($Result) { $UninstallList.Add($Result) }

            # Search for uninstall key in 32-bit user locations
            $Result = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -match "$([regex]::Escape($DisplayName))" }
            if ($Result) { $UninstallList.Add($Result) }

            # Search for uninstall key in 64-bit registry location
            $Result = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -match "$([regex]::Escape($DisplayName))" }
            if ($Result) { $UninstallList.Add($Result) }

            # Search for uninstall key in 64-bit user locations
            $Result = Get-ChildItem "Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Get-ItemProperty | Where-Object { $_.DisplayName -match "$([regex]::Escape($DisplayName))" }
            if ($Result) { $UninstallList.Add($Result) }
    
            # Optionally return the DisplayName and UninstallString
            if ($UninstallString) {
                $UninstallList | ForEach-Object { $_ | Select-Object DisplayName, UninstallString -ErrorAction SilentlyContinue }
            }
            else {
                $UninstallList
            }
        }
    }

    # Initialize the exit code variable
    $ExitCode = 0
}
process {
    # Check for administrative privileges
    if (-not (Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Load unloaded profiles
    $UserProfiles = Get-UserHives -Type "All"
    $ProfileWasLoaded = New-Object System.Collections.Generic.List[string]

    # Loop through each profile on the machine.
    Foreach ($UserProfile in $UserProfiles) {
        # Load user's NTUSER.DAT if it's not already loaded.
        If ((Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            $ProfileWasLoaded.Add("$($UserProfile.SID)")
        }
    }

    # Retrieve similar applications based on names provided
    $SimilarAppsToName = $AppNames | ForEach-Object { Find-UninstallKey -DisplayName $_ -UninstallString }
    if (-not $SimilarAppsToName) {
        Write-Host "[Error] The requested app(s) was not found and none were found that are similar!"
        exit 1
    }

    # Unload all hives that were loaded for this script.
    ForEach ($UserHive in $ProfileWasLoaded) {
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserHive)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Create a list to store apps that are confirmed for uninstallation
    $AppsToUninstall = New-Object System.Collections.Generic.List[Object]
    $SimilarAppsToName | ForEach-Object {
        foreach ($AppName in $AppNames) {
            if ($AppName -eq $_.DisplayName) {
                # A matching app has been found
                $ExactMatch = $True
    
                if ($_.UninstallString) {
                    # Uninstall string is available
                    $UninstallStringFound = $True
                    # Add app to uninstall list
                    $AppsToUninstall.Add($_)
                }
            }
        }
    }

    # Check if any exact matches were found
    if (-not $ExactMatch) {
        Write-Host "[Error] Your requested apps were not found. Please see the below list and try again."
        $SimilarAppsToName | Format-Table DisplayName | Out-String | Write-Host
        exit 1
    }

    # Check if uninstall strings were found for the apps
    if (-not $UninstallStringFound) {
        Write-Host "[Error] No uninstall string found for any of your requested apps!"
        exit 1
    }

    # Check if there are apps without uninstall strings or not found at all
    $AppNames | ForEach-Object {
        if ($AppsToUninstall.DisplayName -notcontains $_) {
            Write-Host "[Error] Either the uninstall string was not present or the app itself was not found for one of your selected apps! See the below list of similar apps and try again."
            $SimilarAppsToName | Format-Table DisplayName | Out-String | Write-Host
            $ExitCode = 1
        }
    }

    # Convert timeout from minutes to seconds
    $TimeoutInSeconds = $Timeout * 60
    $StartTime = Get-Date

    # Process each app to uninstall
    $AppsToUninstall | ForEach-Object {
        $AdditionalArguments = New-Object System.Collections.Generic.List[String]

        # If the uninstall string contains msiexec that's what our executable will be.
        if($_.UninstallString -match "msiexec"){
            $Executable = "msiexec.exe"
        }

        # If it contains a filepath we'll use that as our executable.
        if($_.UninstallString -notmatch "msiexec" -and $_.UninstallString -match '[a-zA-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'){
            $Executable = $Matches[0]
        }

        # Confirm we have an executable.
        if(-not $Executable){
            Write-Host -Object "[Error] Unable to find uninstall executable!"
            exit 1
        }

        # Split uninstall string into executable and possible arguments
        $PossibleArguments = $_.UninstallString -split ' ' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match "^/"}

        # Decide executable and additional arguments based on uninstall string analysis
        $i = 0
        foreach ($PossibleArgument in $PossibleArguments) {
            if (-not ($PossibleArgument -match "^/I{") -and $PossibleArgument) {
                $AdditionalArguments.Add($PossibleArgument)
            }

            if ($PossibleArgument -match "^/I{") {
                $AdditionalArguments.Add("$($PossibleArgument -replace '/I', '/X')")
            }

            $i++
        }

        # Add custom arguments from the user
        if ($Arguments) {
            $Arguments.Split(',') | ForEach-Object {
                $AdditionalArguments.Add($_.Trim())
            }
        }

        # Add the usual silent uninstall arguments if not present
        if($Executable -match "Msiexec"){
            if($AdditionalArguments -notcontains "/qn"){
                $AdditionalArguments.Add("/qn")
            }

            if($AdditionalArguments -notcontains "/norestart"){
                $AdditionalArguments.Add("/norestart")
            }
        }elseif($Executable -match "\.exe"){
            if($AdditionalArguments -notcontains "/S"){
                $AdditionalArguments.Add("/S")
            }

            if($AdditionalArguments -notcontains "/norestart"){
                $AdditionalArguments.Add("/norestart")
            }
        }

        # Verify that executable for uninstallation is found
        if (-not $Executable) {
            Write-Host "[Error] Could not find the executable from the uninstall string!"
            exit 1
        }

        # Start the uninstallation process
        Write-Host -Object "Beginning uninstall of $($_.DisplayName) using $Executable $AdditionalArguments..."
        try{
            if ($AdditionalArguments) {
                $Uninstall = Start-Process $Executable -ArgumentList $AdditionalArguments -NoNewWindow -PassThru
            }
            else {
                $Uninstall = Start-Process $Executable -NoNewWindow -PassThru
            }
        }catch{
            Write-Host "[Error] $($_.Exception.Message)"
            return
        }

        # Calculate the remaining time for the uninstall process and enforce timeout
        $TimeElapsed = (Get-Date) - $StartTime
        $RemainingTime = $TimeoutInSeconds - $TimeElapsed.TotalSeconds

        # Wait for the uninstall process to complete within the remaining time
        try {
            $Uninstall | Wait-Process -Timeout $RemainingTime -ErrorAction Stop
        }
        catch {
            Write-Host -Object "[Alert] The uninstall process for $($_.DisplayName) has exceeded the specified timeout of $Timeout minutes."
            Write-Host -Object "[Alert] The script is now terminating."
            $Uninstall | Stop-Process -Force
            $ExitCode = 1
        }

        # Check and report the exit code of the uninstallation process
        Write-Host -Object "Exit code for $($_.DisplayName): $($Uninstall.ExitCode)"
        if ($Uninstall.ExitCode -ne 0) {
            Write-Host -Object "[Error] Exit code does not indicate success!"
            $ExitCode = 1
        }
    }

    # Pause for 30 seconds before final checks
    Start-Sleep -Seconds 30

    $UserProfiles = Get-UserHives -Type "All"
    $ProfileWasLoaded = New-Object System.Collections.Generic.List[string]

    # Loop through each profile on the machine.
    Foreach ($UserProfile in $UserProfiles) {
        # Load user's NTUSER.DAT if it's not already loaded.
        If ((Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
            $ProfileWasLoaded.Add("$($UserProfile.SID)")
        }
    }

    # Re-check for any remaining apps to confirm they were uninstalled
    $SimilarAppsToName = $AppNames | ForEach-Object { Find-UninstallKey -DisplayName $_ }
    $SimilarAppsToName | ForEach-Object {
        foreach ($AppName in $AppNames) {
            if ($_.DisplayName -eq $AppName) {
                Write-Host -Object "[Error] Failed to uninstall $($_.DisplayName)."
                $UninstallFailure = $True
                $ExitCode = 1
            }
        }
    }

    # Unload all hives that were loaded for this script.
    ForEach ($UserHive in $ProfileWasLoaded) {
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserHive)" -Wait -WindowStyle Hidden | Out-Null
        }
    }

    # Confirm successful uninstallation if no failures detected
    if (-not $UninstallFailure) {
        Write-Host "Successfully uninstalled your requested apps!"
    }

    # Handle reboot if requested and there were no uninstall failures
    if ($Reboot -and -not $UninstallFailure) {
        Write-Host -Object "[Alert] a reboot was requested. Scheduling restart for 60 seconds from now..."
        Start-Process shutdown.exe -ArgumentList "/r /t 60" -Wait -NoNewWindow
    }

    # Exit script with the final exit code
    exit $ExitCode
}
end {
    
    
    
}


