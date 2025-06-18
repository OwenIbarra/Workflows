# Restricts the use of Python in Excel for all users. By default itll enable a security prompt but does have the option to block or to set it back to the Microsoft default (no warnings or prompts).

<#
.SYNOPSIS
    Restricts the use of Python in Excel for all users. By default it'll enable a security prompt but does have the option to block or to set it back to the Microsoft default (no warnings or prompts).
.DESCRIPTION
    Restricts the use of Python in Excel for all users. By default it'll enable a security prompt but does have the option to block or to set it back to the Microsoft default (no warnings or prompts).
.EXAMPLE
    (No Parameters)
    
    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1001\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 1
    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1002\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 1
    Set Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1003\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings to 1

PARAMETER: -Block
    Blocks the use of Python in Excel.
.EXAMPLE
    -Block

    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1001\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 2
    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1002\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 2
    Set Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1003\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings to 2

PARAMETER: -IncludeNewUsers
    Adds the registry key to the Default Profile so that this change carriers over when new accounts are created.
.EXAMPLE
    -IncludeNewUsers

    Set Registry::HKEY_USERS\DefaultProfile\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings to 1
    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1001\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 1
    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1002\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 1
    Set Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1003\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings to 1

PARAMETER: -ChangeBackToMicrosoftDefault
    Resets the setting/restriction back to the Microsoft Default (enabled with no security prompt).
.EXAMPLE
    -ChangeBackToMicrosoftDefault

    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1001\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 0
    Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1002\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings changed from 1 to 0
    Set Registry::HKEY_USERS\S-1-5-21-3870645062-3653562310-3850680542-1003\software\policies\microsoft\office\16.0\excel\security\PythonFunctionWarnings to 0
.LINK
    https://support.microsoft.com/en-us/office/data-security-and-python-in-excel-33cc88a4-4a87-485e-9ff9-f35958278327
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 8.1, Server 2012
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [Switch]$Block = [System.Convert]::ToBoolean($env:blockPython),
    [Parameter()]
    [Switch]$IncludeNewUsers = [System.Convert]::ToBoolean($env:includeNewUsers),
    [Parameter()]
    [Switch]$ChangeBackToMicrosoftDefault = [System.Convert]::ToBoolean($env:changeBackToMicrosoftDefaultSetting)
)

begin {

    # If incompatible options are detected error out
    if($Block -and $ChangeBackToMicrosoftDefault){
        Write-Error "-ChangeBackToMicrosoftDefault and -Block cannot be used together. The 'Change Back To Microsoft Default' option is to set Python in Excel back to how Microsoft ships the feature (with all security warnings disabled)."
        exit 1
    }

    # Write a warning message for the least secure option
    if($ChangeBackToMicrosoftDefault){
        Write-Warning "Changing the setting back to the default. All Python security warnings will be disabled..."
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Handy registry setting function
    function Set-HKProperty {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet('DWord', 'QWord', 'String', 'ExpandedString', 'Binary', 'MultiString', 'Unknown')]
            $PropertyType = 'DWord'
        )
        if (-not $(Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            New-Item -Path $Path -Force | Out-Null
        }
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
        else {
            # Create property with value
            try {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            Write-Host "Set $Path\$Name to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    # This function will gather all the user profiles on the system for use later
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
                $DefaultProfile.Path = "$env:SystemDrive\Users\Default"
    
                $DefaultProfile | Where-Object { $ExcludedUsers -notcontains $_.UserName }
            }
        }
    
        $UserProfiles | Where-Object { $ExcludedUsers -notcontains $_.UserName }
    }
}
process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # If we're only asked to set it for existing users we won't include the default registry hive
    if($IncludeNewUsers){
        $UserProfiles = Get-UserHives -Type "All" -IncludeDefault
    }else{
        $UserProfiles = Get-UserHives -Type "All"
    }
    
    $Key = "software\policies\microsoft\office\16.0\excel\security"
    $PropertyName = "PythonFunctionWarnings"

    if($ChangeBackToMicrosoftDefault){
        # No Prompt and unlocked
        $Value = 0
    }

    # This is the default option for the script
    if(-not ($ChangeBackToMicrosoftDefault) -and -not ($Block)){
        # Prompt
        $Value = 1
    }
    
    if($Block){
        # Block
        $Value = 2
    }

    # Loop through each profile on the machine
    Foreach ($UserProfile in $UserProfiles) {
        # Load User ntuser.dat if it's not already loaded
        If (($ProfileWasLoaded = Test-Path Registry::HKEY_USERS\$($UserProfile.SID)) -eq $false) {
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe LOAD HKU\$($UserProfile.SID) `"$($UserProfile.UserHive)`"" -Wait -WindowStyle Hidden
        }

        Set-HKProperty -Path "Registry::HKEY_USERS\$($UserProfile.SID)\$Key" -Name $PropertyName -Value $Value
        
        # Unload NTuser.dat
        If ($ProfileWasLoaded -eq $false) {
            [gc]::Collect()
            Start-Sleep 1
            Start-Process -FilePath "cmd.exe" -ArgumentList "/C reg.exe UNLOAD HKU\$($UserProfile.SID)" -Wait -WindowStyle Hidden | Out-Null
        }
    }
}
end {
    
    
    
}
