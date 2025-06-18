# Enable (show) or disable (hide) the shutdown, restart, sleep, and hibernate options in the start menu power options in Windows.
#Requires -Version 5.1

<#
.SYNOPSIS
    Enable (show) or disable (hide) the shutdown, restart, sleep, and hibernate options in the start menu power options in Windows.

.DESCRIPTION
    This script can be used to enable or disable the shutdown, restart, sleep and hibernate options in the start menu power options. 

.PARAMETER Action
    Action to take with selected options. Valid arguments are Enable and Disable.
.PARAMETER Shutdown
    Provide this switch to take action on the shutdown option.
.PARAMETER Restart
    Provide this switch to take action on the restart option.
.PARAMETER Sleep
    Provide this switch to take action on the sleep option.
.PARAMETER Hibernate
    Provide this switch to take action on the hibernate option.

.EXAMPLE
    -Action "Enable" -Shutdown
    This example will enable the shutdown option in the start menu power options. If it is already enabled, no action is taken.

    [Info] Taking enable action on shutdown option...
    Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutDown\value changed from 1 to 0
    [Info] Shutdown is now set to enable.

.EXAMPLE
    -Action "Disable" -Shutdown -Restart
    This example will disable the shutdown and restart options in the start menu power options. If an option is already disabled, no action will be taken for that option.

    [Info] Taking disable action on shutdown option...
    Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutDown\value changed from 0 to 1
    [Info] Shutdown is now set to disable.

    [Info] Taking disable action on restart option...
    Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideRestart\value changed from 0 to 1
    [Info] Restart is now set to disable.

.EXAMPLE
    -Action "Enable" -Shutdown -Restart -Sleep
    This example will enable the shutdown, restart and sleep options in the start menu power options. If an option is already enabled, no action will be taken for that option. In this example, shutdown and restart are already enabled.

    [Info] Taking enable action on shutdown option...
    [Info] Shutdown is already set to enable.

    [Info] Taking enable action on restart option...
    [Info] Restart is already set to enable.

    [Info] Taking enable action on sleep option...
    Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSleep\value changed from 1 to 0
    [Info] Sleep is now set to enable.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows 11, Windows Server 2019+
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$Action,

    [Parameter()]
    [switch]$Shutdown = [System.Convert]::ToBoolean($env:shutdown),

    [Parameter()]
    [switch]$Restart = [System.Convert]::ToBoolean($env:restart),

    [Parameter()]
    [switch]$Sleep = [System.Convert]::ToBoolean($env:sleep),

    [Parameter()]
    [switch]$Hibernate = [System.Convert]::ToBoolean($env:hibernate)
)

begin {

    if ($env:Action -and $env:Action -ne "null") { $Action = $env:Action }

    if (-not $Action){
        Write-Host "[Error] Please specify an action."
        exit 1
    }

    if ($Action -notin "Enable","Disable"){
        Write-Host "[Error] Please specify a valid action: Enable, Disable"
        exit 1
    }

    if (-not $Shutdown -and -not $Restart -and -not $Sleep -and -not $Hibernate){
        Write-Host "[Error] At least one option needs to be selected"
        exit 1
    }

    function Test-IsServer2016OrLower{
        try {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                $majorVersion = ([version](Get-WmiObject Win32_OperatingSystem).Version).Major
                $OS = (Get-WmiObject Win32_OperatingSystem).Caption
            }
            else {
                $majorVersion = ([version](Get-CimInstance Win32_OperatingSystem).Version).Major
                $OS = (Get-CimInstance Win32_OperatingSystem).Caption
            }

            if ($majorVersion -lt 10 -or $OS -match "16"){
                return $true
            }
            else{
                return $false
            }
        }
        catch {
            throw
        }
    }

    # check if running on unsupported OS
    try{
        if ((Test-IsServer2016OrLower) -eq $true){
            Write-Host "[Error] This script is not supported on this OS. Supported OS:"
            Write-Host "Windows 10, Windows 11, Windows Server 2019+"
            exit 1
        }
    }
    catch{
        Write-Host -Object "[Error] Unable to get OS build information."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Test-IsDomainJoined {
        # Check the PowerShell version to determine the appropriate cmdlet to use
        try {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                return $(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
            }
            else {
                return $(Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a part of a domain."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    function Set-RegKey {
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet("DWord", "QWord", "String", "ExpandedString", "Binary", "MultiString", "Unknown")]
            $PropertyType = "DWord"
        )
    
        # Check if the specified registry path exists
        if (!(Test-Path -Path $Path)) {
            try {
                # If the path does not exist, create it
                New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            }
            catch {
                # If there is an error creating the path, output an error message and exit
                Write-Host "[Error] Unable to create the registry path $Path for $Name. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
        }
    
        # Check if the registry key already exists at the specified path
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
            # Retrieve the current value of the registry key
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
            if ($CurrentValue -eq $Value) {
                Write-Host "$Path\$Name is already the value '$Value'."
            }
            else {
                try {
                    # Update the registry key with the new value
                    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
                }
                catch {
                    # If there is an error setting the key, output an error message and exit
                    Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                    Write-Host "[Error] $($_.Exception.Message)"
                    exit 1
                }
                # Output the change made to the registry key
                Write-Host "$Path\$Name changed from $CurrentValue to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
            }
        }
        else {
            try {
                # If the registry key does not exist, create it with the specified value and property type
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
            }
            catch {
                # If there is an error creating the key, output an error message and exit
                Write-Host "[Error] Unable to set registry key for $Name at $Path. Please see the error below!"
                Write-Host "[Error] $($_.Exception.Message)"
                exit 1
            }
            # Output the creation of the new registry key
            Write-Host "Set $Path\$Name to $((Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name)"
        }
    }

    function Test-IsVM {
        try {
            if ($PSVersionTable.PSVersion.Major -lt 3) {
                $model = (Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop).Model
            }
            else {
                $model = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Model
            }

            if ($model -match "Virtual|VM"){
                return $true
            }
            else{
                return $false
            }
        }
        catch {
            Write-Host -Object "[Error] Unable to validate whether or not this device is a VM."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }
    
    function Test-IsSleepEnabled{
        $sleepReg = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
        $sleepRegKey = "ShowSleepOption"

        try{
            # the below value only has an effect on sleep if it is set to 0 (so return $false)
            # if it is set to anything else, or it does not exist, it will not effect the functionality of the sleep function or this script (so return $true)
            $currentValue = (Get-ItemProperty -Path $sleepReg -Name $sleepRegKey -ErrorAction SilentlyContinue).$sleepRegKey

            if ($currentValue -eq 0){
                return $false
            }
            else{
                return $true
            }
        }
        catch{
            Write-Host -Object "[Error] Unable to validate whether or not sleep is enabled."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    function Test-HibernateStatus {
        # get supported sleep states from powercfg
        $supportedSleepStates = powercfg.exe /a 2>$null

        $output = [PSCustomObject]@{
            Supported = $null
            Enabled = $null
        }

        # search through output of powercfg to determine status
        if ($supportedSleepStates | Select-String "The system firmware does not support hibernation"){
            $output.Supported = $false
            $output.Enabled = $false
        }
        elseif ($supportedSleepStates | Select-String "Hibernation has not been enabled"){
            $output.Supported = $true
            $output.Enabled = $false
        }
        else{
            $output.Supported = $true
            $output.Enabled = $true
        }

        # output the PSCustomObject
        return $output
    }
}
process {
    if ((Test-IsElevated) -eq $false) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    if (Test-IsDomainJoined){
        Write-Host "[Warning] Domain-joined host detected. GPO settings could override these settings.`n"
    }

    # enable = show buttons = value is 0
    # disable = hide buttons = value is 1
    if ($Action -eq "Enable"){
        $newValue = 0
    }
    elseif ($Action -eq "Disable"){
        $newValue = 1
    }

    $ExitCode = 0

    if ($shutdown){
        Write-Host "[Info] Taking $action action on shutdown option..."
        $shutdownReg = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideShutDown"

        try{
            if ((Get-ItemProperty $shutdownReg -Name "value" -ErrorAction SilentlyContinue).Value -eq $newValue){
                Write-Host "[Info] Shutdown is already set to $($action.ToLower()).`n"
            }
            else{
                Set-RegKey -Path $shutdownReg -Name "value" -Value $newValue -PropertyType "DWord" -ErrorAction Stop
                Write-Host "[Info] Shutdown is now set to $($action.ToLower()).`n"
            }
        }
        catch{
            Write-Host "[Error] Failed to set: $shutdownReg\value to $newValue"
            Write-Host "[Error] $($_.Exception.Message)`n"
            $ExitCode = 1
        }
    }

    if ($restart){
        Write-Host "[Info] Taking $action action on restart option..."
        $restartReg = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideRestart"

        try{
            if ((Get-ItemProperty $restartReg -Name "value" -ErrorAction SilentlyContinue).Value -eq $newValue){
                Write-Host "[Info] Restart is already set to $($action.ToLower()).`n"
            }
            else{
                Set-RegKey -Path $restartReg -Name "value" -Value $newValue -PropertyType "DWord" -ErrorAction Stop
                Write-Host "[Info] Restart is now set to $($action.ToLower()).`n"
            }
        }
        catch{
            Write-Host "[Error] Failed to set: $restartReg\value to $newValue"
            Write-Host "[Error] $($_.Exception.Message)`n"
            $ExitCode = 1
        }
    }

    if ($sleep -or $hibernate){
        if (Test-IsVM){
            Write-Host "[Warning] Possible virtual machine detected. Sleep and hibernate options may not work as expected on virtual machines.`n"
        }
    }

    if ($sleep){
        Write-Host "[Info] Taking $action action on sleep option..."
        
        if ($Action -eq "Enable"){
            $sleepEnabled = Test-IsSleepEnabled

            if ($sleepEnabled -eq $false){
                Write-Host "[Error] HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings\ShowSleepOption is set to 0. This needs to be set to 1 in order for the enable action to work as expected.`n"
                $ExitCode = 1
            }
        }

        if ($sleepEnabled -or $Action -eq "Disable"){
            $hideSleepReg = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Start\HideSleep"
            try{
                if ((Get-ItemProperty $hideSleepReg -Name "value" -ErrorAction SilentlyContinue).Value -eq $newValue){
                    Write-Host "[Info] Sleep is already set to $($action.ToLower()).`n"
                }
                else{
                    Set-RegKey -Path $hideSleepReg -Name "value" -Value $newValue -PropertyType "DWord" -ErrorAction Stop
                    Write-Host "[Info] Sleep is now set to $($action.ToLower()).`n"
                }
            }
            catch{
                Write-Host "[Error] Failed to set: $hideSleepReg\value to $newValue"
                Write-Host "[Error] $($_.Exception.Message)`n"
                $ExitCode = 1
            }
        }
    }

    if ($hibernate){
        Write-Host "[Info] Taking $action action on hibernate option..."

        # check if hibernation is supported and enabled on this device
        $result = Test-HibernateStatus
        $hibernationSupported = $result.Supported
        $hibernationEnabled = $result.Enabled

        if (-not $hibernationSupported){
            Write-Host "[Error] Hibernation is not supported on $env:computername. No changes will be made to hibernation settings.`n"
            $ExitCode = 1
        }
        elseif (-not $hibernationEnabled){
            Write-Host "[Error] Hibernation is supported on $env:computername but is not enabled. Please enable hibernation on this system.`n"
            $ExitCode = 1
        }

        # if enabled, continue with action
        if ($hibernationEnabled){
            # newValue is reversed for hibernate, since it is a "show" and not a "hide" regkey
            if ($Action -eq "Enable"){
                $newValue = 1
            }
            elseif ($Action -eq "Disable"){
                $newValue = 0
            }

            $hibernateReg = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"

            try{
                if ((Get-ItemProperty $hibernateReg -Name "ShowHibernateOption" -ErrorAction SilentlyContinue).ShowHibernateOption -eq $newValue){
                    Write-Host "[Info] Hibernate is already set to $($action.ToLower())."
                }
                else{
                    Set-RegKey -Path $hibernateReg -Name "ShowHibernateOption" -Value $newValue -PropertyType "DWord" -ErrorAction Stop
                    Write-Host "[Info] Hibernate is now set to $($action.ToLower())."
                }
            }
            catch{
                Write-Host "[Info] Hibernation action: $Action failed"
                Write-Host "[Error] $($_.Exception.Message)`n"
            }
        }
    }
    
    exit $ExitCode
}
end {
    
    
    
}
