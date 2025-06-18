# Returns the longest idle time of any user(s) logged in to an RDS(Remote Desktop Services) server.
#Requires -Version 5.1

<#
.SYNOPSIS
    Returns the longest idle time of any user(s) logged in to an RDS(Remote Desktop Services) server.
.DESCRIPTION
    Returns the longest idle time of any user(s) logged in to an RDS(Remote Desktop Services) server.
    If RDS(Remote Desktop Services) is installed and the RSAT tools for it as well,
     then this will get the idle time of each logged in user.
.EXAMPLE
    No parameters needed.
    Returns the longest idle time of all users logged in.
.EXAMPLE
     -UserName "Fred"
    Returns the longest idle time of the user Fred.
.EXAMPLE
    PS C:\> Get-User-Idle-Time.ps1 -UserName "Fred"
    Returns the longest idle time of the user Fred.
.OUTPUTS
    PSCustomObject[]
.NOTES
    Minimum OS Architecture Supported: Windows Server 2016
    Release Notes: Renamed script and added Script Variable support
.COMPONENT
    ManageUsers
#>

[CmdletBinding()]
param (
    # Specify one user on a Terminal Services Server, else leave blank for normal servers and workstations
    [Parameter()]
    $UserName
)

begin {

    if ($env:rdsUsernameToSearchFor -and $env:rdsUsernameToSearchFor -notlike "null") { $UserName = $env:rdsUsernameToSearchFor }
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
        { Write-Output $true }
        else
        { Write-Output $false }
    }
    function Split-Line {
        param (
            [Parameter(ValueFromPipeline)][string]$Text
        )
        process {
            $Text -split ',' | ForEach-Object {
                # Trim spaces and > from start and end
                "$_".Trim().Trim('>')
            }
        }
    }
    function Write-PSCustomObject {
        param (
            [Parameter(Position = 0)][string[]]$Text
        )
        process {
            $LineCounter = 0
            [PSCustomObject]@{
                UserName    = $Text[$LineCounter++]
                SessionName = if ($Text.Count -eq 5) { "" }else { $Text[$LineCounter++] } # Accounts for disconnected users
                ID          = $Text[$LineCounter++]
                State       = $Text[$LineCounter++]
                IdleTime    = $Text[$LineCounter++]
                LogonTime   = $Text[$LineCounter++]
            }
        }
    }
    Function Get-QueryUser() {
        [CmdletBinding()]
        Param()
        $FeatureName = "RDS-RD-Server"
        $IsFeatureInstalled = try { Get-WindowsFeature -Name $FeatureName | Select-Object -ExpandProperty Installed } catch { $false }

        if ($IsFeatureInstalled -or $PSBoundParameters.Debug.IsPresent) {
            try {
                $QueryUsers = query.exe user
                # Replaces all occurrences of 2 or more spaces in a row with a single comma
                $Lines = $QueryUsers | ForEach-Object { $_ -replace ('\s{2,}', ',') }
                if ($Lines.Count -gt 1) {
                    for ($i = 1; $i -lt $($Lines.Count); $i++) {
                        Write-PSCustomObject $($Lines[$i] | Split-Line)
                    }
                }
                else {
                    return $null
                }
            }
            catch {
                throw $_
            }
        }
        else {
            throw "Remote Desktop Services is not installed or setup on this server."
        }
    }
    function Format-IdleTime {
        param (
            [Parameter(ValueFromPipeline)][string]$Text
        )
        process {
            # $Text = "1"
            # $Text = "01:01"
            # $Text = "11+11:11"
            $IdleTime = if ($Text -match "\d+\+\d+:\d+") {
                $HoursMinutes = $Text -split '\+' | Select-Object -First 2
                [PSCustomObject]@{
                    Days    = [int]($Text -split '\+' | Select-Object -First 1)
                    Hours   = [int]($HoursMinutes -split '\:' | Select-Object -First 1)
                    Minutes = [int]($HoursMinutes -split '\:' | Select-Object -First 1 -Skip 1)
                }
            }
            elseif ($Text -match "\d+\:\d+") {
                $HoursMinutes = $Text
                [PSCustomObject]@{
                    Days    = 0
                    Hours   = [int]($HoursMinutes -split '\:' | Select-Object -First 1)
                    Minutes = [int]($HoursMinutes -split '\:' | Select-Object -First 1 -Skip 1)
                }
            }
            elseif ($Text -match "\d+") {
                $HoursMinutes = $Text
                [PSCustomObject]@{
                    Days    = 0
                    Hours   = 0
                    Minutes = [int]($HoursMinutes)
                }
            }
            $CurrentDate = Get-Date
            $IdleDate = Get-Date
            if ($IdleTime.Days) {
                $IdleDate = $IdleDate.AddDays( 0 - $($IdleTime.Days))
            }
            if ($IdleTime.Hours) {
                $IdleDate = $IdleDate.AddHours( 0 - $($IdleTime.Hours))
            }
            if ($IdleTime.Minutes) {
                $IdleDate = $IdleDate.AddMinutes( 0 - $($IdleTime.Minutes))
            }
            $TimeSpan = New-TimeSpan -Start $IdleDate -End $CurrentDate | Select-Object -Property Days, Hours, Minutes
            "Days: $($TimeSpan.Days) Hours: $($TimeSpan.Hours) Minutes: $($TimeSpan.Minutes)"
        }
    }
    $IsDebug = if ($PSBoundParameters.Debug.IsPresent) { $true }else { $false }
}

process {
    if (-not (Test-IsElevated)) {
        Write-Error -Message "Access Denied. Please run with Administrator privileges."
        exit 1
    }

    try {
        $Users = Get-QueryUser -ErrorAction Stop -Debug:$IsDebug | Select-Object UserName, SessionName, ID, State, @{label = "IdleTime"; expression = {
                if ($_.IdleTime -like ".") {
                    Format-IdleTime -Text "0"
                }
                else {
                    Format-IdleTime -Text $_.IdleTime
                }
            }
        }, LogonTime
        $Results = if ($UserName) {
            $Users | Where-Object { $_.UserName -like $UserName }
        }
        else { $Users }
        $Results | Format-Table | Out-String | Write-Host
    }
    catch {
        Write-Error $_
        exit 1
    }
}

end {
    
    
    
}

