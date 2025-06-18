# Runs an nmap scan to find rogue dhcp servers on a network. This script will not install nmap and nmap is required for this script to work.
#Requires -Version 4.0

<#
.SYNOPSIS
    Runs an nmap scan to find rogue dhcp servers on a network. This script will not install nmap and nmap is required for this script to work.
.DESCRIPTION
    Runs an nmap scan to find rogue dhcp servers on a network. This script will not install nmap and nmap is required for this script to work.
.EXAMPLE
    (No Parameters)
    
    DHCP Servers found.

    Mac Address       IP Address    
    -----------       ----------    
    00:15:5D:FF:93:C3 172.17.240.1  
                      172.17.242.16 
    00:15:5D:45:D5:07 172.17.251.231



    Checking allowed servers list...
    C:\ProgramData\NinjaRMMAgent\scripting\customscript_gen_14.ps1 : Rogue DHCP Server Found! 172.17.240.1 is not on the 
    list of allowed DHCP Servers.
        + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException
        + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException,customscript_gen_14.ps1

PARAMETER: -AllowedServers "172.17.240.1"
    Lists 172.17.240.1 as an allowed dhcp server.

PARAMETER: -CustomField "ReplaceMeWithAnyMultilineCustomField"
    Output results to a custom field of your choice.

PARAMETER: -AllowedServersField "ReplaceMeWithAnyTextCustomField"
    Will retrieve a list of allowed servers from a custom field.
    
.OUTPUTS
    None
.NOTES
    Minimum Supported OS: Windows 8, Server 2012
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String[]]$AllowedServers,
    [Parameter()]
    [String]$CustomField = "rogueDHCPServers",
    [Parameter()]
    [String]$AllowedServersField = "allowedDHCPServers"
)

begin {

    # If script variables are used set them here
    if($env:allowedServersCustomField -and $env:allowedServersCustomField -notlike "null"){
        $AllowedServersField = $env:allowedServersCustomField
    }

    if($AllowedServersField -and -not ($AllowedServers)){
        $AllowedServers = (Ninja-Property-Get $AllowedServersField) -split ',' | ForEach-Object { ($_).trim() }
    }

    if($env:allowedServers -and $env:allowedServers -notlike "null"){
        $AllowedServers = $env:AllowedServers -split ',' | ForEach-Object { ($_).trim() }
    }

    if($env:customFieldName -and $env:customFieldName -notlike "null"){
        $CustomField = $env:customFieldName 
    }

    # Parses out the subnet info into cidr format
    function Get-Subnet {
        $DefaultGateways = (Get-NetIPConfiguration).IPv4DefaultGateway

        $Subnets = $DefaultGateways | ForEach-Object {
            $Index = $_.ifIndex
            $PrefixLength = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.PrefixOrigin -ne 'WellKnown' -and $Index -eq $_.InterfaceIndex } | Select-Object -ExpandProperty PrefixLength)
            if ($_.NextHop -and $PrefixLength) {
                "$($_.NextHop)/$PrefixLength"
            }
        }

        if ($Subnets) {
            $Subnets | Select-Object -Unique
        }
    }

    # Handy uninstall string finder
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

            $Result = Get-ChildItem HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($Result) { $UninstallList.Add($Result) }

            $Result = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$DisplayName*" }
            if ($Result) { $UninstallList.Add($Result) }

            # Programs don't always have an uninstall string listed here so to account for that I made this optional.
            if ($UninstallString) {
                $UninstallList | Select-Object -ExpandProperty UninstallString -ErrorAction SilentlyContinue
            }
            else {
                $UninstallList
            }
        }
    }

    $Nmap = (Find-UninstallKey -DisplayName "Nmap" -UninstallString) -replace '"' -replace 'uninstall.exe', 'nmap.exe'
    if (-not $Nmap) {
        Write-Error "Nmap is not installed! Please install nmap prior to running this script. https://nmap.org/download.html"
        exit 1
    }
}
process {

    # Get's a list of subnets
    $Subnets = Get-Subnet
    if (-not $Subnets) {
        Write-Error "Unable to get list of subnets?"
        exit 1
    }

    # nmap arguments
    $Arguments = @(
        "-sU"
        "-p"
        "67"
        "-d"
        $Subnets
        "--open"
        "-oX"
        "$env:TEMP\nmap-results.xml"
    )
    try {
        Start-Process -FilePath $Nmap -ArgumentList $Arguments -WindowStyle Hidden -Wait
        [xml]$result = Get-Content -Path "$env:Temp\nmap-results.xml"
    }
    catch {
        Write-Error "Nmap scan failed to run! Ensure nmap is installed prior to running this script."
        exit 1
    }

    # Parse the xml results
    if ($result) {
        $resultObject = $result.DocumentElement.host | ForEach-Object {
            New-Object psobject -Property @{
                "IP Address"  = ($_.address | Where-Object { $_.addrtype -match "ip" } | Select-Object -ExpandProperty "addr")
                "Mac Address" = ($_.address | Where-Object { $_.addrtype -match "mac" } | Select-Object -ExpandProperty "addr")
            }
        }
    }
    else {
        Write-Error "Nmap results are empty?"
        exit 1
    }

    # Check if the dhcp servers found are on the list. If so simply report back what were found otherwise indicate that they're Rogue DHCP Servers.
    if ($resultObject) {
        Write-Host "DHCP Servers found."
        $resultObject | Sort-Object -Property "IP Address" -Unique | Format-Table | Out-String | Write-Host
        Remove-Item -Path "$env:Temp\nmap-results.xml" -Force

        Write-Host "Checking allowed servers list..."
        $ErrorOut = $False
        $resultObject | ForEach-Object {
            if ($AllowedServers -notcontains $_."IP Address") {
                Write-Error "Rogue DHCP Server Found! $($_.'IP Address') is not on the list of allowed DHCP Servers."
                $ErrorOut = $True
            }
        }

        Ninja-Property-Set -Name $CustomField -Value ($resultObject | Where-Object { $AllowedServers -notcontains $_."IP Address" } | Format-List | Out-String)

        if($ErrorOut -eq $True){
            exit 1
        }

        Write-Host "No rogue dhcp servers found."
    }
}
end {
    
    
    
}
