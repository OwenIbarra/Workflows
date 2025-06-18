# Create and apply a firewall rule with your specified configuration options.
#Requires -Version 5.1

<#
.SYNOPSIS
    Create and apply a firewall rule with your specified configuration options.
.DESCRIPTION
    Create and apply a firewall rule with your specified configuration options.
.EXAMPLE
    -RuleName "My Test Rule" -Direction "Both" -Action "Allow Connection if Secure" -Protocol "Both" -Port "49153"
    
    Creating firewall rule(s) with your desired options.
    Successfully created firewall rule.

    DisplayName  Direction Action Status                                                  
    -----------  --------- ------ ------                                                  
    My Test Rule   Inbound  Allow The rule was parsed successfully from the store. (65536)
    My Test Rule   Inbound  Allow The rule was parsed successfully from the store. (65536)
    My Test Rule  Outbound  Allow The rule was parsed successfully from the store. (65536)
    My Test Rule  Outbound  Allow The rule was parsed successfully from the store. (65536)

PARAMETER: -RuleName "ReplaceMeWithYourDesiredFirewallRuleName"
    The name of the firewall rule.

PARAMETER: -ProfileName "ReplaceMeWithYourDesiredFirewallProfile"
    The profile to which the firewall rule applies (e.g., Domain, Private, Public, All).

PARAMETER: -Direction "ReplaceMeWithTheDirectionOftheTraffic"
    The direction of the traffic (Inbound, Outbound, Both).

PARAMETER: -Action "ReplaceMeWithYourDesiredAction"
    The action to take on matching traffic (Allow, Allow with Authentication, Block).

PARAMETER: -ProgramPath "ReplaceMeWithThePathToYourProgram"
    The path to the program for which the rule applies, if applicable.

PARAMETER: -Protocol "ReplaceMeWithYourDesiredProtocol"
    The network protocol (TCP, UDP, Both). This option is required if creating a port based rule.

PARAMETER: -Port "ReplaceMeWithYourDesiredPortNumber"
    The port number(s) for the rule. Can be a single port, a list of ports, or a range (e.g., 80, 443, 1000-2000).

PARAMETER: -LocalIP "ReplaceMeWithALocalIp"
    The local IP address this rule applies to (if any). Only individual IP addresses are supported (e.g., 192.168.0.23).

PARAMETER: -RemoteIp "ReplaceMeWithARemoteIp"
    The remote IP address this rule applies to (if any). Only individual IP addresses are supported (e.g., 8.8.8.8).
.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$RuleName,
    [Parameter()]
    [String]$ProfileName = "All",
    [Parameter()]
    [String]$Direction = "Inbound",
    [Parameter()]
    [String]$Action,
    [Parameter()]
    [String]$ProgramPath,
    [Parameter()]
    [String]$Protocol,
    [Parameter()]
    [String]$Port,
    [Parameter()]
    [String]$LocalIP,
    [Parameter()]
    [String]$RemoteIP
)

begin {
    # Replace the command line parameters with script form information
    if ($env:ruleName -and $env:ruleName -notlike "null") { $RuleName = $env:ruleName }
    if ($env:profileName -and $env:profileName -notlike "null") { $ProfileName = $env:profileName }
    if ($env:direction -and $env:direction -notlike "null") { $Direction = $env:direction }
    if ($env:action -and $env:action -notlike "null") { $Action = $env:action }
    if ($env:programPath -and $env:programPath -notlike "null") { $ProgramPath = $env:programPath }
    if ($env:protocol -and $env:protocol -notlike "null") { $Protocol = $env:protocol }
    if ($env:port -and $env:port -notlike "null") { $Port = $env:port }
    if ($env:localIp -and $env:localIp -notlike "null") { $LocalIP = $env:localIp }
    if ($env:remoteIp -and $env:remoteIp -notlike "null") { $RemoteIP = $env:remoteIp }

    # Check if the rule name is provided
    if (!$RuleName) {
        Write-Host -Object "[Error] You must provide a name for the firewall exception."
        exit 1
    }

    # Check if the rule name contains an invalid character
    if ($RuleName -match '[|]') {
        Write-Host -Object "[Error] An invalid rule name of '$RuleName' was given. Rule names cannot contain the following characters: |"
        exit 1
    }

    # Check if the profile name is provided
    if (!$ProfileName) {
        Write-Host -Object "[Error] Cannot create a firewall exception without the firewall profile name."
        exit 1
    }

    # Define valid profiles and check if the provided profile name is valid
    $ValidProfiles = "Domain", "Private", "Public", "All"
    if ($ValidProfiles -notcontains $ProfileName) {
        Write-Host -Object "[Error] An invalid profile name of '$ProfileName' was given. Only one of the following profile names are valid: Domain, Private, Public, All"
        exit 1
    }

    # Check if the direction is provided
    if (!$Direction) {
        Write-Host -Object "[Error] You must provide a direction for the exception!"
        exit 1
    }

    # Define valid directions and check if the provided direction is valid
    $ValidDirections = "Inbound", "Outbound", "Both"
    if ($ValidDirections -notcontains $Direction) {
        Write-Host -Object "[Error] An invalid direction of '$Direction' was given. Only one of the following directions are allowed: 'Inbound', 'Outbound', 'Both'"
        exit 1
    }

    # Check if the action is provided
    if (!$Action) {
        Write-Host -Object "[Error] Missing an action to perform!"
        exit 1
    }

    # Define valid actions and check if the provided action is valid
    $ValidActions = "Allow", "Allow Connection if Secure", "Block"
    if ($ValidActions -notcontains $Action) {
        Write-Host -Object "[Error] An invalid action of '$Action' was given. Only one of the following actions are allowed: 'Allow', 'Allow Connection if Secure', 'Block'"
        exit 1
    }

    # Check if the program path is valid if provided
    if ($ProgramPath -and !(Test-Path -Path $ProgramPath -ErrorAction SilentlyContinue)) {
        Write-Host -Object "[Error] An invalid program path of '$ProgramPath' was given. File does not exist at that path."
        exit 1
    }

    # Check if the program path points to an executable file
    if ($ProgramPath -and (Get-Item -Path $ProgramPath -Force -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Extension -ErrorAction SilentlyContinue) -ne ".exe") {
        Write-Host -Object "[Error] An invalid program path of '$ProgramPath' was given. Only exe files are allowed!"
        exit 1
    }

    # Define valid protocols and check if the provided protocol is valid
    $ValidProtocols = "TCP", "UDP", "Both"
    if ($Protocol -and $ValidProtocols -notcontains $Protocol) {
        Write-Host -Object "[Error] An invalid protocol of '$Protocol' was given. Only one of the following protocols are valid: TCP, UDP, Both"
        exit 1
    }

    # Check if the port number is valid
    if ($Port -and $Port -match "[^,\-0-9\s]") {
        Write-Host -Object "[Error] An invalid port number of '$Port' was given. The following are valid port number examples: '49153','49153,49156,49157','49153-49160','49153,49155,49157-49158'"
        Write-Host -Object "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"
        exit 1
    }

    # Validate port ranges if provided
    if ($Port) {
        # Split the port string by commas to handle multiple ports or port ranges
        $Port -split ',' | Where-Object { $_ -match '[\-]' } | ForEach-Object {
            # Check if the port range format is valid (should contain a single hyphen)
            if ($_.Trim() -notmatch '^[^-]*-[^-]*$') {
                Write-Host -Object "[Error] An invalid port range of '$($_.Trim())' was given. Ranges should look like '49154-49155'."
                exit 1
            }

            # Ensure the port range contains only positive numbers and a hyphen
            if ($_.Trim() -notmatch '^[\s]*[0-9]+[\s]*-[\s]*[0-9]+[\s]*$') {
                Write-Host -Object "[Error] An invalid port range of '$($_.Trim())' was given. Ranges should look like '49154-49155' where both numbers in the range are positive numbers."
                exit 1
            }

            # Split the port range into individual numbers
            try {
                $numbers = $_.Trim() -split '-'
                $number1 = [int]$numbers[0]
                $number2 = [int]$numbers[1]
            }
            catch {
                Write-Host -Object "[Error] Failed to break up port into numbers."
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }

            # Check if the starting number of the range is less than the ending number
            if ($number1 -ge $number2) {
                Write-Host -Object "[Error] An invalid port range of '$($_.Trim())' was given. The starting number of the range must be less than the ending number."
                exit 1
            }
        }

        # Check if port numbers are within valid range
        $Port -split ',' -split '-' | ForEach-Object {
            try {
                [long]$PortToCheck = $_.Trim()
            }
            catch {
                Write-Host -Object "[Error] An invalid port number of '$($_.Trim())' was given. A number that is less than or equal to 65535 was expected."
                Write-Host -Object "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"
                Write-Host -Object "[Error] $($_.Exception.Message)"
                exit 1
            }

            if ($PortToCheck -gt 65535) {
                Write-Host -Object "[Error] An invalid port number of '$PortToCheck' was given. Port must be less than or equal to 65535."
                Write-Host -Object "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml"
                exit 1
            }
        }
    }

    # Check if only one of Protocol or Port is specified; both must be specified together
    if ((!$Protocol -and $Port) -or (!$Port -and $Protocol)) {
        Write-Host -Object "[Error] When specifying a port or protocol you must specify both a port and a protocol."
        exit 1
    }

    # Validate the format of LocalIP
    if ($LocalIP -and $LocalIP -match '[^a-zA-Z_0-9\.:]') {
        Write-Host -Object "[Error] An invalid local ip of '$LocalIP' was given. Valid Examples: '192.168.0.12','2002:9d3b:1a31:4:208:74ff:fe39:fc43'"
        exit 1
    }

    # Check if LocalIP is either in IPv4 or IPv6 format
    if ($LocalIP -and ($LocalIP -notmatch '[0-9][\.]' -and $LocalIP -notmatch '[a-zA-Z_0-9][:]')) {
        Write-Host -Object "[Error] An invalid local ip of '$LocalIP' was given. Valid Examples: '192.168.0.12','2002:9d3b:1a31:4:208:74ff:fe39:fc43'"
        exit 1
    }

    # Attempt to cast LocalIP to [IPAddress] to validate it
    if ($LocalIP) {
        try {
            [ipaddress]$LocalIP
        }
        catch {
            Write-Host -Object "[Error] An invalid local ip of '$LocalIP' was given. Valid Examples: '192.168.0.12','2002:9d3b:1a31:4:208:74ff:fe39:fc43'"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Validate the format of RemoteIP
    if ($RemoteIP -and $RemoteIP -match '[^a-zA-Z_0-9\.:]') {
        Write-Host -Object "[Error] An invalid remote ip of '$RemoteIP' was given. Valid Examples: '1.1.1.1','2001:4860:4860::8888'"
        exit 1
    }

    # Check if RemoteIP is either in IPv4 or IPv6 format
    if ($RemoteIP -and ($RemoteIP -notmatch '[0-9][\.]' -and $RemoteIP -notmatch '[a-zA-Z_0-9][:]')) {
        Write-Host -Object "[Error] An invalid remote ip of '$RemoteIP' was given. Valid Examples: '1.1.1.1','2001:4860:4860::8888'"
        exit 1
    }

    # Attempt to cast RemoteIP to [IPAddress] to validate it
    if ($RemoteIP) {
        try {
            [ipaddress]$RemoteIP
        }
        catch {
            Write-Host -Object "[Error] An invalid remote ip of '$RemoteIP' was given. Valid Examples: '1.1.1.1','2001:4860:4860::8888'"
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    # Ensure at least one of ProgramPath, Port and Protocol, or IPs is specified
    if (!$ProgramPath -and !$Port -and !$RemoteIP -and !$LocalIP) {
        Write-Host -Object "[Error] You must specify either a program, a port and protocol, or an IP."
        exit 1
    }

    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Try to get the status of the firewall profiles (Domain, Public, Private)
    try {
        $DomainProfile = Get-NetFirewallProfile -Name "Domain" -ErrorAction Stop | Where-Object { $_.Enabled -eq $True }
        $PublicProfile = Get-NetFirewallProfile -Name "Public" -ErrorAction Stop | Where-Object { $_.Enabled -eq $True }
        $PrivateProfile = Get-NetFirewallProfile -Name "Private" -ErrorAction Stop | Where-Object { $_.Enabled -eq $True }
    }
    catch {
        Write-Host -Object "[Error] Failed to get current firewall profile status."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Initialize a hashtable to store the new firewall rule properties
    $NewFirewallRule = @{
        DisplayName = $RuleName
    }

    # Warn if any of the firewall profiles are disabled
    if (!$DomainProfile) {
        Write-Host -Object "[Warning] Domain firewall profile is disabled!"
    }
    if (!$PrivateProfile) {
        Write-Host -Object "[Warning] Private firewall profile is disabled!"
    }
    if (!$PublicProfile) {
        Write-Host -Object "[Warning] Public firewall profile is disabled!"
    }

    # Set the profile for the new firewall rule based on the provided profile name
    switch ($ProfileName) {
        "All" {
            if (!$DomainProfile -and !$PrivateProfile -and !$PublicProfile) {
                Write-Host -Object "[Error] Unable to set firewall rule as all firewall profiles are disabled."
                exit 1
            } 

            $NewFirewallRule["Profile"] = "Any" 
        }
        "Domain" {
            if (!$DomainProfile) {
                Write-Host -Object "[Error] Unable to set firewall rule as the domain firewall profile is disabled."
                exit 1
            }

            $NewFirewallRule["Profile"] = "Domain" 
        }
        "Private" {
            if (!$PrivateProfile) {
                Write-Host -Object "[Error] Unable to set firewall rule as the private firewall profile is disabled."
                exit 1
            }

            $NewFirewallRule["Profile"] = "Private" 
        }
        "Public" {
            if (!$PublicProfile) {
                Write-Host -Object "[Error] Unable to set firewall rule as the public firewall profile is disabled."
                exit 1
            }

            $NewFirewallRule["Profile"] = "Public" 
        }
    }

    # Set the direction for the new firewall rule based on the provided direction
    switch ($Direction) {
        "Inbound" { $NewFirewallRule["Direction"] = "Inbound" }
        "Outbound" { $NewFirewallRule["Direction"] = "Outbound" }
        "Both" { $NewFirewallRule["Direction"] = "Inbound" }
    }

    # Set the action for the new firewall rule based on the provided action
    switch ($Action) {
        "Allow" { $NewFirewallRule["Action"] = "Allow" }
        "Allow Connection if Secure" { 
            $NewFirewallRule["Action"] = "Allow"
            $NewFirewallRule["Authentication"] = "Required"  
        }
        "Block" { $NewFirewallRule["Action"] = "Block" }
    }

    # Process the program path if provided
    if ($ProgramPath) {
        try {
            $ProgramPath = Get-Item -Path $ProgramPath -Force | Select-Object -ExpandProperty FullName 
        }
        catch {
            Write-Host -Object "[Error] Unable to retrieve program '$ProgramPath'."
            Write-Host -Object "[Error] $($_.Exception.Message)"
            exit 1
        }

        $NewFirewallRule["Program"] = $ProgramPath
    }

    # Process the protocol and port if both are provided
    if ($Protocol -and $Port) {
        switch ($Protocol) {
            "Both" { $NewFirewallRule["Protocol"] = "TCP" }
            "TCP" { $NewFirewallRule["Protocol"] = "TCP" }
            "UDP" { $NewFirewallRule["Protocol"] = "UDP" }
        }

        $NewFirewallRule["LocalPort"] = ($Port -split ',' -replace '\s')
    }

    # Set the local IP address if provided
    if ($LocalIP) {
        $NewFirewallRule["LocalAddress"] = $LocalIP
    }

    # Set the remote IP address if provided
    if ($RemoteIP) {
        $NewFirewallRule["RemoteAddress"] = $RemoteIP
    }

    # Try to create the new firewall rule
    try {
        Write-Host -Object "Creating firewall rule(s) with your desired options."

        $RuleResults = New-Object System.Collections.Generic.List[Object]

        New-NetFirewallRule @NewFirewallRule -ErrorAction Stop | ForEach-Object {
            $RuleResults.Add($_)
        }

        # If the protocol is both TCP and UDP, create an additional rule for UDP
        if ($Protocol -eq "Both") {
            $NewFirewallRule["Protocol"] = "UDP"
            New-NetFirewallRule @NewFirewallRule -ErrorAction Stop | ForEach-Object {
                $RuleResults.Add($_)
            }
        }

        # If the direction is both inbound and outbound, create an additional rule for outbound
        if ($Direction -eq "Both") {
            $NewFirewallRule["Direction"] = "Outbound"
            New-NetFirewallRule @NewFirewallRule -ErrorAction Stop | ForEach-Object {
                $RuleResults.Add($_)
            }

            # If the protocol is both TCP and UDP, create an additional rule for TCP in outbound direction
            if ($Protocol -eq "Both") {
                $NewFirewallRule["Protocol"] = "TCP"
                New-NetFirewallRule @NewFirewallRule -ErrorAction Stop | ForEach-Object {
                    $RuleResults.Add($_)
                }
            }
        }
    }
    catch {
        Write-Host -Object "[Error] Failed to create firewall rule!"
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    if (($RuleResults | Where-Object { $_.Enabled -eq $True })) {
        Write-Host -Object "Successfully created firewall rule."
        $RuleResults | Format-Table DisplayName, Direction, Action, Status -AutoSize | Out-String | Write-Host
    }

    exit $ExitCode
}
end {
    
    
    
}
