# Checks several common blacklists to see if the devices WAN IP is currently being blacklisted. A private recursive DNS server is recommended, as it is not uncommon for DNS blocklists to block public DNS servers such as 1.1.1.1.
#Requires -Version 5.1

<#
.SYNOPSIS
    Checks several common blacklists to see if the device's WAN IP is currently being blacklisted. A private recursive DNS server is recommended, as it is not uncommon for DNS blocklists to block public DNS servers such as 1.1.1.1.
.DESCRIPTION
    Checks several common blacklists to see if the device's WAN IP is currently being blacklisted. A private recursive DNS server is recommended, as it is not uncommon for DNS blocklists to block public DNS servers such as 1.1.1.1. 
.EXAMPLE
    (No Parameters) - When found on blacklist

    [Alert] The WAN IP '127.0.0.1' was found on 9 blacklist(s).
    You may want to validate these results with 'https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a127.0.0.1'.
    Name                          TTL                                                ResponseCode                          
    ----                          ---                                                ------------                          
    Blocklist.de                  1269                                               127.0.0.14                            
    Interserver RBL               903                                                127.0.0.2                             
    Interserver Spam Assassin RBL 903                                                127.0.0.2                             
    Mailspike Z                   120                                                127.0.0.2                             
    Mailspike BL                  120                                                127.0.0.2                             
    S5H                           5, 86400, 86400, 86400, 30, 300, 30, 300, 300, 300 127.0.0.2, 85.119.82.99, 2001:ba8:1...
    UCE Protect - L1              902                                                127.0.0.2                             
    UCE Protect - L2              902                                                127.0.0.2                             
    UCE Protect - L3              902                                                127.0.0.2

    Blacklists Checked: 0Spam, 0Spam RBL, Anonmails DNSBL, Backscatterer, Blocklist.de, Cymru Bogons, Dan Tor, Dan Tor Exit, Drone BL, Fabel Sources, Host Karma, ImproWare (IMP) DNS RBL, ImproWare (IMP) Spam RBL, Interserver RBL, Interserver Spam Assassin RBL, JIPPG's Relay Blackhole List Project, Kempt.net DNS Black List, Mailspike Z, Mailspike BL, Nordspam BL, PSBL, S5H, Schulte, Spam Eating Monkey - Backscatter, Spam Eating Monkey - Black, SpamCop, Suomispam, Truncate, UCE Protect - L1, UCE Protect - L2, UCE Protect - L3, ZapBL

.EXAMPLE
    (No Parameters) - When not found on blacklist

    The WAN IP '127.0.0.1' was not found on any blacklists.
    You may want to validate these results with 'https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a127.0.0.1'.

    Blacklists Checked: 0Spam, 0Spam RBL, Anonmails DNSBL, Backscatterer, Blocklist.de, Cymru Bogons, Dan Tor, Dan Tor Exit, Drone BL, Fabel Sources, Host Karma, ImproWare (IMP) DNS RBL, ImproWare (IMP) Spam RBL, Interserver RBL, Interserver Spam Assassin RBL, JIPPG's Relay Blackhole List Project, Kempt.net DNS Black List, Mailspike Z, Mailspike BL, Nordspam BL, PSBL, S5H, Schulte, Spam Eating Monkey - Backscatter, Spam Eating Monkey - Black, SpamCop, Suomispam, Truncate, UCE Protect - L1, UCE Protect - L2, UCE Protect - L3, ZapBL

PARAMETER: -CustomField "ReplaceMeWithYourDesiredMultilineCustomField"
    Optionally specify the name of a multiline custom field to store the results in.

.NOTES
    Minimum OS Architecture Supported: Windows 10, Windows Server 2016
    Release Notes: Initial Release
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]$CustomField
)

begin {
    # If using script form variables, replace command line parameters with them.
    if($env:multilineCustomFieldName -and $env:multilineCustomFieldName -notlike "null") { $CustomField = $env:multilineCustomFieldName }

    # Local administrator privileges are required to set custom fields.
    function Test-IsElevated {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object System.Security.Principal.WindowsPrincipal($id)
        $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    function Set-NinjaProperty {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $True)]
            [String]$Name,
            [Parameter()]
            [String]$Type,
            [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
            $Value,
            [Parameter()]
            [String]$DocumentName
        )
        
        $Characters = $Value | Out-String | Measure-Object -Character | Select-Object -ExpandProperty Characters
        if ($Characters -ge 200000) {
            throw [System.ArgumentOutOfRangeException]::New("Character limit exceeded: the value is greater than or equal to 200,000 characters.")
        }
            
        # If requested to set the field value for a Ninja document, specify it here.
        $DocumentationParams = @{}
        if ($DocumentName) { $DocumentationParams["DocumentName"] = $DocumentName }
            
        # This is a list of valid fields that can be set. If no type is specified, assume that the input does not need to be changed.
        $ValidFields = "Attachment", "Checkbox", "Date", "Date or Date Time", "Decimal", "Dropdown", "Email", "Integer", "IP Address", "MultiLine", "MultiSelect", "Phone", "Secure", "Text", "Time", "URL", "WYSIWYG"
        if ($Type -and $ValidFields -notcontains $Type) { Write-Warning "$Type is an invalid type. Please check here for valid types: https://ninjarmm.zendesk.com/hc/en-us/articles/16973443979789-Command-Line-Interface-CLI-Supported-Fields-and-Functionality" }
            
        # The field below requires additional information to set.
        $NeedsOptions = "Dropdown"
        if ($DocumentName) {
            if ($NeedsOptions -contains $Type) {
                # Redirect error output to the success stream to handle errors more easily if nothing is found or something else goes wrong.
                $NinjaPropertyOptions = Ninja-Property-Docs-Options -AttributeName $Name @DocumentationParams 2>&1
            }
        }
        else {
            if ($NeedsOptions -contains $Type) {
                $NinjaPropertyOptions = Ninja-Property-Options -Name $Name 2>&1
            }
        }
            
        # If an error is received with an exception property, exit the function with that error information.
        if ($NinjaPropertyOptions.Exception) { throw $NinjaPropertyOptions }
            
        # The types below require values not typically given to be set. The code below will convert whatever we're given into a format ninjarmm-cli supports.
        switch ($Type) {
            "Checkbox" {
                # Although it's highly likely we were given a value like "True" or a boolean data type, it's better to be safe than sorry.
                $NinjaValue = [System.Convert]::ToBoolean($Value)
            }
            "Date or Date Time" {
                # Ninjarmm-cli expects the GUID of the option to be selected. Therefore, match the given value with a GUID.
                $Date = (Get-Date $Value).ToUniversalTime()
                $TimeSpan = New-TimeSpan (Get-Date "1970-01-01 00:00:00") $Date
                $NinjaValue = $TimeSpan.TotalSeconds
            }
            "Dropdown" {
                # Ninjarmm-cli expects the GUID of the option we're trying to select, so match the value we were given with a GUID.
                $Options = $NinjaPropertyOptions -replace '=', ',' | ConvertFrom-Csv -Header "GUID", "Name"
                $Selection = $Options | Where-Object { $_.Name -eq $Value } | Select-Object -ExpandProperty GUID
            
                if (-not $Selection) {
                    throw [System.ArgumentOutOfRangeException]::New("Value is not present in dropdown options.")
                }
            
                $NinjaValue = $Selection
            }
            default {
                # All the other types shouldn't require additional work on the input.
                $NinjaValue = $Value
            }
        }
            
        # Set the field differently depending on whether it's a field in a Ninja Document or not.
        if ($DocumentName) {
            $CustomField = Ninja-Property-Docs-Set -AttributeName $Name -AttributeValue $NinjaValue @DocumentationParams 2>&1
        }
        else {
            $CustomField = $NinjaValue | Ninja-Property-Set-Piped -Name $Name 2>&1
        }
            
        if ($CustomField.Exception) {
            throw $CustomField
        }
    }

    # Blacklists we are going to check.
    $BlackLists = @(
        [PSCustomObject]@{
            DisplayName     = "0Spam"
            DNSBLDomainName = "bl.0spam.org"
        }
        [PSCustomObject]@{
            DisplayName     = "0Spam RBL"
            DNSBLDomainName = "rbl.0spam.org"
        }
        [PSCustomObject]@{
            DisplayName     = "Anonmails DNSBL"
            DNSBLDomainName = "spam.dnsbl.anonmails.de"
        }
        [PSCustomObject]@{
            DisplayName     = "Backscatterer"
            DNSBLDomainName = "ips.backscatterer.org"
        }
        [PSCustomObject]@{
            DisplayName     = "Blocklist.de"
            DNSBLDomainName = "bl.blocklist.de"
        }
        [PSCustomObject]@{
            DisplayName     = "Cymru Bogons"
            DNSBLDomainName = "bogons.cymru.com"
        }
        [PSCustomObject]@{
            DisplayName     = "Dan Tor"
            DNSBLDomainName = "tor.dan.me.uk"
        }
        [PSCustomObject]@{
            DisplayName     = "Dan Tor Exit"
            DNSBLDomainName = "torexit.dan.me.uk"
        }
        [PSCustomObject]@{
            DisplayName     = "Drone BL"
            DNSBLDomainName = "dnsbl.dronebl.org"
        }
        [PSCustomObject]@{
            DisplayName     = "Fabel Sources"
            DNSBLDomainName = "spamsources.fabel.dk"
        }
        [PSCustomObject]@{
            DisplayName     = "Host Karma"
            DNSBLDomainName = "hostkarma.junkemailfilter.com"
        }
        [PSCustomObject]@{
            DisplayName     = "ImproWare (IMP) DNS RBL"
            DNSBLDomainName = "dnsrbl.swinog.ch"
        }
        [PSCustomObject]@{
            DisplayName     = "ImproWare (IMP) Spam RBL"
            DNSBLDomainName = "spamrbl.swinog.ch"
        }
        [PSCustomObject]@{
            DisplayName     = "Interserver RBL"
            DNSBLDomainName = "rbl.interserver.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Interserver Spam Assassin RBL"
            DNSBLDomainName = "rblspamassassin.interserver.net"
        }
        [PSCustomObject]@{
            DisplayName     = "JIPPG's Relay Blackhole List Project"
            DNSBLDomainName = "mail-abuse.blacklist.jippg.org"
        }
        [PSCustomObject]@{
            DisplayName     = "Kempt.net DNS Black List"
            DNSBLDomainName = "dnsbl.kempt.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Mailspike Z"
            DNSBLDomainName = "z.mailspike.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Mailspike BL"
            DNSBLDomainName = "bl.mailspike.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Nordspam BL"
            DNSBLDomainName = "bl.nordspam.com"
        }
        [PSCustomObject]@{
            DisplayName     = "PSBL"
            DNSBLDomainName = "psbl.surriel.com"
        }
        [PSCustomObject]@{
            DisplayName     = "S5H"
            DNSBLDomainName = "all.s5h.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Schulte"
            DNSBLDomainName = "rbl.schulte.org"
        }
        [PSCustomObject]@{
            DisplayName     = "Spam Eating Monkey - Backscatter"
            DNSBLDomainName = "backscatter.spameatingmonkey.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Spam Eating Monkey - Black"
            DNSBLDomainName = "bl.spameatingmonkey.net"
        }
        [PSCustomObject]@{
            DisplayName     = "SpamCop"
            DNSBLDomainName = "bl.spamcop.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Suomispam"
            DNSBLDomainName = "bl.suomispam.net"
        }
        [PSCustomObject]@{
            DisplayName     = "Truncate"
            DNSBLDomainName = "truncate.gbudb.net"
        }
        [PSCustomObject]@{
            DisplayName     = "UCE Protect - L1"
            DNSBLDomainName = "dnsbl-1.uceprotect.net"
        }
        [PSCustomObject]@{
            DisplayName     = "UCE Protect - L2"
            DNSBLDomainName = "dnsbl-2.uceprotect.net"
        }
        [PSCustomObject]@{
            DisplayName     = "UCE Protect - L3"
            DNSBLDomainName = "dnsbl-3.uceprotect.net"
        }
        [PSCustomObject]@{
            DisplayName     = "ZapBL"
            DNSBLDomainName = "dnsbl.zapbl.net"
        }
    )

    if (!$ExitCode) {
        $ExitCode = 0
    }
}
process {
    # Check if the script is running with elevated privileges (Administrator)
    if (!(Test-IsElevated)) {
        Write-Host -Object "[Error] Access Denied. Please run with Administrator privileges."
        exit 1
    }

    # Try to retrieve the WAN IP using the ipify.org service
    try {
        $WanIP = (Invoke-WebRequest -Uri "api.ipify.org" -UseBasicParsing).Content
    }
    catch {
        Write-Host -Object "[Error] Failed to retrieve WAN IP."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Validate the retrieved WAN IP format
    if ($WanIP -notmatch '\d+\.\d+\.\d+\.\d+') {
        Write-Host -Object "[Error] The service ipify.org returned '$WanIp' which is not a valid IP."
        exit 1
    }

    # Further validate the WAN IP by attempting to cast it as an IP address object
    try {
        [IPAddress]$WanIP | Out-Null
    }
    catch {
        Write-Host -Object "[Error] The service ipify.org returned '$WanIp' which is not a valid IP."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Reverse the IP address octets for DNSBL query
    $IPOctets = $WanIP -split '\.'
    [array]::Reverse($IPOctets)
    $ReversedIp = $IPOctets -join '.'

    # Validate the reversed IP format
    if ($ReversedIp -notmatch '\d+\.\d+\.\d+\.\d+') {
        Write-Host -Object "[Error] '$ReversedIp' is not a valid reversed IP of '$WanIP'."
        exit 1
    }

    # Further validate the reversed IP by attempting to cast it as an IP address object
    try {
        [IPAddress]$ReversedIp | Out-Null
    }
    catch {
        Write-Host -Object "[Error] '$ReversedIp' is not a valid reversed IP of '$WanIP'."
        Write-Host -Object "[Error] $($_.Exception.Message)"
        exit 1
    }

    # Initialize a list to store blacklisted services
    $BlackListedServices = New-Object System.Collections.Generic.List[object]

    # Loop through each DNSBL to check if the IP is listed
    $BlackLists | ForEach-Object {
        try {
            $Result = Resolve-DnsName -Name "$ReversedIp.$($_.DNSBLDomainName)" -NoHostsFile -DnsOnly -QuickTimeout -ErrorAction Stop

            $BlockListIP = Resolve-DnsName -Name $($_.DNSBLDomainName) -NoHostsFile -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue

            foreach($IPAddress in $Result.IPAddress){
                if($IPaddress -notmatch '^127\.0\.' -and $BlockListIP -and $BlockListIP -notcontains $IPAddress){
                    Write-Host -Object "[Error] A Response Code of '$IPaddress' was given by $($_.DisplayName)."
                    Write-Host -Object "[Error] Typically response codes start with '127.0.' you may want to use different DNS servers."
                    $ExitCode = 1
                    return
                }
            }

            # If the result does not contain an IP address skip to next entry
            if(!$($Result.IPAddress)){
                return
            }

            $BlackListedServices.Add(
                [PSCustomObject]@{
                    Name         = $($_.DisplayName)
                    TTL          = $($Result.TTL -join ', ')
                    ResponseCode = $($Result.IPAddress -join ', ')
                }
            )
        }
        catch {
            return
        }
    }

    # Create a custom field value to store the results
    $CustomFieldValue = New-Object System.Collections.Generic.List[string]
    $MXToolboxLink = "https://mxtoolbox.com/SuperTool.aspx?action=blacklist%3a$WanIP"

    # Check if any blacklists contain the WAN IP and output the results
    if($BlackListedServices.Count -gt 0){
        Write-Host -Object "[Alert] The WAN IP '$WanIp' was found on $($BlackListedServices.Count) blacklist(s)."
        Write-Host -Object "You may want to validate these results with '$MXToolboxLink'."
        $CustomFieldValue.Add("[Alert] The WAN IP '$WanIp' was found on $($BlackListedServices.Count) blacklist(s).")
        $CustomFieldValue.Add($MXToolboxLink)

        ($BlackListedServices | Format-Table | Out-String).Trim() | Write-Host
        $CustomFieldValue.Add($($BlackListedServices | Format-List | Out-String))
    }else{
        Write-Host -Object "The WAN IP '$WanIp' was not found on any blacklists."
        Write-Host -Object "You may want to validate these results with '$MXToolboxLink'."

        $CustomFieldValue.Add("The WAN IP '$WanIp' was not found on any blacklists.")
        $CustomFieldValue.Add($MXToolboxLink)
    }

    # Output the list of blacklists checked
    Write-Host -Object "`nBlacklists Checked: $($BlackLists.DisplayName -join ', ')"

    # Optionally set a custom field with the results
    if($CustomField){
        try {
            Write-Host "`nAttempting to set Custom Field '$CustomField'."
            Set-NinjaProperty -Name $CustomField -Value $CustomFieldValue
            Write-Host "Successfully set Custom Field '$CustomField'!"
        }
        catch {
            Write-Host "[Error] $($_.Exception.Message)"
            exit 1
        }
    }

    exit $ExitCode
}
end {
    
    
    
}
