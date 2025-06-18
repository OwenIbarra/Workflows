# This script will set event viewer up to record additional information (according to best practices) as well as increase the eventlog sizes to 256MBs and 500MB for the Security Log. All Audit Log Subcategories are changed by this!
#Requires -Version 5.1 -RunAsAdministrator

<#
.SYNOPSIS
    This script will set event viewer up to record additional information (according to best practices) as well as increase the eventlog sizes to 256MB's and 500MB for the Security Log. All Audit Log Subcategories are changed by this!
.DESCRIPTION
    This script will set event viewer up to record additional information (according to best practices) as well as increase the eventlog sizes to 256MB's and 500MB for the Security Log. All Audit Log Subcategories are changed by this!
.EXAMPLE
    (No Parameters)

    Subcategory                            Inclusion Setting  
    -----------                            -----------------  
    Account Lockout                        Success and Failure
    Application Generated                  Success and Failure
    Application Group Management           Success and Failure
    Audit Policy Change                    Success and Failure
    ...

PARAMETER: -WhatIf
    This parameter will run through a hypothetical scenario of what will happen if this script is run. 
.EXAMPLE
    -WhatIf

    What if: Performing the operation "Testing if Workstation and is elevated." on target "".
    What if: Performing the operation "Create New RegKey" on target "HKLM:\System\CurrentControlSet\Control\Lsa".
    HKLM:\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy changed from 0 to 0
    WARNING: Changes to the event viewer log sizes require a reboot to take affect. This script does NOT reboot the computer.
    ...

PARAMETER: -SetToMicrosoftDefaults
    This parameter will set everything back to the same settings Microsoft ships by default.
.EXAMPLE
    -SetToMicrosoftDefaults

    Subcategory                            Inclusion Setting  
    -----------                            -----------------  
    Account Lockout                        Success            
    Application Generated                  No Auditing        
    Application Group Management           No Auditing        
    Audit Policy Change                    Success
    ...

.LINK
    https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11)
.OUTPUTS
    None
.NOTES
    General Notes: DOES NOT WORK WITH WINDOWS SERVER!
    Minimum OS Architecture Supported: Windows 10+
    Release Notes: Renamed script and added Script Variable support
.COMPONENT
    Misc
#>

### DISCLAIMER ###
### This script is provided as is, as an option for devices where Group Policy or Intune is not possible.
### We do not recommend this script for compliance purposes, please use Group Policy or some form of MDM for these use cases.
# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11)


[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false)]
    [Switch]$SetToMicrosoftDefaults = [System.Convert]::ToBoolean($env:setToMicrosoftDefaults)
)

begin {

    if ($PSCmdlet.ShouldProcess($Path, "Testing if Workstation and is elevated.")) {
        function Test-IsWorkstation {
            $OS = Get-CimInstance -ClassName Win32_OperatingSystem
            if ($OS.ProductType -eq "1") {
                return $True
            }
        }
    
        if (!(Test-IsWorkstation)) {
            Write-Error "This script will not run on servers. Please use Group Policy to set the event log settings. https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn452415(v=ws.11)"
            exit 1
        }
    
        function Test-IsSystem {
            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            return $id.Name -like "NT AUTHORITY*" -or $id.IsSystem
        }
    
        function Test-IsElevated {
            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $p = New-Object System.Security.Principal.WindowsPrincipal($id)
            $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        }
    
        if (!(Test-IsElevated) -and !(Test-IsSystem)) {
            Write-Error -Message "Access Denied. Please run with Administrator privileges."
            exit 1
        }
    }

    # This will convert auditpol into a much more usable powershell object.
    function Get-AuditPolicy {
        [CmdletBinding()]
        param(
            [Parameter()]
            [String]$SubCategory
        )
        begin {
            $AuditPolicy = auditpol /get /Category:* /r | ConvertFrom-Csv
        }
        process {
            if ($SubCategory) {
                $AuditPolicy | Where-Object { $_.Subcategory -like $SubCategory }
            }
            else {
                $AuditPolicy
            }
        }
    }

    # Function to set a given audit policy
    function Set-AuditPolicy {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter()]
            [String]$SubCategory,
            [Parameter()]
            [String]$Value
        )

        $CurrentPolicy = Get-AuditPolicy -SubCategory $SubCategory
        
        if ($CurrentPolicy."Inclusion Setting" -ne $Value) {
            # If it's currently set as "No Auditing" we can skip these 3 lines.
            if ($CurrentPolicy."Inclusion Setting" -notlike "No Auditing") {
                if ($PSCmdlet.ShouldProcess("Start-Process", "auditpol.exe /set /Subcategory:`"$SubCategory`" /success:disable /failure:disable")) {
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C auditpol.exe /set /Subcategory:`"$SubCategory`" /success:disable /failure:disable" -Wait -WindowStyle Hidden | Out-Null
                }
            }

            if ($Value -match "Success") {
                if ($PSCmdlet.ShouldProcess("Start-Process", "auditpol.exe /set /Subcategory:`"$SubCategory`" /success:enable")) {
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C auditpol.exe /set /Subcategory:`"$SubCategory`" /success:enable" -Wait -WindowStyle Hidden | Out-Null
                }
            }

            if ($Value -match "Failure") {
                if ($PSCmdlet.ShouldProcess("Start-Process", "auditpol.exe /set /Subcategory:`"$SubCategory`" /failure:enable")) {
                    Start-Process -FilePath "cmd.exe" -ArgumentList "/C auditpol.exe /set /Subcategory:`"$SubCategory`" /failure:enable" -Wait -WindowStyle Hidden | Out-Null
                }
            }
        }

        $Result = Get-AuditPolicy -SubCategory $SubCategory

        # Now that it's been set let's verify our results.
        if ($Result."Inclusion Setting" -notlike $Value) {
            Write-Error "Failed to set Audit Policy $SubCategory!"
            exit 1
        }
    }

    function Set-HKProperty {
        [CmdletBinding(SupportsShouldProcess)]
        param (
            $Path,
            $Name,
            $Value,
            [ValidateSet('DWord', 'QWord', 'String', 'ExpandedString', 'Binary', 'MultiString', 'Unknown')]
            $PropertyType = 'DWord'
        )
        if (-not $(Test-Path -Path $Path)) {
            # Check if path does not exist and create the path
            if ($PSCmdlet.ShouldProcess($Path, "Create New RegKey")) {
                New-Item -Path $Path -Force | Out-Null
            }
        }
        if ((Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore)) {
            # Update property and print out what it was changed from and changed to
            $CurrentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name
            try {
                if ($PSCmdlet.ShouldProcess($Path, "Create New RegKey")) {
                    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -Confirm:$false -ErrorAction Stop | Out-Null
                }
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            if ($PSCmdlet.ShouldProcess("$Path\$Name", "Changed from $CurrentValue to $Value")) {
                Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name)"
            }
        }
        else {
            # Create property with value
            try {
                if ($PSCmdlet.ShouldProcess($Path, "Create New RegKey")) {
                    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -Confirm:$false -ErrorAction Stop | Out-Null
                }
            }
            catch {
                Write-Error "[Error] Unable to Set registry key for $Name please see below error!"
                Write-Error $_
                exit 1
            }
            if ($PSCmdlet.ShouldProcess("$Path\$Name", "Would change from $CurrentValue to $Value")) {
                Write-Host "$Path\$Name changed from $CurrentValue to $($(Get-ItemProperty -Path $Path -Name $Name -ErrorAction Ignore).$Name)"
            }
        }
    }

    function Set-LogSize {
        [CmdletBinding(SupportsShouldProcess)]
        param(
            [Parameter()]
            [ValidateSet("Application", "Security", "System")]
            [String]$Name,
            [Parameter()]
            $Size
        )

        Write-Warning "Changes to the event viewer log sizes require a reboot to take affect. This script does NOT reboot the computer."
        $Key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog"
        switch ($Name) {
            "Application" { Set-HkProperty -Path "$Key\Application" -Name "MaxSize" -Value ($Size / 1KB) }
            "Security" { Set-HkProperty -Path "$Key\Security" -Name "MaxSize" -Value ($Size / 1KB) }
            "System" { Set-HkProperty -Path "$Key\System" -Name "MaxSize" -Value ($Size / 1KB) }
        }
    }

    # Hashtable for all the audit policies we're going to set.
    if ($SetToMicrosoftDefaults) {
        $AuditLogs = @{"Account Lockout" = "Success" }, @{"Application Generated" = "No Auditing" },
        @{"Application Group Management" = "No Auditing" }, @{"Audit Policy Change" = "Success" },
        @{"Authentication Policy Change" = "Success" }, @{"Authorization Policy Change" = "Success" },
        @{"Central Policy Staging" = "No Auditing" }, @{"Certification Services" = "No Auditing" }, @{"Computer Account Management" = "Success" },
        @{"Credential Validation" = "Success" }, @{"Detailed Directory Service Replication" = "No Auditing" },
        @{"Detailed File Share" = "No Auditing" }, @{"Directory Service Access" = "Success" }, @{"Directory Service Changes" = "No Auditing" },
        @{"Directory Service Replication" = "No Auditing" }, @{"Distribution Group Management" = "No Auditing" },
        @{"DPAPI Activity" = "No Auditing" }, @{"File Share" = "No Auditing" }, @{"File System" = "No Auditing" },
        @{"Filtering Platform Connection" = "No Auditing" }, @{"Filtering Platform Packet Drop" = "No Auditing" },
        @{"Filtering Platform Policy Change" = "No Auditing" }, @{"Group Membership" = "No Auditing" }, @{"Handle Manipulation" = "No Auditing" },
        @{"IPsec Driver" = "No Auditing" }, @{"IPsec Extended Mode" = "No Auditing" }, @{"IPsec Main Mode" = "No Auditing" },
        @{"IPsec Quick Mode" = "No Auditing" }, @{"Kerberos Authentication Service" = "Success" },
        @{"Kerberos Service Ticket Operations" = "Success" }, @{"Kernel Object" = "No Auditing" }, @{"Logoff" = "Success" },
        @{"Logon" = "Success and Failure" }, @{"MPSSVC Rule-Level Policy Change" = "No Auditing" },
        @{"Network Policy Server" = "Success and Failure" }, @{"Non Sensitive Privilege Use" = "No Auditing" },
        @{"Other Account Logon Events" = "No Auditing" }, @{"Other Account Management Events" = "No Auditing" },
        @{"Other Logon/Logoff Events" = "No Auditing" }, @{"Other Object Access Events" = "No Auditing" },
        @{"Other Policy Change Events" = "No Auditing" }, @{"Other Privilege Use Events" = "No Auditing" },
        @{"Other System Events" = "Success and Failure" }, @{"Plug and Play Events" = "No Auditing" }, @{"Process Creation" = "No Auditing" },
        @{"Process Termination" = "No Auditing" }, @{"Registry" = "No Auditing" }, @{"Removable Storage" = "No Auditing" },
        @{"RPC Events" = "No Auditing" }, @{"SAM" = "No Auditing" }, @{"Security Group Management" = "Success" },
        @{"Security State Change" = "Success" }, @{"Security System Extension" = "No Auditing" }, @{"Sensitive Privilege Use" = "No Auditing" },
        @{"Special Logon" = "Success" }, @{"System Integrity" = "Success and Failure" }, @{"Token Right Adjusted Events" = "No Auditing" },
        @{"User / Device Claims" = "No Auditing" }, @{"User Account Management" = "Success" }
    }
    else {
        $AuditLogs = @{"Account Lockout" = "Success and Failure" }, @{"Application Generated" = "Success and Failure" },
        @{"Application Group Management" = "Success and Failure" }, @{"Audit Policy Change" = "Success and Failure" },
        @{"Authentication Policy Change" = "Success and Failure" }, @{"Authorization Policy Change" = "Success and Failure" },
        @{"Central Policy Staging" = "No Auditing" }, @{"Certification Services" = "Success and Failure" },
        @{"Computer Account Management" = "Success and Failure" }, @{"Credential Validation" = "Success and Failure" },
        @{"Detailed Directory Service Replication" = "No Auditing" }, @{"Detailed File Share" = "Success and Failure" },
        @{"Directory Service Access" = "Success and Failure" }, @{"Directory Service Changes" = "Success and Failure" },
        @{"Directory Service Replication" = "No Auditing" }, @{"Distribution Group Management" = "Success and Failure" },
        @{"DPAPI Activity" = "No Auditing" }, @{"File Share" = "Success and Failure" }, @{"File System" = "Success" },
        @{"Filtering Platform Connection" = "Success" }, @{"Filtering Platform Packet Drop" = "No Auditing" },
        @{"Filtering Platform Policy Change" = "Success" }, @{"Group Membership" = "Success" }, @{"Handle Manipulation" = "No Auditing" },
        @{"IPsec Driver" = "Success and Failure" }, @{"IPsec Extended Mode" = "No Auditing" }, @{"IPsec Main Mode" = "No Auditing" },
        @{"IPsec Quick Mode" = "No Auditing" }, @{"Kerberos Authentication Service" = "No Auditing" },
        @{"Kerberos Service Ticket Operations" = "No Auditing" }, @{"Kernel Object" = "No Auditing" }, @{"Logoff" = "Success" },
        @{"Logon" = "Success and Failure" }, @{"MPSSVC Rule-Level Policy Change" = "No Auditing" },
        @{"Network Policy Server" = "Success and Failure" }, @{"Non Sensitive Privilege Use" = "No Auditing" },
        @{"Other Account Logon Events" = "Success and Failure" }, @{"Other Account Management Events" = "Success and Failure" },
        @{"Other Logon/Logoff Events" = "Success and Failure" }, @{"Other Object Access Events" = "Success and Failure" },
        @{"Other Policy Change Events" = "No Auditing" }, @{"Other Privilege Use Events" = "No Auditing" },
        @{"Other System Events" = "Success and Failure" }, @{"Plug and Play Events" = "Success" },
        @{"Process Creation" = "Success and Failure" }, @{"Process Termination" = "No Auditing" }, @{"Registry" = "Success" },
        @{"Removable Storage" = "Success and Failure" }, @{"RPC Events" = "Success and Failure" }, @{"SAM" = "Success" },
        @{"Security Group Management" = "Success and Failure" }, @{"Security State Change" = "Success and Failure" },
        @{"Security System Extension" = "Success and Failure" }, @{"Sensitive Privilege Use" = "Success and Failure" },
        @{"Special Logon" = "Success and Failure" }, @{"System Integrity" = "Success and Failure" }, @{"Token Right Adjusted Events" = "Success" },
        @{"User / Device Claims" = "No Auditing" }, @{"User Account Management" = "Success and Failure" }
    }
}
process {
    # Have to account for someone hitting the whatif checkbox instead of actually putting in the -whatif param.
    if ([System.Convert]::ToBoolean($env:WhatIf)) {
        $WhatIfPreference = $True
    }

    if ($SetToMicrosoftDefaults) {
        Write-Warning "Changing back to the same settings Microsoft ships by default."
        $Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
        Set-HKProperty -Path $Key -Name "SCENoApplyLegacyAuditPolicy" -Value 0
    }
    else {
        $Key = "HKLM:\System\CurrentControlSet\Control\Lsa"
        Set-HKProperty -Path $Key -Name "SCENoApplyLegacyAuditPolicy" -Value 1
    }

    if ($SetToMicrosoftDefaults) {
        Set-LogSize -Name "Application" -Size "20480KB"
        Set-LogSize -Name "Security" -Size "20480KB"
        Set-LogSize -Name "System" -Size "20480KB"
    }
    else {
        # Values must be divisible by 64!
        Set-LogSize -Name "Application" -Size "256000KB"
        Set-LogSize -Name "Security" -Size "512000KB"
        Set-LogSize -Name "System" -Size "256000KB"
    }

    if ($SetToMicrosoftDefaults) {
        $Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        Set-HKProperty -Path $Key -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 0
    }
    else {
        $Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        Set-HKProperty -Path $Key -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
    }

    if ($WhatIfPreference -eq $True) {
        Write-Host "`nWhatIf: Set Audit Policy to the Below Using auditpol.exe"
        $AuditLogs | Format-Table | Out-String | Write-Host
        exit 0
    }

    $AuditLogs | ForEach-Object {
        Set-AuditPolicy -SubCategory $_.Keys -Value $_.Values
    }

    Write-Host "`n## Final Result ##"
    Get-AuditPolicy | Sort-Object -Property Subcategory | Format-Table Subcategory, "Inclusion Setting" | Out-String | Write-Host
    exit 0
}
end {
    
    
    
}

